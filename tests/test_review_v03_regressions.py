# Тесты независимой проверки (Codex, 2026-10-06), перенесены из отчёта без изменений логики.
"""Независимая проверка гонок credentials в версии 0.3."""

from __future__ import annotations

import asyncio

import pytest
from cryptography.fernet import Fernet
from mcp.server.auth.provider import TokenError
from sqlalchemy import select, update

from rugw.__main__ import _users, build_parser
from rugw.auth.yandex import YandexTokens
from rugw.credentials import CredentialsUnavailable
from rugw.db import AuditEvent, User, UserCredential


@pytest.fixture
def harness_settings():
    return {
        "tracker_auth_mode": "user",
        "tracker_org_id": "42",
        "yandex_extra_scopes": "tracker:read tracker:write",
        "token_encryption_keys": Fernet.generate_key().decode(),
    }


async def begin_refresh(harness, monkeypatch):
    await harness.login("alice@company.ru")
    credentials = harness.app.state.credentials
    async with harness.app.state.db.session() as session:
        user = (await session.execute(select(User).where(User.email == "alice@company.ru"))).scalar_one()
        await session.execute(update(UserCredential).where(UserCredential.user_id == user.id).values(expires_at=0))
    started, release = asyncio.Event(), asyncio.Event()

    async def refresh(_token):
        started.set()
        await release.wait()
        return YandexTokens("synthetic-old-refreshed", "synthetic-old-refresh", 3600)

    monkeypatch.setattr(credentials.yandex, "refresh", refresh)
    task = asyncio.create_task(credentials.access_token(user.id))
    await asyncio.wait_for(started.wait(), timeout=5)
    return credentials, user.id, release, task


async def test_review_v03_disable_during_refresh_does_not_restore_credentials(harness, monkeypatch):
    credentials, user_id, release, task = await begin_refresh(harness, monkeypatch)
    try:
        await _users(harness.app.state.db, build_parser().parse_args(["users", "disable", "alice@company.ru"]))
    finally:
        release.set()
    try:
        await task
    except CredentialsUnavailable:
        pass
    async with harness.app.state.db.session() as session:
        assert (await session.get(User, user_id)).disabled
        assert await session.get(UserCredential, (user_id, "yandex")) is None
    # Проверка напрямую относится к хранилищу; новые MCP-вызовы disabled блокируются отдельно.
    with pytest.raises(CredentialsUnavailable):
        await credentials.access_token(user_id)


async def test_review_v03_relogin_during_refresh_keeps_new_login_credentials(harness, monkeypatch):
    credentials, user_id, release, task = await begin_refresh(harness, monkeypatch)
    try:
        # Тот же save вызывает auth/routes.py после нового входа.
        await credentials.save(user_id, YandexTokens("synthetic-new-login", "synthetic-new-refresh", 3600))
    finally:
        release.set()
    await task
    async with harness.app.state.db.session() as session:
        row = await session.get(UserCredential, (user_id, "yandex"))
        assert credentials.cipher.decrypt(row.access_token_enc) == "synthetic-new-login"
        assert credentials.cipher.decrypt(row.refresh_token_enc) == "synthetic-new-refresh"


async def test_review_v03_transaction_rolls_back_and_preserves_frozen_error(harness):
    error = TokenError("invalid_grant", "synthetic review error")
    with pytest.raises(TokenError) as caught:
        async with harness.app.state.db.session() as session:
            session.add(AuditEvent(event="review_rollback", outcome="ok"))
            await session.flush()
            raise error
    assert caught.value is error
    async with harness.app.state.db.session() as session:
        assert (await session.execute(select(AuditEvent).where(AuditEvent.event == "review_rollback"))).first() is None


async def test_review_v03_two_refresh_callers_share_one_refresh(harness):
    await harness.login("alice@company.ru")
    async with harness.app.state.db.session() as session:
        user = (await session.execute(select(User).where(User.email == "alice@company.ru"))).scalar_one()
        await session.execute(update(UserCredential).where(UserCredential.user_id == user.id).values(expires_at=0))
    credentials = harness.app.state.credentials
    first, second = await asyncio.gather(credentials.access_token(user.id), credentials.access_token(user.id))
    assert first == second
    assert len(harness.refreshes) == 1
