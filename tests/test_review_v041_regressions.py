"""Независимая проверка 0.4.1, 2026-10-08. Только SQLite и поддельные ответы."""

import asyncio

import httpx
import pytest
from cryptography.fernet import Fernet

from rugw.__main__ import _users, build_parser
from rugw.auth.yandex import YandexTokens
from rugw.connectors.diadoc import DiadocTokens
from rugw.credentials import CredentialsUnavailable
from rugw.errors import ErrorCode
from rugw.tools import ConnectorError
from tests.test_review_v03_regressions import begin_refresh
from tests.test_v041 import _diadoc, diadoc_settings


@pytest.fixture
def harness_settings():
    return {
        "tracker_auth_mode": "user",
        "tracker_org_id": "42",
        "yandex_extra_scopes": "tracker:read tracker:write",
        "token_encryption_keys": Fernet.generate_key().decode(),
    }


async def test_deleted_then_recreated_user_credentials_reject_old_refresh(harness, monkeypatch):
    credentials, user_id, release, task = await begin_refresh(harness, monkeypatch)
    try:
        parser = build_parser()
        await _users(harness.app.state.db, parser.parse_args(["users", "disable", "alice@company.ru"]))
        await _users(harness.app.state.db, parser.parse_args(["users", "enable", "alice@company.ru"]))
        assert await credentials.save(user_id, YandexTokens("synthetic-new-login", "synthetic-new-refresh", 3600))
    finally:
        release.set()
    try:
        await task
    except CredentialsUnavailable:
        pass
    assert (await credentials._read(user_id))[0:2] == ("synthetic-new-login", "synthetic-new-refresh")


async def test_deleted_then_recreated_service_credentials_reject_old_cas(tmp_path):
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "synthetic-old-login")
            _, generation = await store.get("diadoc")
            await store.delete("diadoc")
            await store.put("diadoc", "synthetic-new-login")
            assert not await store.cas("diadoc", generation, "synthetic-old-refreshed")
            assert (await store.get("diadoc"))[0] == "synthetic-new-login"
        finally:
            await db.dispose()


async def test_diadoc_logout_invalidates_cached_access(tmp_path, monkeypatch):
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "synthetic-old-refresh")
            tokens = DiadocTokens(diadoc_settings(tmp_path), http, store)

            async def response(_form):
                return {
                    "access_token": "synthetic-old-access",
                    "refresh_token": "synthetic-rotated",
                    "expires_in": 3600,
                }

            monkeypatch.setattr(tokens, "_token_request", response)
            assert await tokens.access_token() == "synthetic-old-access"
            # rugw diadoc logout удаляет ту же запись из БД в отдельном процессе.
            await store.delete("diadoc")
            with pytest.raises(ConnectorError) as caught:
                await tokens.access_token()
            assert caught.value.code == ErrorCode.RELOGIN_REQUIRED
        finally:
            await db.dispose()


async def test_diadoc_discards_refresh_if_admin_replaced_login(tmp_path, monkeypatch):
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "synthetic-old-refresh")
            tokens = DiadocTokens(diadoc_settings(tmp_path), http, store)
            started, release = asyncio.Event(), asyncio.Event()

            async def response(form):
                if form["refresh_token"] == "synthetic-old-refresh":
                    started.set()
                    await release.wait()
                    return {
                        "access_token": "synthetic-old-access",
                        "refresh_token": "synthetic-old-rotated",
                        "expires_in": 3600,
                    }
                return {
                    "access_token": "synthetic-new-access",
                    "refresh_token": "synthetic-new-rotated",
                    "expires_in": 3600,
                }

            monkeypatch.setattr(tokens, "_token_request", response)
            task = asyncio.create_task(tokens.access_token())
            await asyncio.wait_for(started.wait(), timeout=5)
            try:
                await store.put("diadoc", "synthetic-new-login")
            finally:
                release.set()
            try:
                access = await task
            except ConnectorError as exc:
                assert exc.code == ErrorCode.RELOGIN_REQUIRED
            else:
                assert access == "synthetic-new-access"
        finally:
            await db.dispose()


async def test_diadoc_serializes_dates_in_documented_format(tmp_path, as_admin):
    import json

    from rugw.connectors.diadoc import PROVIDER

    requests = []

    async def handler(request):
        if request.url.path == "/connect/token":
            return httpx.Response(200, json={"access_token": "synthetic-access", "expires_in": 3600})
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"Documents": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        db, store, tools = await _diadoc(tmp_path, http)
        try:
            await store.put(PROVIDER, "synthetic-refresh")
            await tools["diadoc_documents"].fn(
                box_id="11111111-1111-1111-1111-111111111111", from_date="2026-10-01", to_date="2026-10-08"
            )
            # https://developer.kontur.ru/doc/diadoc-api/proto/GetDocumentsV4Request.html
            assert requests[0]["FromDocumentDate"] == "01.10.2026"
            assert requests[0]["ToDocumentDate"] == "08.10.2026"
        finally:
            await db.dispose()
