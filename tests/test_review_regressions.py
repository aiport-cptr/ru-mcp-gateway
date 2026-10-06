# Тесты независимой проверки (Codex, 2026-10-06), перенесены из отчёта без изменений логики.
"""Локальные регрессионные проверки независимого обзора; ожидаются отказы до исправления."""

from dataclasses import FrozenInstanceError

import httpx
import pytest
from mcp.server.auth.provider import TokenError

from rugw.__main__ import _users, build_parser
from rugw.auth.provider import GatewayOAuthProvider
from rugw.auth.yandex import YandexOAuth
from rugw.connectors.base import call_json
from rugw.tools import ConnectorError


async def test_review_explicit_admin_demotion_survives_login(harness):
    await harness.login("boss@company.ru")
    await _users(harness.app.state.db, build_parser().parse_args(["users", "set-role", "boss@company.ru", "readonly"]))
    tok = await harness.login("boss@company.ru")
    result = await harness.mcp(tok["access_token"], "tools/call", {"name": "gateway_whoami", "arguments": {}})
    assert "readonly" in str(result)


async def test_review_refresh_concurrent_reuse_revokes_grant(harness):
    tok = await harness.login("alice@company.ru")
    async with httpx.AsyncClient() as http:
        settings = harness.app.state.settings
        provider = GatewayOAuthProvider(settings, harness.app.state.db, YandexOAuth(settings, http))
        client = await provider.get_client(tok["client_id"])
        # Два запроса прошли load до первого exchange — допустимое чередование.
        first = await provider.load_refresh_token(client, tok["refresh_token"])
        second = await provider.load_refresh_token(client, tok["refresh_token"])
        new = await provider.exchange_refresh_token(client, first, ["gateway"])
        with pytest.raises((TokenError, FrozenInstanceError)):
            await provider.exchange_refresh_token(client, second, ["gateway"])
        assert await provider.load_access_token(new.access_token) is None


async def test_review_exchange_error_preserves_oauth_token_error(harness):
    tok = await harness.login("alice@company.ru")
    async with httpx.AsyncClient() as http:
        settings = harness.app.state.settings
        provider = GatewayOAuthProvider(settings, harness.app.state.db, YandexOAuth(settings, http))
        client = await provider.get_client(tok["client_id"])
        refresh = await provider.load_refresh_token(client, tok["refresh_token"])
        await provider.exchange_refresh_token(client, refresh, ["gateway"])
        with pytest.raises(TokenError):
            await provider.exchange_refresh_token(client, refresh, ["gateway"])


async def test_review_connector_does_not_echo_upstream_secrets():
    marker = "SYNTHETIC_REVIEW_SECRET"
    transport = httpx.MockTransport(lambda request: httpx.Response(500, text=f"debug authorization={marker}"))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(ConnectorError) as caught:
            await call_json(http, "GET", "https://upstream.invalid/", system="test")
    assert marker not in str(caught.value)
