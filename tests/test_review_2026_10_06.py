"""Регрессионные тесты по независимой проверке от 6 октября 2026 (commit c2f64d3).

Каждый тест воспроизводит одну находку отчёта и должен падать на коде до исправления.
"""

from __future__ import annotations

import re

import httpx
import pytest
import respx
from mcp.server.auth.provider import TokenError
from sqlalchemy import select

from rugw.__main__ import _users, build_parser
from rugw.connectors import bitrix24, onec_odata, yandex_tracker
from rugw.db import AuditEvent, Grant
from rugw.tools import ConnectorError
from tests.conftest import BASE, REDIRECT, make_settings

MARKER = "SECRET-MARKER-7f3a"


# ------------------------------------------------------------------ находка 1 (P1)


async def test_relogin_keeps_explicit_role_downgrade(harness):
    """Пользователь из bootstrap_admin_emails, пониженный командой set-role, не становится admin при входе."""
    await harness.login("boss@company.ru")
    db = harness.app.state.db
    assert await _users(db, build_parser().parse_args(["users", "set-role", "boss@company.ru", "readonly"])) == 0

    tok = await harness.login("boss@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "gateway_whoami", "arguments": {}})
    assert "readonly" in str(res)
    assert "'admin'" not in str(res) and '"admin"' not in str(res)


# ------------------------------------------------------------------ находки 2 и 3 (P1, P2)


async def test_concurrent_refresh_reuse_revokes_grant(harness):
    """Два обмена одного refresh, загруженного до первого обмена: второй — ошибка OAuth и отзыв гранта."""
    tok = await harness.login("alice@company.ru")
    provider = harness.app.state.provider
    client = await provider.get_client(tok["client_id"])

    # Оба «запроса» успели загрузить токен до того, как кто-то из них его обменял.
    first = await provider.load_refresh_token(client, tok["refresh_token"])
    second = await provider.load_refresh_token(client, tok["refresh_token"])
    assert first is not None and second is not None

    issued = await provider.exchange_refresh_token(client, first, [])
    # Находка 3: должен быть именно TokenError, а не FrozenInstanceError.
    with pytest.raises(TokenError) as exc:
        await provider.exchange_refresh_token(client, second, [])
    assert exc.value.error == "invalid_grant"

    # Находка 2: повтор отзывает весь грант, в том числе только что выданные токены.
    assert (await harness.rpc(issued.access_token, "tools/list")).status_code == 401
    async with harness.app.state.db.session() as s:
        assert (await s.get(Grant, first.grant_id)).revoked is True


async def test_concurrent_auth_code_reuse_raises_oauth_error_and_revokes(harness):
    """Тот же сценарий для кода авторизации (RFC 6749 §4.1.2: повтор кода отзывает выданные по нему токены)."""
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)

    provider = harness.app.state.provider
    client = await provider.get_client(cid)
    a = await provider.load_authorization_code(client, code)
    b = await provider.load_authorization_code(client, code)
    issued = await provider.exchange_authorization_code(client, a)
    with pytest.raises(TokenError) as exc:
        await provider.exchange_authorization_code(client, b)
    assert exc.value.error == "invalid_grant"
    assert (await harness.rpc(issued.access_token, "tools/list")).status_code == 401


async def test_sequential_auth_code_reuse_revokes_issued_tokens(harness):
    """Повтор уже обменянного кода через /token тоже гасит выданные по нему токены."""
    cid = await harness.register_client()
    ystate, verifier = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": cid,
        "code_verifier": verifier,
        "resource": f"{BASE}/mcp",
    }
    ok = await harness.c.post("/token", data=form)
    assert ok.status_code == 200
    assert (await harness.c.post("/token", data=form)).status_code == 400
    assert (await harness.rpc(ok.json()["access_token"], "tools/list")).status_code == 401


# ------------------------------------------------------------------ находка 4 (P2)


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_upstream_error_body_not_exposed_tracker(tmp_path):
    s = make_settings(tmp_path, tracker_token="t", tracker_org_id="1")
    async with httpx.AsyncClient() as http:
        tools = {t.name: t for t in yandex_tracker.build(s, http)}
        with respx.mock:
            respx.get("https://api.tracker.yandex.net/v3/issues/SUP-1").mock(
                return_value=httpx.Response(500, text=f"internal: token={MARKER}", headers={"X-Request-Id": "req-123"})
            )
            with pytest.raises(ConnectorError) as e:
                await tools["tracker_get_issue"].fn(key="SUP-1")
    msg = str(e.value)
    assert MARKER not in msg
    assert "500" in msg and "req-123" in msg


async def test_upstream_error_request_id_is_sanitized(tmp_path):
    s = make_settings(tmp_path, tracker_token="t", tracker_org_id="1")
    async with httpx.AsyncClient() as http:
        tools = {t.name: t for t in yandex_tracker.build(s, http)}
        with respx.mock:
            respx.get("https://api.tracker.yandex.net/v3/issues/SUP-1").mock(
                return_value=httpx.Response(400, text="x", headers={"X-Request-Id": f"<b>{MARKER}" + "a" * 200})
            )
            with pytest.raises(ConnectorError) as e:
                await tools["tracker_get_issue"].fn(key="SUP-1")
    assert MARKER not in str(e.value) and "<b>" not in str(e.value)


async def test_upstream_error_body_not_exposed_onec(tmp_path):
    base = "https://1c.corp.ru/base/odata/standard.odata"
    s = make_settings(tmp_path, onec_odata_url=base, onec_username="u", onec_password="p")
    async with httpx.AsyncClient() as http:
        tools = {t.name: t for t in onec_odata.build(s, http)}
        with respx.mock:
            respx.get(url__startswith=f"{base}/Catalog_X").mock(return_value=httpx.Response(400, text=MARKER))
            with pytest.raises(ConnectorError) as e:
                await tools["onec_query"].fn(entity="Catalog_X")
    assert MARKER not in str(e.value)


async def test_bitrix_error_description_not_exposed(tmp_path):
    hook = "https://corp.bitrix24.ru/rest/1/hooksecret"
    s = make_settings(tmp_path, bitrix24_webhook_url=hook)
    async with httpx.AsyncClient() as http:
        tools = {t.name: t for t in bitrix24.build(s, http)}
        with respx.mock:
            respx.post(f"{hook}/crm.deal.get.json").mock(
                return_value=httpx.Response(
                    200, json={"error": "NOT_FOUND", "error_description": f"Not found {MARKER}"}
                )
            )
            with pytest.raises(ConnectorError) as e:
                await tools["bitrix_crm_get"].fn(entity_type="deal", id=1)
            assert MARKER not in str(e.value) and "NOT_FOUND" in str(e.value)

            respx.post(f"{hook}/crm.deal.list.json").mock(
                return_value=httpx.Response(200, json={"error": f"{MARKER} <script>"})
            )
            with pytest.raises(ConnectorError) as e:
                await tools["bitrix_crm_list"].fn(entity_type="deal")
            assert MARKER not in str(e.value) and "<script>" not in str(e.value)


async def test_upstream_error_body_not_in_audit(harness):
    """Через полный путь guarded: тело ошибки не попадает ни в ответ модели, ни в аудит."""
    from rugw.policy import Level
    from rugw.tools import ToolSpec, register

    async def boom() -> str:
        from rugw.connectors.base import call_json

        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(502, text=MARKER))) as c:
            return await call_json(c, "GET", "https://upstream.test/x", system="Тест")

    # Регистрация после старта приложения допустима: SDK читает список инструментов на каждый запрос.
    app = harness.app
    server = app.state.server
    register(server, ToolSpec("test_boom", Level.READ, boom, "boom"), app.state.settings, app.state.auditor)
    tok = await harness.login("alice@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "test_boom", "arguments": {}})
    assert res.get("isError") is True
    assert MARKER not in str(res)
    async with app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.target == "test_boom"))).scalars().all()
    assert ev and all(MARKER not in (e.detail or "") for e in ev)
