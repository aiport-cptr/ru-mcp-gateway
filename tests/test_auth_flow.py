"""Сквозные проверки входа и выдачи токенов."""

from __future__ import annotations

import re

from tests.conftest import BASE


async def test_healthz_reports_auth(harness):
    r = await harness.c.get("/healthz")
    assert r.json()["auth_enabled"] is True


async def test_mcp_without_token_is_401(harness):
    r = await harness.rpc(None, "tools/list")
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


async def test_mcp_with_garbage_token_is_401(harness):
    r = await harness.rpc("not-a-token", "tools/list")
    assert r.status_code == 401


async def test_full_login_and_whoami(harness):
    tok = await harness.login("alice@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "gateway_whoami", "arguments": {}})
    assert "alice@company.ru" in str(res)
    assert "readonly" in str(res)


async def test_bootstrap_admin_gets_admin(harness):
    tok = await harness.login("boss@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "gateway_whoami", "arguments": {}})
    assert "admin" in str(res)


async def test_foreign_domain_denied(harness):
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "mallory@evil-company.ru")
    assert page.status_code == 403


async def test_lookalike_domain_denied(harness):
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "x@company.ru.evil.ru")
    assert page.status_code == 403


async def test_consent_requires_cookie(harness):
    """Чужая форма без cookie (CSRF) не должна выдавать код."""
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    harness.c.cookies.clear()
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    assert r.status_code == 403


async def test_consent_deny_returns_access_denied(harness):
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "deny"})
    assert r.status_code == 302
    assert "error=access_denied" in r.headers["location"]
    assert "code=" not in r.headers["location"]


async def test_consent_replay_rejected(harness):
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    first = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    assert first.status_code == 302
    harness.c.cookies.set("rugw_consent", csrf, domain="localhost", path="/auth/consent")
    again = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    assert again.status_code == 403


async def test_yandex_state_reuse_rejected(harness):
    """Повторный возврат из Яндекса с тем же state после согласия не работает."""
    tok_client = await harness.register_client()
    ystate, _ = await harness.start_authorize(tok_client)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    again = await harness.yandex_return(ystate, "alice@company.ru")
    assert again.status_code == 400


async def test_wrong_resource_rejected(harness):
    cid = await harness.register_client()
    r = await harness.c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "http://127.0.0.1:33418/callback",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "s",
            "resource": "https://other.example/mcp",
        },
    )
    assert r.status_code in (302, 400)
    assert "oauth.yandex.ru" not in r.headers.get("location", "")


async def test_unregistered_redirect_rejected(harness):
    cid = await harness.register_client()
    r = await harness.c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "https://attacker.example/cb",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "s",
        },
    )
    assert r.status_code == 400
    assert "attacker" not in r.headers.get("location", "")


async def test_auth_code_single_use(harness):
    """Код меняется на токен ровно один раз."""
    cid = await harness.register_client()
    ystate, verifier = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://127.0.0.1:33418/callback",
        "client_id": cid,
        "code_verifier": verifier,
        "resource": f"{BASE}/mcp",
    }
    assert (await harness.c.post("/token", data=form)).status_code == 200
    assert (await harness.c.post("/token", data=form)).status_code == 400


async def test_pkce_mismatch_rejected(harness):
    cid = await harness.register_client()
    ystate, _ = await harness.start_authorize(cid)
    page = await harness.yandex_return(ystate, "alice@company.ru")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await harness.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)
    bad = await harness.c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:33418/callback",
            "client_id": cid,
            "code_verifier": "wrong" * 10,
            "resource": f"{BASE}/mcp",
        },
    )
    assert bad.status_code == 400


async def test_refresh_rotation_and_reuse_detection(harness):
    tok = await harness.login("alice@company.ru")
    form = {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": tok["client_id"]}
    r1 = await harness.c.post("/token", data=form)
    assert r1.status_code == 200
    new = r1.json()
    assert new["refresh_token"] != tok["refresh_token"]
    # Старый access-токен после обновления не работает
    assert (await harness.rpc(tok["access_token"], "tools/list")).status_code == 401
    # Повтор старого refresh — признак кражи: отказ и отзыв всего гранта
    assert (await harness.c.post("/token", data=form)).status_code == 400
    assert (await harness.rpc(new["access_token"], "tools/list")).status_code == 401
    form2 = {"grant_type": "refresh_token", "refresh_token": new["refresh_token"], "client_id": tok["client_id"]}
    assert (await harness.c.post("/token", data=form2)).status_code == 400


async def test_revoke(harness):
    tok = await harness.login("alice@company.ru")
    # MCP SDK требует поле client_secret даже у публичных клиентов — передаём пустое.
    r = await harness.c.post(
        "/revoke", data={"token": tok["access_token"], "client_id": tok["client_id"], "client_secret": ""}
    )
    assert r.status_code == 200, r.text
    assert (await harness.rpc(tok["access_token"], "tools/list")).status_code == 401


async def test_mcp_rejects_foreign_host_header(harness):
    """Защита от DNS rebinding: запросы к /mcp с чужим Host отклоняются."""
    tok = await harness.login("alice@company.ru")
    r = await harness.c.post(
        "/mcp",
        headers={
            "Host": "evil.example",
            "Authorization": f"Bearer {tok['access_token']}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
    )
    assert r.status_code in (400, 403, 421)


async def test_healthz_works_with_internal_host(harness):
    r = await harness.c.get("/healthz", headers={"Host": "127.0.0.1:8000"})
    assert r.status_code == 200
