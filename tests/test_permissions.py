"""Права на инструменты и аудит."""

from __future__ import annotations

from sqlalchemy import select, update

from rugw.db import AuditEvent, User


def _names(result: dict) -> set[str]:
    return {t["name"] for t in result["tools"]}


async def test_readonly_sees_only_read_tools(harness):
    tok = await harness.login("alice@company.ru")
    names = _names(await harness.mcp(tok["access_token"], "tools/list"))
    assert "gateway_whoami" in names
    assert "test_echo_write" not in names


async def test_readonly_cannot_call_write_tool(harness):
    tok = await harness.login("alice@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "test_echo_write", "arguments": {"text": "x"}})
    assert res.get("isError") is True
    assert "wrote:x" not in str(res)


async def _set_role(harness, email: str, role: str, disabled: bool = False):
    async with harness.app.state.db.session() as s:
        await s.execute(update(User).where(User.email == email).values(role=role, disabled=disabled))


async def test_member_can_write_and_it_is_audited(harness):
    tok = await harness.login("bob@company.ru")
    await _set_role(harness, "bob@company.ru", "member")
    names = _names(await harness.mcp(tok["access_token"], "tools/list"))
    assert "test_echo_write" in names
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "test_echo_write", "arguments": {"text": "hello"}}
    )
    assert "wrote:hello" in str(res)
    async with harness.app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.target == "test_echo_write"))).scalars().all()
    assert [e.outcome for e in ev] == ["ok"]
    assert "hello" in ev[0].detail


async def test_denied_call_is_audited(harness):
    tok = await harness.login("alice@company.ru")
    await harness.mcp(tok["access_token"], "tools/call", {"name": "test_echo_write", "arguments": {"text": "x"}})
    async with harness.app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.target == "test_echo_write"))).scalars().all()
    assert [e.outcome for e in ev] == ["denied"]


async def test_role_downgrade_applies_immediately(harness):
    tok = await harness.login("bob@company.ru")
    await _set_role(harness, "bob@company.ru", "member")
    await _set_role(harness, "bob@company.ru", "readonly")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "test_echo_write", "arguments": {"text": "x"}})
    assert res.get("isError") is True


async def test_disabled_user_token_stops_working(harness):
    tok = await harness.login("alice@company.ru")
    await _set_role(harness, "alice@company.ru", "readonly", disabled=True)
    assert (await harness.rpc(tok["access_token"], "tools/list")).status_code == 401


async def test_audit_redacts_secrets():
    from rugw.security import audit_dump

    text = audit_dump({"query": "ok", "api_key": "SECRET1", "nested": {"password": "SECRET2"}}, 1000)
    assert "SECRET1" not in text and "SECRET2" not in text and "ok" in text
