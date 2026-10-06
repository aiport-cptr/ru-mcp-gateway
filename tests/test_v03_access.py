"""0.3: права на ресурсы коннекторов (docs/design/0.3-access.md)."""

from __future__ import annotations

import io
import json

import httpx
import pytest
import respx
from sqlalchemy import delete, select

from rugw.__main__ import _grants, build_parser
from rugw.access import Permissions, _Rule, validate_grant
from rugw.connectors import bitrix24, onec_odata, yandex_tracker
from rugw.db import AuditEvent, ResourceGrant
from rugw.policy import Level
from tests.conftest import make_settings

TRACKER = "https://api.tracker.yandex.net/v3"
HOOK = "https://corp.bitrix24.ru/rest/1/hooksecret"
ONEC = "https://1c.corp.ru/base/odata/standard.odata"

pytestmark = pytest.mark.anyio


def P(role: str, *rules: tuple[str, str, str]) -> Permissions:  # noqa: N802
    return Permissions(role=role, rules=tuple(_Rule(c, r, Level(lv)) for c, r, lv in rules))


# ================================================================== модель прав


def test_role_is_ceiling():
    p = P("readonly", ("tracker", "*", "write"))
    assert p.allows("tracker", "SUP", Level.READ)
    assert not p.allows("tracker", "SUP", Level.WRITE)  # роль readonly не пишет даже с правом write


def test_write_grant_implies_read_and_patterns():
    p = P("member", ("tracker", "SUP", "write"), ("onec", "Catalog_*", "read"))
    assert p.allows("tracker", "SUP", Level.READ) and p.allows("tracker", "SUP", Level.WRITE)
    assert not p.allows("tracker", "SUPPORT", Level.READ)  # точное совпадение, не префикс
    assert p.allows("onec", "Catalog_Контрагенты", Level.READ)
    assert not p.allows("onec", "Document_Реализация", Level.READ)
    assert not p.allows("onec", "Catalog_X", Level.WRITE)
    assert not p.allows("bitrix24", "lead", Level.READ)  # нет права — нет доступа


def test_no_rules_no_access_admin_everything():
    assert not P("member").allows("tracker", "SUP", Level.READ)
    assert not P("member").allows_connector("tracker", Level.READ)
    assert P("admin").allows("tracker", "ANY", Level.WRITE)
    assert P("admin").allows_connector("onec", Level.WRITE)


def test_connector_wildcard_and_isolation():
    p = P("member", ("*", "*", "read"), ("tracker", "SUP", "write"))
    assert p.allows("onec", "Anything", Level.READ)
    assert not p.allows("onec", "Anything", Level.WRITE)
    assert p.allows("tracker", "SUP", Level.WRITE)
    assert not p.allows("bitrix24", "deal:0", Level.WRITE)


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        ((("bitrix24", "deal:3", "read"),), True),
        ((("bitrix24", "deal:*", "read"),), True),
        ((("bitrix24", "*", "read"),), True),
        ((("*", "*", "read"),), True),
        ((("bitrix24", "lead", "read"),), False),
        ((("tracker", "deal:3", "read"),), False),
    ],
)
def test_may_have_prefix(rules, expected):
    assert P("member", *rules).may_have("bitrix24", "deal:", Level.READ) is expected


@pytest.mark.parametrize(
    "args",
    [
        ("role:admin", "tracker", "*", "read"),  # admin и так всё может
        ("role:boss", "tracker", "*", "read"),
        ("user:not-an-email", "tracker", "*", "read"),
        ("group:x", "tracker", "*", "read"),
        ("role:member", "jira", "*", "read"),
        ("role:member", "tracker", "SUP ?", "read"),
        ("role:member", "tracker", "[A-Z]*", "read"),  # только *, без классов fnmatch
        ("role:member", "tracker", "SUP", "admin"),
        ("role:member", "tracker", "", "read"),
    ],
)
def test_validate_grant_rejects(args):
    with pytest.raises(ValueError):
        validate_grant(*args)


def test_validate_grant_normalizes():
    assert validate_grant("user:Ivan@Company.RU", "tracker", "SUP", "write") == (
        "user:ivan@company.ru",
        "tracker",
        "SUP",
        "write",
    )


# ================================================================== Трекер


def _tracker(tmp_path):
    s = make_settings(tmp_path, tracker_token="t", tracker_org_id="1")
    return {t.name: t for t in yandex_tracker.build(s, httpx.AsyncClient())}


async def test_tracker_denied_queue_does_not_call_upstream(tmp_path, as_user):
    as_user("member", ("tracker", "SUP", "read"))
    t = _tracker(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        route = m.get(f"{TRACKER}/issues/HR-1").mock(return_value=httpx.Response(200, json={"key": "HR-1"}))
        with pytest.raises(Exception, match="HR"):
            await t["tracker_get_issue"].fn(key="HR-1")
    assert not route.called


async def test_tracker_moved_issue_checked_by_real_queue(tmp_path, as_user):
    """SUP-1 переехала в HR-7: по старому ключу Трекер отдаёт задачу из HR — доступа нет."""
    as_user("member", ("tracker", "SUP", "read"))
    t = _tracker(tmp_path)
    with respx.mock:
        respx.get(f"{TRACKER}/issues/SUP-1").mock(
            return_value=httpx.Response(200, json={"key": "HR-7", "queue": {"key": "HR"}, "summary": "секрет HR"})
        )
        with pytest.raises(Exception, match="HR") as e:
            await t["tracker_get_issue"].fn(key="SUP-1")
    assert "секрет" not in str(e.value)


async def test_tracker_search_filters_by_queue(tmp_path, as_user):
    as_user("member", ("tracker", "SUP", "read"))
    t = _tracker(tmp_path)
    issues = [
        {"key": "SUP-1", "queue": {"key": "SUP"}, "summary": "видно"},
        {"key": "HR-2", "queue": {"key": "HR"}, "summary": "зарплаты"},
        {"key": "XX-3", "summary": "без очереди в ответе — по ключу"},
        {"summary": "мусор без ключа"},
    ]
    with respx.mock:
        respx.post(f"{TRACKER}/issues/_search").mock(return_value=httpx.Response(200, json=issues))
        out = json.loads(await t["tracker_search_issues"].fn(query="Queue: HR"))
    assert [i["key"] for i in out["issues"]] == ["SUP-1"]
    assert "3" in out["hidden"]
    assert "зарплаты" not in json.dumps(out, ensure_ascii=False)


async def test_tracker_comment_needs_write_on_real_queue(tmp_path, as_user):
    as_user("member", ("tracker", "SUP", "write"), ("tracker", "HR", "read"))
    t = _tracker(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{TRACKER}/issues/HR-1").mock(return_value=httpx.Response(200, json={"key": "HR-1"}))
        post = m.post(f"{TRACKER}/issues/HR-1/comments").mock(return_value=httpx.Response(201, json={"id": 1}))
        with pytest.raises(Exception, match="write"):
            await t["tracker_add_comment"].fn(key="HR-1", text="привет")
        assert not post.called

        m.get(f"{TRACKER}/issues/SUP-2").mock(return_value=httpx.Response(200, json={"key": "SUP-2"}))
        ok = m.post(f"{TRACKER}/issues/SUP-2/comments").mock(return_value=httpx.Response(201, json={"id": 2}))
        await t["tracker_add_comment"].fn(key="SUP-2", text="привет")
        assert ok.called


async def test_tracker_comments_use_resolved_key(tmp_path, as_user):
    """Комментарии читаются у задачи, доступ к которой проверен, — по её фактическому ключу."""
    as_user("member", ("tracker", "*", "read"))
    t = _tracker(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{TRACKER}/issues/SUP-1").mock(return_value=httpx.Response(200, json={"key": "SUP-9"}))
        c = m.get(f"{TRACKER}/issues/SUP-9/comments").mock(return_value=httpx.Response(200, json=[]))
        await t["tracker_get_comments"].fn(key="SUP-1")
    assert c.called


# ================================================================== Битрикс24


def _bitrix(tmp_path):
    s = make_settings(tmp_path, bitrix24_webhook_url=HOOK)
    return {t.name: t for t in bitrix24.build(s, httpx.AsyncClient())}


async def test_bitrix_list_filters_by_category(tmp_path, as_user):
    as_user("member", ("bitrix24", "deal:0", "read"))
    t = _bitrix(tmp_path)
    deals = [
        {"ID": "1", "TITLE": "основная", "CATEGORY_ID": "0"},
        {"ID": "2", "TITLE": "тендеры", "CATEGORY_ID": "5"},
        {"ID": "3", "TITLE": "без воронки"},
    ]
    with respx.mock:
        route = respx.post(f"{HOOK}/crm.deal.list.json").mock(return_value=httpx.Response(200, json={"result": deals}))
        out = json.loads(await t["bitrix_crm_list"].fn(entity_type="deal", select=["ID", "TITLE"]))
    assert [d["ID"] for d in out["items"]] == ["1"]
    assert "CATEGORY_ID" in json.loads(route.calls[0].request.content)["select"]


async def test_bitrix_no_deal_access_denied_before_call(tmp_path, as_user):
    as_user("member", ("bitrix24", "lead", "read"))
    t = _bitrix(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        route = m.post(f"{HOOK}/crm.deal.list.json").mock(return_value=httpx.Response(200, json={"result": []}))
        with pytest.raises(Exception, match="сделкам"):
            await t["bitrix_crm_list"].fn(entity_type="deal")
        c = m.post(f"{HOOK}/crm.contact.get.json").mock(return_value=httpx.Response(200, json={"result": {}}))
        with pytest.raises(Exception, match="contact"):
            await t["bitrix_crm_get"].fn(entity_type="contact", id=1)
    assert not route.called and not c.called


async def test_bitrix_get_other_category_denied(tmp_path, as_user):
    as_user("member", ("bitrix24", "deal:0", "read"))
    t = _bitrix(tmp_path)
    with respx.mock:
        respx.post(f"{HOOK}/crm.deal.get.json").mock(
            return_value=httpx.Response(200, json={"result": {"ID": "2", "CATEGORY_ID": "5", "TITLE": "тендер"}})
        )
        with pytest.raises(Exception, match="deal:5") as e:
            await t["bitrix_crm_get"].fn(entity_type="deal", id=2)
    assert "тендер" not in str(e.value)


async def test_bitrix_comment_requires_write_on_category(tmp_path, as_user):
    as_user("member", ("bitrix24", "deal:*", "read"), ("bitrix24", "deal:0", "write"))
    t = _bitrix(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        m.post(f"{HOOK}/crm.deal.get.json").mock(
            return_value=httpx.Response(200, json={"result": {"ID": "2", "CATEGORY_ID": "5"}})
        )
        add = m.post(f"{HOOK}/crm.timeline.comment.add.json").mock(return_value=httpx.Response(200, json={"result": 1}))
        with pytest.raises(Exception, match="write"):
            await t["bitrix_crm_add_comment"].fn(entity_type="deal", id=2, comment="x")
    assert not add.called


# ================================================================== 1С


def _onec(tmp_path):
    s = make_settings(tmp_path, onec_odata_url=ONEC, onec_username="u", onec_password="p")
    return {t.name: t for t in onec_odata.build(s, httpx.AsyncClient())}


async def test_onec_entity_grants(tmp_path, as_user):
    as_user("member", ("onec", "Catalog_*", "read"))
    t = _onec(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        doc = m.get(url__startswith=f"{ONEC}/Document_").mock(return_value=httpx.Response(200, json={"value": []}))
        with pytest.raises(Exception, match="Document_"):
            await t["onec_query"].fn(entity="Document_Реализация")
        m.get(f"{ONEC}/").mock(
            return_value=httpx.Response(
                200, json={"value": [{"name": "Catalog_Контрагенты"}, {"name": "Document_Реализация"}]}
            )
        )
        listed = json.loads(await t["onec_list_entities"].fn())
    assert listed == ["Catalog_Контрагенты"]
    assert not doc.called


@pytest.mark.parametrize(
    "nav",
    [
        {"select": ["Контрагент/ИНН"]},
        {"filter": "Контрагент/Description eq 'Ромашка'"},
        {"orderby": "Контрагент/Description"},
    ],
)
async def test_onec_navigation_blocked_without_full_access(tmp_path, as_user, nav):
    """Переход по ссылке читает другой набор — без доступа ко всем наборам запрещён."""
    as_user("member", ("onec", "Document_*", "read"))
    t = _onec(tmp_path)
    with respx.mock(assert_all_called=False) as m:
        r = m.get(url__startswith=f"{ONEC}/Document_").mock(return_value=httpx.Response(200, json={"value": []}))
        with pytest.raises(Exception, match="другие наборы"):
            await t["onec_query"].fn(entity="Document_Реализация", **nav)
    assert not r.called


async def test_onec_navigation_allowed_with_full_access(tmp_path, as_user):
    as_user("member", ("onec", "*", "read"))
    t = _onec(tmp_path)
    with respx.mock:
        respx.get(url__startswith=f"{ONEC}/Document_").mock(return_value=httpx.Response(200, json={"value": []}))
        await t["onec_query"].fn(entity="Document_Реализация", select=["Контрагент/ИНН"])


# ================================================================== сквозные: MCP + база + CLI


@pytest.fixture
def harness_settings():
    return {"tracker_token": "svc", "tracker_org_id": "1", "bitrix24_webhook_url": HOOK}


async def _restrict(harness, *grants: tuple[str, str, str, str]) -> None:
    """Убрать права по умолчанию из миграции и выдать перечисленные."""
    async with harness.app.state.db.session() as s:
        await s.execute(delete(ResourceGrant))
        for subject, connector, resource, level in grants:
            s.add(ResourceGrant(subject=subject, connector=connector, resource=resource, level=level))


def _names(result: dict) -> set[str]:
    return {t["name"] for t in result["tools"]}


async def test_default_grants_keep_02_behaviour(harness):
    tok = await harness.login("alice@company.ru")
    names = _names(await harness.mcp(tok["access_token"], "tools/list"))
    assert {"tracker_get_issue", "bitrix_crm_list"} <= names
    assert "tracker_add_comment" not in names  # readonly


async def test_tools_list_follows_grants(harness):
    await _restrict(harness, ("user:alice@company.ru", "tracker", "SUP", "write"))
    tok = await harness.login("alice@company.ru")
    from tests.test_permissions import _set_role

    await _set_role(harness, "alice@company.ru", "member")
    names = _names(await harness.mcp(tok["access_token"], "tools/list"))
    assert {"tracker_get_issue", "tracker_add_comment", "gateway_whoami"} <= names
    assert not any(n.startswith("bitrix_") for n in names)

    bob = await harness.login("bob@company.ru")  # прав нет вообще
    assert not any(
        n.startswith(("tracker_", "bitrix_")) for n in _names(await harness.mcp(bob["access_token"], "tools/list"))
    )


async def test_resource_denial_is_audited_as_denied(harness):
    await _restrict(harness, ("role:readonly", "tracker", "SUP", "read"))
    tok = await harness.login("alice@company.ru")
    harness.mock.get(f"{TRACKER}/issues/HR-1").mock(return_value=httpx.Response(200, json={"key": "HR-1"}))
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "HR-1"}}
    )
    assert res.get("isError") is True
    async with harness.app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.target == "tracker_get_issue"))).scalars().all()
    assert [e.outcome for e in ev] == ["denied"]


async def test_hidden_tool_call_by_name_is_denied(harness):
    """Скрытый в списке инструмент нельзя вызвать, зная имя."""
    await _restrict(harness, ("role:readonly", "tracker", "SUP", "read"))
    tok = await harness.login("alice@company.ru")
    route = harness.mock.post(f"{HOOK}/crm.deal.list.json").mock(return_value=httpx.Response(200, json={"result": []}))
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "bitrix_crm_list", "arguments": {"entity_type": "deal"}}
    )
    assert res.get("isError") is True
    assert not route.called


async def test_grant_change_applies_immediately(harness):
    await _restrict(harness, ("role:readonly", "tracker", "SUP", "read"))
    tok = await harness.login("alice@company.ru")
    harness.mock.get(f"{TRACKER}/issues/SUP-1").mock(return_value=httpx.Response(200, json={"key": "SUP-1"}))
    call = {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    assert (await harness.mcp(tok["access_token"], "tools/call", call)).get("isError") is False
    await _restrict(harness)  # отобрали всё
    assert (await harness.mcp(tok["access_token"], "tools/call", call)).get("isError") is True


async def test_whoami_lists_access(harness):
    await _restrict(
        harness, ("role:readonly", "tracker", "SUP", "write"), ("user:alice@company.ru", "onec", "Catalog_*", "read")
    )
    tok = await harness.login("alice@company.ru")
    res = await harness.mcp(tok["access_token"], "tools/call", {"name": "gateway_whoami", "arguments": {}})
    access = res["structuredContent"]["result"]["access"]
    # право write выше потолка роли readonly — не показывается как доступное
    assert {"connector": "onec", "resource": "Catalog_*", "level": "read"} in access
    assert all(a["level"] != "write" for a in access)


async def test_cli_grants(harness):
    db = harness.app.state.db
    p = build_parser()
    out = io.StringIO()
    assert (
        await _grants(db, p.parse_args(["grants", "add", "user:Ivan@company.ru", "tracker", "SUP", "write"]), out) == 0
    )
    assert (
        await _grants(db, p.parse_args(["grants", "add", "user:ivan@company.ru", "tracker", "SUP", "read"]), out) == 1
    )
    assert await _grants(db, p.parse_args(["grants", "add", "role:admin", "tracker", "*", "read"]), out) == 2
    out = io.StringIO()
    await _grants(db, p.parse_args(["grants", "list", "--subject", "user:ivan@company.ru"]), out)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1 and "user:ivan@company.ru\ttracker\tSUP\twrite" in lines[0]
    gid = int(lines[0].split("\t")[0])
    assert await _grants(db, p.parse_args(["grants", "remove", str(gid)]), io.StringIO()) == 0
    assert await _grants(db, p.parse_args(["grants", "remove", str(gid)]), io.StringIO()) == 1
