"""0.4: коды ошибок и номер запроса, связанные задачи Трекера, новые коннекторы."""

from __future__ import annotations

import io
import json
import logging
import re

import httpx
import pytest
import respx
from pydantic import ValidationError
from sqlalchemy import delete, select

from rugw.__main__ import _audit, _grants, build_parser, configure_logging
from rugw.access import AccessDenied, Permissions, _Rule
from rugw.connectors import amocrm, build_all, kontur_focus, marketplaces, moysklad
from rugw.connectors.yandex_tracker import hide_foreign_issues
from rugw.db import AuditEvent, ResourceGrant
from rugw.policy import Level
from rugw.tools import ToolSpec
from tests.conftest import make_settings

pytestmark = pytest.mark.anyio

AMO = "https://acme.amocrm.ru/api/v4"
MS = "https://api.moysklad.ru/api/remap/1.2"
FOCUS = "https://focus-api.kontur.ru/api3"
WB = "https://statistics-api.wildberries.ru"
OZON = "https://api-seller.ozon.ru"
RID = re.compile(r"запрос (rq-[0-9a-f]{12})")


def tools(builder, tmp_path, **settings):
    return {t.name: t for t in builder(make_settings(tmp_path, **settings), httpx.AsyncClient())}


# ================================================================== коды ошибок и номер запроса


@pytest.fixture
def harness_settings():
    return {"tracker_token": "svc", "tracker_org_id": "1"}


async def _call(harness, token, name, args):
    return await harness.mcp(token, "tools/call", {"name": name, "arguments": args})


async def test_error_has_code_and_request_id_matching_audit(harness):
    tok = await harness.login("alice@company.ru")
    harness.mock.get("https://api.tracker.yandex.net/v3/issues/SUP-1").mock(return_value=httpx.Response(503))
    res = await _call(harness, tok["access_token"], "tracker_get_issue", {"key": "SUP-1"})
    text = str(res)
    assert res["isError"] is True
    assert "код UPSTREAM_ERROR" in text
    rid = RID.search(text).group(1)
    async with harness.app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.request_id == rid))).scalars().all()
    assert len(ev) == 1 and ev[0].target == "tracker_get_issue" and "UPSTREAM_ERROR" in ev[0].detail

    out = io.StringIO()
    await _audit(harness.app.state.db, build_parser().parse_args(["audit", "list", "--request", rid]), out)
    assert rid in out.getvalue() and "tracker_get_issue" in out.getvalue()


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "UPSTREAM_AUTH"), (404, "UPSTREAM_NOT_FOUND"), (429, "UPSTREAM_RATE_LIMIT"), (400, "UPSTREAM_BAD_REQUEST")],
)
async def test_upstream_status_codes(harness, status, code):
    tok = await harness.login("alice@company.ru")
    harness.mock.get("https://api.tracker.yandex.net/v3/issues/SUP-1").mock(return_value=httpx.Response(status))
    assert f"код {code}" in str(await _call(harness, tok["access_token"], "tracker_get_issue", {"key": "SUP-1"}))


async def test_access_denied_and_bad_input_codes(harness):
    tok = await harness.login("alice@company.ru")
    res = await _call(harness, tok["access_token"], "tracker_get_issue", {"key": "../x"})
    assert "код BAD_INPUT" in str(res)
    async with harness.app.state.db.session() as s:
        await s.execute(delete(ResourceGrant))
        s.add(ResourceGrant(subject="role:readonly", connector="tracker", resource="SUP", level="read"))
    res = await _call(harness, tok["access_token"], "tracker_get_issue", {"key": "HR-1"})
    assert "код ACCESS_DENIED" in str(res) and RID.search(str(res))


async def test_unexpected_error_is_internal_without_details(harness, caplog):
    from rugw.tools import register

    async def broken() -> str:
        raise RuntimeError("секретная-деталь-из-стека")

    app = harness.app
    register(
        app.state.server, ToolSpec("test_broken", Level.READ, broken, "boom"), app.state.settings, app.state.auditor
    )
    tok = await harness.login("alice@company.ru")
    with caplog.at_level(logging.ERROR, logger="rugw.tools"):
        res = await _call(harness, tok["access_token"], "test_broken", {})
    text = str(res)
    assert res["isError"] is True and "код INTERNAL" in text and "секретная" not in text
    rid = RID.search(text).group(1)
    assert any(rid in r.getMessage() for r in caplog.records)  # подробности — в лог сервера по номеру запроса


def test_httpx_url_logging_disabled():
    configure_logging()
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING


# ================================================================== Трекер: связанные задачи


def test_hide_foreign_issues():
    perms = Permissions(role="member", rules=(_Rule("tracker", "SUP", Level.READ),))
    issue = {
        "key": "SUP-1",
        "queue": {"key": "SUP"},
        "parent": {"key": "HR-5", "display": "Увольнение Иванова"},
        "epic": {"key": "SUP-2", "display": "Свой эпик"},
        "links": [{"object": {"key": "FIN-9", "display": "Бонусы"}}],
        "previousQueue": {"key": "HR", "display": "HR"},
    }
    out = hide_foreign_issues(issue, perms)
    dumped = json.dumps(out, ensure_ascii=False)
    assert "Увольнение" not in dumped and "Бонусы" not in dumped
    assert out["epic"]["display"] == "Свой эпик" and out["key"] == "SUP-1"
    assert out["previousQueue"] == {"key": "HR", "display": "HR"}  # очередь, не задача
    assert hide_foreign_issues(issue, Permissions(role="admin", rules=()))["parent"]["display"] == "Увольнение Иванова"


# ================================================================== реестр коннекторов


def test_connector_must_be_declared(tmp_path, monkeypatch):
    from rugw import connectors

    async def f() -> str:
        return ""

    monkeypatch.setattr(
        connectors, "BUILDERS", (lambda s, h, c: [ToolSpec("x", Level.READ, f, "x", connector="jira")],)
    )
    with pytest.raises(RuntimeError, match="jira"):
        build_all(make_settings(tmp_path), httpx.AsyncClient())


async def test_grants_accept_new_connectors(harness):
    db = harness.app.state.db
    for conn in ("amocrm", "moysklad", "focus", "wildberries", "ozon"):
        args = build_parser().parse_args(["grants", "add", "role:member", conn, "*", "read"])
        assert await _grants(db, args, io.StringIO()) == 0


# ================================================================== amoCRM


@pytest.mark.parametrize(
    "url",
    [
        "http://acme.amocrm.ru",
        "https://acme.amocrm.ru/api",
        "https://evil.ru",
        "https://amocrm.ru.evil.ru",
        "https://acme.amocrm.ru?x=1",
        "https://user@acme.amocrm.ru",
    ],
)
def test_amocrm_url_validation(tmp_path, url):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, amocrm_base_url=url, amocrm_token="t")


def test_amocrm_url_normalized(tmp_path):
    assert (
        make_settings(tmp_path, amocrm_base_url="https://acme.kommo.com/").amocrm_base_url == "https://acme.kommo.com"
    )


async def test_amocrm_leads_filtered_by_pipeline(tmp_path, as_user):
    as_user("member", ("amocrm", "lead:100", "read"))
    t = tools(amocrm.build, tmp_path, amocrm_base_url="https://acme.amocrm.ru", amocrm_token="amo-secret")
    leads = [{"id": 1, "name": "свой", "pipeline_id": 100}, {"id": 2, "name": "чужой", "pipeline_id": 200}, {"id": 3}]
    with respx.mock:
        route = respx.get(f"{AMO}/leads").mock(return_value=httpx.Response(200, json={"_embedded": {"leads": leads}}))
        out = json.loads(await t["amocrm_leads_list"].fn(query="кофе"))
    assert [x["id"] for x in out["leads"]] == [1] and "2" in out["hidden"]
    req = route.calls[0].request
    assert req.headers["Authorization"] == "Bearer amo-secret" and req.url.params["query"] == "кофе"


async def test_amocrm_empty_list_204(tmp_path, as_admin):
    t = tools(amocrm.build, tmp_path, amocrm_base_url="https://acme.amocrm.ru", amocrm_token="x")
    with respx.mock:
        respx.get(f"{AMO}/leads").mock(return_value=httpx.Response(204))
        assert json.loads(await t["amocrm_leads_list"].fn()) == {"leads": []}


async def test_amocrm_note_needs_write_on_real_pipeline(tmp_path, as_user):
    as_user("member", ("amocrm", "lead:*", "read"), ("amocrm", "lead:100", "write"))
    t = tools(amocrm.build, tmp_path, amocrm_base_url="https://acme.amocrm.ru", amocrm_token="x")
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{AMO}/leads/2").mock(return_value=httpx.Response(200, json={"id": 2, "pipeline_id": 200}))
        post = m.post(f"{AMO}/leads/notes").mock(
            return_value=httpx.Response(200, json={"_embedded": {"notes": [{"id": 9}]}})
        )
        with pytest.raises(Exception, match="lead:200"):
            await t["amocrm_add_note"].fn(entity_type="lead", id=2, text="x")
        assert not post.called
        m.get(f"{AMO}/leads/1").mock(return_value=httpx.Response(200, json={"id": 1, "pipeline_id": 100}))
        assert json.loads(await t["amocrm_add_note"].fn(entity_type="lead", id=1, text="привет"))["id"] == 9
    assert json.loads(post.calls[0].request.content) == [
        {"entity_id": 1, "note_type": "common", "params": {"text": "привет"}}
    ]


async def test_amocrm_contact_note_requires_contact_write(tmp_path, as_user):
    as_user("member", ("amocrm", "contact", "read"))
    t = tools(amocrm.build, tmp_path, amocrm_base_url="https://acme.amocrm.ru", amocrm_token="x")
    with respx.mock(assert_all_called=False) as m:
        post = m.post(f"{AMO}/contacts/notes").mock(return_value=httpx.Response(200, json={}))
        with pytest.raises(Exception, match="contact"):
            await t["amocrm_add_note"].fn(entity_type="contact", id=5, text="x")
    assert not post.called


# ================================================================== МойСклад


async def test_moysklad_list_headers_and_slim(tmp_path, as_user):
    as_user("member", ("moysklad", "product", "read"))
    t = tools(moysklad.build, tmp_path, moysklad_token="ms-secret")
    rows = [{"id": "a", "name": "Кофе", "meta": {"href": "x" * 500}, "state": {"name": "Новый", "meta": {}}}]
    with respx.mock(assert_all_called=False) as m:
        route = m.get(f"{MS}/entity/product").mock(
            return_value=httpx.Response(200, json={"meta": {"size": 1}, "rows": rows})
        )
        out = json.loads(await t["moysklad_list"].fn(entity="product", search="кофе", limit=500))
        assert out == {"total": 1, "rows": [{"id": "a", "name": "Кофе", "state": "Новый"}]}
        req = route.calls[0].request
        assert req.headers["Authorization"] == "Bearer ms-secret" and "gzip" in req.headers["Accept-Encoding"]
        assert req.url.params["limit"] == "100"
        cp = m.get(f"{MS}/entity/counterparty").mock(return_value=httpx.Response(200, json={"rows": []}))
        with pytest.raises(Exception, match="counterparty"):
            await t["moysklad_list"].fn(entity="counterparty")
        assert not cp.called
        with pytest.raises(Exception, match="entity"):
            await t["moysklad_list"].fn(entity="../security/token")


# ================================================================== Контур.Фокус


def test_focus_ids():
    assert kontur_focus.parse_ids("7707083893, 1027700132195") == (["7707083893"], ["1027700132195"])
    for bad in ["", "123", "7707083893;abc", ",".join(["7707083893"] * 11)]:
        with pytest.raises(Exception):  # noqa: B017
            kontur_focus.parse_ids(bad)


async def test_focus_method_grant_and_key_not_leaked(tmp_path, as_user):
    as_user("member", ("focus", "req", "read"))
    t = tools(kontur_focus.build, tmp_path, focus_key="FOCUS-SECRET-KEY")
    with respx.mock(assert_all_called=False) as m:
        route = m.get(f"{FOCUS}/req").mock(return_value=httpx.Response(200, json=[{"inn": "7707083893"}]))
        await t["focus_lookup"].fn(inn_or_ogrn="7707083893")
        assert route.calls[0].request.url.params["key"] == "FOCUS-SECRET-KEY"
        analytics = m.get(f"{FOCUS}/analytics").mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(AccessDenied, match="analytics"):
            await t["focus_lookup"].fn(inn_or_ogrn="7707083893", method="analytics")
        assert not analytics.called
        m.get(f"{FOCUS}/req").mock(return_value=httpx.Response(403, text="bad key FOCUS-SECRET-KEY"))
        with pytest.raises(Exception) as e:
            await t["focus_lookup"].fn(inn_or_ogrn="7707083893")
    assert "FOCUS-SECRET-KEY" not in str(e.value)


# ================================================================== Wildberries


async def test_wb_report_truncation_and_auth(tmp_path, as_user):
    as_user("member", ("wildberries", "orders", "read"))
    t = tools(marketplaces.build, tmp_path, wildberries_token="wb-token")
    rows = [{"srid": str(i)} for i in range(700)]
    with respx.mock(assert_all_called=False) as m:
        route = m.get(f"{WB}/api/v1/supplier/orders").mock(return_value=httpx.Response(200, json=rows))
        out = json.loads(await t["wb_orders"].fn(date_from="2026-10-01", flag=1, limit=1000))
        assert out["total"] == 700 and len(out["rows"]) == 500 and "500 из 700" in out["truncated"]
        req = route.calls[0].request
        assert req.headers["Authorization"] == "wb-token"
        assert req.url.params["dateFrom"] == "2026-10-01" and req.url.params["flag"] == "1"
        sales = m.get(f"{WB}/api/v1/supplier/sales").mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(Exception, match="sales"):
            await t["wb_sales"].fn(date_from="2026-10-01")
        assert not sales.called


@pytest.mark.parametrize("bad", ["01.10.2026", "2026-13-01", "2026-10-01; drop", "вчера", "2026-02-30"])
async def test_wb_date_validation(tmp_path, as_admin, bad):
    t = tools(marketplaces.build, tmp_path, wildberries_token="x")
    with pytest.raises(Exception, match="[Дд]ат"):
        await t["wb_stocks"].fn(date_from=bad)


# ================================================================== Ozon


async def test_ozon_headers_bodies_and_grants(tmp_path, as_user):
    as_user("member", ("ozon", "stocks", "read"), ("ozon", "postings", "read"))
    t = tools(marketplaces.build, tmp_path, ozon_client_id="12345", ozon_api_key="oz-secret")
    with respx.mock(assert_all_called=False) as m:
        st = m.post(f"{OZON}/v4/product/info/stocks").mock(return_value=httpx.Response(200, json={"items": []}))
        await t["ozon_stocks"].fn(offer_ids=["SKU-1"], limit=5000)
        req = st.calls[0].request
        assert req.headers["Client-Id"] == "12345" and req.headers["Api-Key"] == "oz-secret"
        assert json.loads(req.content) == {
            "filter": {"visibility": "ALL", "offer_id": ["SKU-1"]},
            "last_id": "",
            "limit": 1000,
        }

        ps = m.post(f"{OZON}/v3/posting/fbs/list").mock(
            return_value=httpx.Response(200, json={"result": {"postings": []}})
        )
        await t["ozon_fbs_postings"].fn(since="2026-10-01", to="2026-10-05T12:00:00", status="awaiting_packaging")
        body = json.loads(ps.calls[0].request.content)
        assert body["filter"] == {
            "since": "2026-10-01T00:00:00Z",
            "to": "2026-10-05T12:00:00Z",
            "status": "awaiting_packaging",
        }

        pl = m.post(f"{OZON}/v3/product/list").mock(return_value=httpx.Response(200, json={"result": {}}))
        with pytest.raises(Exception, match="products"):
            await t["ozon_products"].fn()
        assert not pl.called
        with pytest.raises(Exception, match="артикул"):
            await t["ozon_stocks"].fn(offer_ids=['x"; drop'])


def test_ozon_client_id_validation(tmp_path):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, ozon_client_id="12a", ozon_api_key="k")


# ================================================================== сквозной: новые коннекторы видны по правам


async def test_new_connectors_in_tools_list(tmp_path):
    from rugw.app import build_app

    s = make_settings(
        tmp_path,
        amocrm_base_url="https://acme.amocrm.ru",
        amocrm_token="x",
        moysklad_token="x",
        focus_key="x",
        wildberries_token="x",
        ozon_client_id="1",
        ozon_api_key="x",
    )
    app = build_app(s, http=httpx.AsyncClient())
    names = set(app.state.server._specs)
    assert {
        "amocrm_leads_list",
        "amocrm_add_note",
        "moysklad_list",
        "moysklad_stock",
        "focus_lookup",
        "wb_stocks",
        "wb_orders",
        "wb_sales",
        "ozon_products",
        "ozon_stocks",
        "ozon_fbs_postings",
    } <= names
    write = {n for n, sp in app.state.server._specs.items() if sp.level == Level.WRITE}
    assert write & {"moysklad_list", "focus_lookup", "wb_orders", "ozon_stocks"} == set()  # только чтение
