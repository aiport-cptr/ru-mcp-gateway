"""Коннекторы: правильные запросы во внешние системы и защита от некорректного ввода."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rugw.connectors import bitrix24, onec_odata, yandex_tracker
from rugw.tools import ConnectorError
from tests.conftest import make_settings

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("as_admin")]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _tools(specs):
    return {s.name: s for s in specs}


async def test_tracker_disabled_without_credentials(tmp_path):
    assert yandex_tracker.build(make_settings(tmp_path), httpx.AsyncClient()) == []


async def test_tracker_search_and_headers(tmp_path):
    s = make_settings(tmp_path, tracker_token="trk-secret", tracker_org_id="123")
    async with httpx.AsyncClient() as http:
        t = _tools(yandex_tracker.build(s, http))
        with respx.mock:
            route = respx.post("https://api.tracker.yandex.net/v3/issues/_search").mock(
                return_value=httpx.Response(
                    200, json=[{"key": "SUP-1", "summary": "Тест", "status": {"display": "Открыт"}}]
                )
            )
            out = await t["tracker_search_issues"].fn(query="Queue: SUP", limit=5)
        req = route.calls[0].request
        assert req.headers["Authorization"] == "OAuth trk-secret"
        assert req.headers["X-Org-ID"] == "123"
        assert json.loads(req.content) == {"query": "Queue: SUP"}
        assert "SUP-1" in out
        assert t["tracker_add_comment"].level.value == "write"


@pytest.mark.parametrize("bad", ["../admin", "SUP-1/comments", "sup 1", "SUP-", ""])
async def test_tracker_rejects_bad_keys(tmp_path, bad):
    s = make_settings(tmp_path, tracker_token="t", tracker_org_id="1")
    t = _tools(yandex_tracker.build(s, httpx.AsyncClient()))
    with pytest.raises(ConnectorError):
        await t["tracker_get_issue"].fn(key=bad)


async def test_tracker_auth_error_does_not_leak_token(tmp_path):
    s = make_settings(tmp_path, tracker_token="trk-secret", tracker_org_id="1")
    async with httpx.AsyncClient() as http:
        t = _tools(yandex_tracker.build(s, http))
        with respx.mock:
            respx.get("https://api.tracker.yandex.net/v3/issues/SUP-1").mock(return_value=httpx.Response(401))
            with pytest.raises(ConnectorError) as e:
                await t["tracker_get_issue"].fn(key="sup-1")
    assert "trk-secret" not in str(e.value)


async def test_bitrix_list_and_entity_whitelist(tmp_path):
    hook = "https://corp.bitrix24.ru/rest/1/hooksecret"
    s = make_settings(tmp_path, bitrix24_webhook_url=hook)
    async with httpx.AsyncClient() as http:
        t = _tools(bitrix24.build(s, http))
        with respx.mock:
            respx.post(f"{hook}/crm.deal.list.json").mock(
                return_value=httpx.Response(200, json={"result": [{"ID": "7", "TITLE": "Сделка", "CATEGORY_ID": "0"}]})
            )
            out = await t["bitrix_crm_list"].fn(entity_type="deal")
        assert "Сделка" in out
        with pytest.raises(ConnectorError):
            await t["bitrix_crm_list"].fn(entity_type="user")  # не CRM — запрещено


async def test_bitrix_api_error_surfaces(tmp_path):
    hook = "https://corp.bitrix24.ru/rest/1/hooksecret"
    s = make_settings(tmp_path, bitrix24_webhook_url=hook)
    async with httpx.AsyncClient() as http:
        t = _tools(bitrix24.build(s, http))
        with respx.mock:
            respx.post(f"{hook}/crm.deal.get.json").mock(
                return_value=httpx.Response(200, json={"error": "NOT_FOUND", "error_description": "Not found"})
            )
            with pytest.raises(ConnectorError) as e:
                await t["bitrix_crm_get"].fn(entity_type="deal", id=1)
    assert "hooksecret" not in str(e.value)


async def test_onec_query_builds_odata(tmp_path):
    base = "https://1c.corp.ru/base/odata/standard.odata"
    s = make_settings(tmp_path, onec_odata_url=base, onec_username="ai_reader", onec_password="p")
    async with httpx.AsyncClient() as http:
        t = _tools(onec_odata.build(s, http))
        assert all(spec.level.value == "read" for spec in t.values())
        with respx.mock:
            route = respx.get(url__startswith=f"{base}/Catalog_").mock(
                return_value=httpx.Response(200, json={"value": [{"Description": "Ромашка"}]})
            )
            out = await t["onec_query"].fn(entity="Catalog_Контрагенты", filter="Description eq 'Ромашка'", top=500)
        q = route.calls[0].request.url.params
        assert q["$top"] == "100"  # ограничение сверху
        assert q["$filter"] == "Description eq 'Ромашка'"
        assert "Ромашка" in out


@pytest.mark.parametrize("bad", ["../$metadata", "Catalog_X?$top=1", "Catalog X", "Catalog_X/../../"])
async def test_onec_rejects_bad_entity(tmp_path, bad):
    s = make_settings(tmp_path, onec_odata_url="https://1c/x", onec_username="u", onec_password="p")
    t = _tools(onec_odata.build(s, httpx.AsyncClient()))
    with pytest.raises(ConnectorError):
        await t["onec_query"].fn(entity=bad)
