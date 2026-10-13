"""0.4.5: коннектор «Моё дело» (только чтение). Только поддельные ответы."""

import io
import json

import httpx
import pytest
import respx

from rugw.__main__ import _grants, build_parser
from rugw.access import AccessDenied
from rugw.connectors import moedelo
from rugw.policy import Level
from rugw.tools import ConnectorError
from tests.conftest import make_settings

pytestmark = pytest.mark.anyio
MD = "https://restapi.moedelo.org"


def tools(tmp_path, **settings):
    return {t.name: t for t in moedelo.build(make_settings(tmp_path, **settings), httpx.AsyncClient())}


def test_disabled_without_key(tmp_path):
    assert tools(tmp_path) == {}


async def test_list_header_paging_and_slim(tmp_path, as_user):
    as_user("member", ("moedelo", "bill", "read"))
    t = tools(tmp_path, moedelo_api_key="md-synthetic-key")
    body = {
        "ResourceList": [
            {
                "Id": 7,
                "Number": "15",
                "Online": "https://moedelo.org/public/bill/secret-link",
                "Items": [{"Name": "Услуга", "_links": [{"rel": "self"}]}],
                "_links": [{"rel": "self", "href": "x"}],
            }
        ],
        "TotalCount": 1,
        "_links": [],
    }
    with respx.mock(assert_all_called=True) as m:
        route = m.get(f"{MD}/accounting/api/v1/sales/bill").mock(return_value=httpx.Response(200, json=body))
        out = json.loads(await t["moedelo_list"].fn(kind="bill", page=0, page_size=1000))
    req = route.calls[0].request
    assert req.headers["md-api-key"] == "md-synthetic-key"
    assert req.url.params["pageNo"] == "1" and req.url.params["pageSize"] == "100"
    assert out == {"rows": [{"Id": 7, "Number": "15", "Items": [{"Name": "Услуга"}]}], "TotalCount": 1}
    assert "secret-link" not in json.dumps(out)  # публичная ссылка на счёт не отдаётся


async def test_resource_grants_per_kind(tmp_path, as_user):
    as_user("member", ("moedelo", "kontragent", "read"))
    t = tools(tmp_path, moedelo_api_key="k")
    with respx.mock(assert_all_called=False) as m:
        bills = m.get(f"{MD}/accounting/api/v1/sales/bill")
        card = m.get(f"{MD}/kontragents/api/v1/kontragent/5").mock(
            return_value=httpx.Response(200, json={"Id": 5, "Inn": "7700000000", "_links": []})
        )
        contacts = m.get(f"{MD}/kontragents/api/v1/kontragent/5/contact").mock(
            return_value=httpx.Response(200, json={"ResourceList": [{"Fio": "Иванов", "_links": []}]})
        )
        with pytest.raises(AccessDenied):
            await t["moedelo_list"].fn(kind="bill")
        with pytest.raises(AccessDenied):
            await t["moedelo_get"].fn(kind="act", id=1)
        assert json.loads(await t["moedelo_get"].fn(kind="kontragent", id=5)) == {"Id": 5, "Inn": "7700000000"}
        assert json.loads(await t["moedelo_kontragent_contacts"].fn(kontragent_id=5)) == [{"Fio": "Иванов"}]
    assert not bills.called and card.called and contacts.called


@pytest.mark.parametrize("bad", ["../security", "bill/1", "", "BILL"])
async def test_kind_validated(tmp_path, as_admin, bad):
    t = tools(tmp_path, moedelo_api_key="k")
    with respx.mock(assert_all_called=False) as m:
        with pytest.raises(ConnectorError):
            await t["moedelo_list"].fn(kind=bad)
        assert not m.calls


@pytest.mark.parametrize("bad", [0, -1, 10**16, True])
async def test_id_validated(tmp_path, as_admin, bad):
    t = tools(tmp_path, moedelo_api_key="k")
    with respx.mock(assert_all_called=False) as m:
        with pytest.raises(ConnectorError):
            await t["moedelo_get"].fn(kind="bill", id=bad)
        assert not m.calls


async def test_upstream_error_is_neutral(tmp_path, as_admin):
    t = tools(tmp_path, moedelo_api_key="md-synthetic-key")
    with respx.mock() as m:
        m.get(f"{MD}/kontragents/api/v1/kontragent").mock(
            return_value=httpx.Response(401, text="invalid key md-synthetic-key for firm 123")
        )
        with pytest.raises(ConnectorError) as e:
            await t["moedelo_list"].fn(kind="kontragent")
    assert "md-synthetic-key" not in str(e.value) and "firm 123" not in str(e.value)


async def test_read_only_tools_and_grants(tmp_path, harness):
    t = tools(tmp_path, moedelo_api_key="k")
    assert {s.level for s in t.values()} == {Level.READ}
    args = build_parser().parse_args(["grants", "add", "role:member", "moedelo", "bill", "read"])
    assert await _grants(harness.app.state.db, args, io.StringIO()) == 0
