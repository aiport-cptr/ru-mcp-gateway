"""Моё дело (онлайн-бухгалтерия, REST API). Только чтение.

Документация: https://restapi.moedelo.org/s/?url=/docs (Api Explorer),
примеры от разработчиков сервиса: https://github.com/moedelo/api-examples
Авторизация: ключ API в заголовке md-api-key. Ключ даёт полный доступ к учёту фирмы;
шлюз вызывает только чтение (GET) — запись и удаление в коннекторе не реализованы.

Права шлюза (ресурс): вид данных — kontragent, contract, bill, act, invoice, waybill,
retailreport, good, stock.

Из ответов убираются служебные гиперссылки (_links, _embedded) и поле Online —
публичная ссылка на счёт, открывающаяся без входа.
"""

from __future__ import annotations

from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "moedelo"

# вид данных → путь списка (ресурс прав = ключ)
KINDS = {
    "kontragent": "/kontragents/api/v1/kontragent",
    "contract": "/contract/api/v1/contract",
    "bill": "/accounting/api/v1/sales/bill",
    "act": "/accounting/api/v1/sales/act",
    "invoice": "/accounting/api/v1/sales/invoice",
    "waybill": "/accounting/api/v1/sales/waybill",
    "retailreport": "/accounting/api/v1/sales/retailreport",
    "good": "/stock/api/v1/good",
    "stock": "/stock/api/v1/stock",
}
KIND_NAMES = (
    "kontragent — контрагенты, contract — договоры, bill — счета, act — акты, invoice — счета-фактуры, "
    "waybill — накладные, retailreport — отчёты о розничной продаже, good — товары, stock — склады"
)
DROP = frozenset({"_links", "_embedded", "Online"})


def slim(value: Any) -> Any:
    """Убрать служебные ссылки и публичную ссылку на документ (рекурсивно)."""
    if isinstance(value, dict):
        return {k: slim(v) for k, v in value.items() if k not in DROP}
    if isinstance(value, list):
        return [slim(v) for v in value]
    return value


def _kind(kind: str) -> str:
    if kind not in KINDS:
        raise ConnectorError(f"kind: один из {', '.join(KINDS)}")
    return kind


def _id(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 10**15:
        raise ConnectorError("id — положительное число")
    return value


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None, secrets: Any = None) -> list[ToolSpec]:
    if not settings.moedelo_api_key:
        return []
    base = settings.moedelo_api_base.rstrip("/")

    def headers() -> dict[str, str]:
        return {"md-api-key": settings.moedelo_api_key.get_secret_value(), "Accept": "application/json"}

    async def get(path: str, params: dict[str, Any] | None = None) -> Any:
        return await call_json(http, "GET", f"{base}{path}", system="Моё дело", headers=headers(), params=params)

    async def moedelo_list(kind: str, page: int = 1, page_size: int = 50) -> str:
        """Список данных из бухгалтерии «Моё дело». kind: kontragent — контрагенты, contract — договоры,
        bill — счета, act — акты, invoice — счета-фактуры, waybill — накладные, retailreport — отчёты
        о розничной продаже, good — товары, stock — склады. Страницы с 1."""
        current_permissions().require(CONNECTOR, _kind(kind), Level.READ)
        params = {"pageNo": max(1, min(page, 100_000)), "pageSize": max(1, min(page_size, 100))}
        data = await get(KINDS[kind], params)
        if isinstance(data, dict):
            rows = data.get("ResourceList", [])
            out: dict[str, Any] = {"rows": slim(rows) if isinstance(rows, list) else []}
            for key in ("TotalCount", "PageNo", "PageSize"):
                if key in data:
                    out[key] = data[key]
            return clip(out)
        return clip({"rows": slim(data) if isinstance(data, list) else []})

    async def moedelo_get(kind: str, id: int) -> str:  # noqa: A002 — так понятнее модели
        """Одна запись из «Моё дело» по id: контрагент, договор, счёт, акт и т.д. (kind — как в moedelo_list)."""
        current_permissions().require(CONNECTOR, _kind(kind), Level.READ)
        data = await get(f"{KINDS[kind]}/{_id(id)}")
        return clip(slim(data))

    async def moedelo_kontragent_contacts(kontragent_id: int) -> str:
        """Контактные лица контрагента в «Моё дело» (ФИО, телефоны, почта)."""
        current_permissions().require(CONNECTOR, "kontragent", Level.READ)
        data = await get(f"{KINDS['kontragent']}/{_id(kontragent_id)}/contact")
        rows = data.get("ResourceList", []) if isinstance(data, dict) else []
        return clip(slim(rows))

    return [
        ToolSpec("moedelo_list", Level.READ, moedelo_list, moedelo_list.__doc__, CONNECTOR),
        ToolSpec("moedelo_get", Level.READ, moedelo_get, moedelo_get.__doc__, CONNECTOR),
        ToolSpec(
            "moedelo_kontragent_contacts",
            Level.READ,
            moedelo_kontragent_contacts,
            moedelo_kontragent_contacts.__doc__,
            CONNECTOR,
        ),
    ]
