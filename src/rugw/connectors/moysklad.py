"""МойСклад (JSON API 1.2). Только чтение.

Документация: https://dev.moysklad.ru/doc/api/remap/1.2/
Токен: Настройки → Токены. Заведите для шлюза пользователя только с правами на просмотр.

Права шлюза (ресурс): тип сущности — product, counterparty, customerorder, demand, supply,
store, а также stock для отчёта об остатках.
"""

from __future__ import annotations

from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "moysklad"
ENTITIES = {
    "product": "Товары",
    "counterparty": "Контрагенты",
    "customerorder": "Заказы покупателей",
    "demand": "Отгрузки",
    "supply": "Приёмки",
    "store": "Склады",
}
# Поля, которые отдаём модели: служебные meta/ссылки занимают много места и ей не нужны.
FIELDS = (
    "id",
    "name",
    "code",
    "article",
    "externalCode",
    "description",
    "moment",
    "updated",
    "sum",
    "payedSum",
    "shippedSum",
    "inn",
    "kpp",
    "phone",
    "email",
    "archived",
    "applicable",
    "stock",
    "reserve",
    "inTransit",
    "quantity",
    "price",
    "salePrice",
    "uom",
)


def _slim(row: Any) -> Any:
    if not isinstance(row, dict):
        return row
    out = {k: row[k] for k in FIELDS if k in row}
    state = row.get("state")
    if isinstance(state, dict) and "name" in state:
        out["state"] = state["name"]
    return out


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None) -> list[ToolSpec]:
    if not settings.moysklad_token:
        return []
    base = settings.moysklad_api_base.rstrip("/")

    def headers() -> dict[str, str]:
        return {
            "Authorization": f"Bearer {settings.moysklad_token.get_secret_value()}",
            # МойСклад требует сжатие ответа
            "Accept-Encoding": "gzip",
        }

    async def moysklad_list(entity: str, search: str = "", limit: int = 20, offset: int = 0) -> str:
        """Список записей МойСклад. entity: product (товары), counterparty (контрагенты),
        customerorder (заказы покупателей), demand (отгрузки), supply (приёмки), store (склады).
        search — контекстный поиск по названию, коду, артикулу и т.п."""
        if entity not in ENTITIES:
            raise ConnectorError(f"entity: один из {', '.join(ENTITIES)}")
        current_permissions().require(CONNECTOR, entity, Level.READ)
        params: dict[str, Any] = {"limit": max(1, min(limit, 100)), "offset": max(0, min(offset, 1_000_000))}
        if search:
            params["search"] = search[:200]
        data = await call_json(
            http, "GET", f"{base}/entity/{entity}", system="МойСклад", headers=headers(), params=params
        )
        rows = data.get("rows", []) if isinstance(data, dict) else []
        size = (data.get("meta") or {}).get("size") if isinstance(data, dict) else None
        return clip({"total": size, "rows": [_slim(r) for r in rows]})

    async def moysklad_stock(search: str = "", limit: int = 50, offset: int = 0) -> str:
        """Остатки товаров по всем складам (отчёт «Остатки»). search — поиск по товару."""
        current_permissions().require(CONNECTOR, "stock", Level.READ)
        params: dict[str, Any] = {"limit": max(1, min(limit, 100)), "offset": max(0, min(offset, 1_000_000))}
        if search:
            params["search"] = search[:200]
        data = await call_json(
            http, "GET", f"{base}/report/stock/all", system="МойСклад", headers=headers(), params=params
        )
        rows = data.get("rows", []) if isinstance(data, dict) else []
        return clip([_slim(r) for r in rows])

    return [
        ToolSpec("moysklad_list", Level.READ, moysklad_list, moysklad_list.__doc__, CONNECTOR),
        ToolSpec("moysklad_stock", Level.READ, moysklad_stock, moysklad_stock.__doc__, CONNECTOR),
    ]
