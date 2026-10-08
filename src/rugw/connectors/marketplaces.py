"""Маркетплейсы: Wildberries и Ozon. Только чтение.

Wildberries — Statistics API: https://dev.wildberries.ru/en/docs/openapi/reports
  Токен категории «Статистика» (только чтение). Лимит WB — 1 запрос в минуту на метод:
  частые вызовы вернут UPSTREAM_RATE_LIMIT. Ответ может содержать десятки тысяч строк —
  шлюз отдаёт модели не больше limit.
  Права шлюза (ресурс): stocks, orders, sales.

Ozon — Seller API: https://docs.ozon.ru/api/seller
  Ключ с ролью только на чтение. Права шлюза (ресурс): products, stocks, postings.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

WB = "wildberries"
OZON = "ozon"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?)?$")
_OFFER = re.compile(r"^[\w.\-/]{1,100}$")
WB_REPORTS = {
    "stocks": "/api/v1/supplier/stocks",
    "orders": "/api/v1/supplier/orders",
    "sales": "/api/v1/supplier/sales",
}
OZON_VISIBILITY = ("ALL", "VISIBLE", "INVISIBLE", "EMPTY_STOCK", "READY_TO_SUPPLY", "STATE_FAILED")


def check_date(value: str) -> str:
    value = value.strip()
    if not _DATE.match(value):
        raise ConnectorError("Дата: ГГГГ-ММ-ДД или ГГГГ-ММ-ДДTчч:мм[:сс]")
    try:
        dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConnectorError("Несуществующая дата") from exc
    return value


def build_wildberries(settings: Settings, http: httpx.AsyncClient) -> list[ToolSpec]:
    if not settings.wildberries_token:
        return []
    base = settings.wildberries_statistics_base.rstrip("/")

    async def report(name: str, date_from: str, flag: int | None, limit: int) -> str:
        current_permissions().require(WB, name, Level.READ)
        params: dict[str, Any] = {"dateFrom": check_date(date_from)}
        if flag is not None:
            if flag not in (0, 1):
                raise ConnectorError("flag: 0 (изменения с даты) или 1 (за конкретную дату)")
            params["flag"] = flag
        data = await call_json(
            http,
            "GET",
            f"{base}{WB_REPORTS[name]}",
            system="Wildberries",
            headers={"Authorization": settings.wildberries_token.get_secret_value()},
            params=params,
        )
        rows = data if isinstance(data, list) else []
        limit = max(1, min(limit, 500))
        out: dict[str, Any] = {"total": len(rows), "rows": rows[:limit]}
        if len(rows) > limit:
            out["truncated"] = f"показано {limit} из {len(rows)}; сузьте период"
        return clip(out)

    async def wb_stocks(date_from: str, limit: int = 100) -> str:
        """Остатки на складах Wildberries, изменившиеся с date_from (ГГГГ-ММ-ДД). Лимит WB: 1 запрос в минуту."""
        return await report("stocks", date_from, None, limit)

    async def wb_orders(date_from: str, flag: int = 0, limit: int = 100) -> str:
        """Заказы Wildberries. flag=0 — изменённые с date_from, flag=1 — все за дату date_from.
        Лимит WB: 1 запрос в минуту."""
        return await report("orders", date_from, flag, limit)

    async def wb_sales(date_from: str, flag: int = 0, limit: int = 100) -> str:
        """Продажи и возвраты Wildberries. flag=0 — изменённые с date_from, flag=1 — все за дату date_from.
        Лимит WB: 1 запрос в минуту."""
        return await report("sales", date_from, flag, limit)

    return [ToolSpec(f.__name__, Level.READ, f, f.__doc__, WB) for f in (wb_stocks, wb_orders, wb_sales)]


def build_ozon(settings: Settings, http: httpx.AsyncClient) -> list[ToolSpec]:
    if not (settings.ozon_client_id and settings.ozon_api_key):
        return []
    base = settings.ozon_api_base.rstrip("/")

    async def post(path: str, body: dict) -> Any:
        return await call_json(
            http,
            "POST",
            f"{base}{path}",
            system="Ozon",
            headers={"Client-Id": settings.ozon_client_id, "Api-Key": settings.ozon_api_key.get_secret_value()},
            json=body,
        )

    def visibility(value: str) -> str:
        if value not in OZON_VISIBILITY:
            raise ConnectorError(f"visibility: одно из {', '.join(OZON_VISIBILITY)}")
        return value

    def offers(value: list[str] | None) -> list[str]:
        for o in value or []:
            if not _OFFER.match(o):
                raise ConnectorError(f"Некорректный артикул: {o[:30]}")
        return list(value or [])[:100]

    async def ozon_products(visibility_filter: str = "ALL", limit: int = 50, last_id: str = "") -> str:
        """Список товаров Ozon (product_id, offer_id). Для следующей страницы передайте last_id из ответа."""
        current_permissions().require(OZON, "products", Level.READ)
        data = await post(
            "/v3/product/list",
            {
                "filter": {"visibility": visibility(visibility_filter)},
                "last_id": last_id[:200],
                "limit": max(1, min(limit, 1000)),
            },
        )
        return clip((data or {}).get("result", data) if isinstance(data, dict) else data)

    async def ozon_stocks(offer_ids: list[str] | None = None, limit: int = 50, last_id: str = "") -> str:
        """Остатки товаров Ozon (FBO и FBS). offer_ids — артикулы продавца; без них — все товары."""
        current_permissions().require(OZON, "stocks", Level.READ)
        flt: dict[str, Any] = {"visibility": "ALL"}
        if offer_ids:
            flt["offer_id"] = offers(offer_ids)
        data = await post(
            "/v4/product/info/stocks",
            {"filter": flt, "last_id": last_id[:200], "limit": max(1, min(limit, 1000))},
        )
        return clip(data)

    async def ozon_fbs_postings(since: str, to: str, status: str = "", limit: int = 50, offset: int = 0) -> str:
        """Отправления FBS за период since…to (ГГГГ-ММ-ДДTчч:мм:сс). status — например awaiting_packaging."""
        current_permissions().require(OZON, "postings", Level.READ)
        if status and not re.fullmatch(r"[a-z_]{1,50}", status):
            raise ConnectorError("status: латиница и _ (например awaiting_packaging)")

        def ts(v: str) -> str:
            v = check_date(v)
            return v if "T" in v else f"{v}T00:00:00"

        flt: dict[str, Any] = {"since": ts(since) + "Z", "to": ts(to) + "Z"}
        if status:
            flt["status"] = status
        data = await post(
            "/v3/posting/fbs/list",
            {"dir": "DESC", "filter": flt, "limit": max(1, min(limit, 1000)), "offset": max(0, offset)},
        )
        return clip((data or {}).get("result", data) if isinstance(data, dict) else data)

    return [
        ToolSpec(f.__name__, Level.READ, f, f.__doc__, OZON) for f in (ozon_products, ozon_stocks, ozon_fbs_postings)
    ]


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None, secrets: Any = None) -> list[ToolSpec]:
    return build_wildberries(settings, http) + build_ozon(settings, http)
