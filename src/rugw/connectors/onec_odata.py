"""1С:Предприятие через стандартный OData. Только чтение.

В 1С: Администрирование → Опубликовать на веб-сервере → «Публиковать стандартный
интерфейс OData», затем открыть нужные объекты (обработка «Настройка автоматического
REST-сервиса»). Заведите отдельного пользователя 1С с правами только на чтение.

Права шлюза (ресурс): имя набора OData, например Catalog_Контрагенты или Document_*.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from rugw.access import AccessDenied, current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "onec"

# Имя набора OData, например Catalog_Контрагенты или Document_РеализацияТоваровУслуг.
ENTITY = re.compile(r"^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё0-9_]{0,200}$")
FIELD = re.compile(r"^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё0-9_/]{0,200}$")


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None) -> list[ToolSpec]:
    if not (settings.onec_odata_url and settings.onec_username and settings.onec_password):
        return []
    base = settings.onec_odata_url.rstrip("/")
    auth = httpx.BasicAuth(settings.onec_username, settings.onec_password.get_secret_value())

    async def onec_list_entities(name_contains: str = "") -> str:
        """Список доступных наборов данных 1С (справочники, документы, регистры). Можно фильтровать по подстроке."""
        data = await call_json(http, "GET", f"{base}/", system="1С", auth=auth, params={"$format": "json"})
        perms = current_permissions()
        names = [v.get("name") or v.get("url") for v in (data or {}).get("value", []) if isinstance(v, dict)]
        needle = name_contains.lower()
        return clip(
            sorted(
                n
                for n in names
                if isinstance(n, str)
                and ENTITY.match(n)
                and needle in n.lower()
                and perms.allows(CONNECTOR, n, Level.READ)
            )
        )

    async def onec_query(
        entity: str,
        filter: str = "",
        select: list[str] | None = None,
        orderby: str = "",
        top: int = 20,
    ) -> str:
        """Чтение записей набора 1С. filter и orderby — в синтаксисе OData,
        например filter="Description eq 'Ромашка'" и orderby="Date desc"."""
        if not ENTITY.match(entity):
            raise ConnectorError("Некорректное имя набора 1С")
        perms = current_permissions()
        perms.require(CONNECTOR, entity, Level.READ)
        for f in select or []:
            if not FIELD.match(f):
                raise ConnectorError(f"Некорректное имя поля: {f}")
        # Навигация через «/» (Контрагент/ИНН) читает данные другого набора. Разрешаем её,
        # только если доступ есть ко всем наборам 1С — иначе это обход прав на наборы.
        if not perms.allows(CONNECTOR, "*", Level.READ):
            if any("/" in f for f in select or []) or "/" in filter or "/" in orderby:
                raise AccessDenied(
                    "Переходы по ссылкам на другие наборы («/» в select, filter, orderby) доступны "
                    "только при доступе ко всем наборам 1С"
                )
        params = {"$format": "json", "$top": str(max(1, min(top, 100)))}
        if filter:
            params["$filter"] = filter
        if select:
            params["$select"] = ",".join(select)
        if orderby:
            params["$orderby"] = orderby
        data = await call_json(http, "GET", f"{base}/{quote(entity)}", system="1С", auth=auth, params=params)
        return clip((data or {}).get("value", data))

    return [
        ToolSpec("onec_list_entities", Level.READ, onec_list_entities, onec_list_entities.__doc__, CONNECTOR),
        ToolSpec("onec_query", Level.READ, onec_query, onec_query.__doc__, CONNECTOR),
    ]
