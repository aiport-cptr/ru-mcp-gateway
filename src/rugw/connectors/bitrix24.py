"""Битрикс24 через входящий вебхук.

Вебхук создаётся в портале: Разработчикам → Другое → Входящий вебхук.
Выдайте вебхуку только права CRM. URL вебхука — секрет (RUGW_BITRIX24_WEBHOOK_URL).
Методы REST вызываются только из явного списка ниже; произвольные методы недоступны.
"""

from __future__ import annotations

from typing import Any

import httpx

from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

ENTITIES = {"deal": "crm.deal", "lead": "crm.lead", "contact": "crm.contact", "company": "crm.company"}
TIMELINE_TYPES = {"deal": "deal", "lead": "lead", "contact": "contact", "company": "company"}


def build(settings: Settings, http: httpx.AsyncClient) -> list[ToolSpec]:
    if not settings.bitrix24_webhook_url:
        return []

    def url(method: str) -> str:
        return settings.bitrix24_webhook_url.get_secret_value().rstrip("/") + f"/{method}.json"

    async def rest(method: str, payload: dict[str, Any]) -> Any:
        data = await call_json(http, "POST", url(method), system="Битрикс24", json=payload)
        if isinstance(data, dict) and data.get("error"):
            raise ConnectorError(f"Битрикс24: {data.get('error_description') or data.get('error')}")
        return data.get("result") if isinstance(data, dict) else data

    def entity(name: str) -> str:
        if name not in ENTITIES:
            raise ConnectorError(f"Сущность должна быть одной из: {', '.join(ENTITIES)}")
        return ENTITIES[name]

    async def bitrix_crm_list(
        entity_type: str,
        filter: dict[str, Any] | None = None,
        select: list[str] | None = None,
        limit: int = 20,
    ) -> str:
        """Список сделок/лидов/контактов/компаний. entity_type: deal|lead|contact|company.
        filter — фильтр в формате Битрикс24, например {"STAGE_ID": "NEW", ">OPPORTUNITY": 100000}."""
        limit = max(1, min(limit, 50))
        result = await rest(
            f"{entity(entity_type)}.list",
            {
                "filter": filter or {},
                "select": select or ["ID", "TITLE", "STAGE_ID", "OPPORTUNITY", "ASSIGNED_BY_ID"],
                "order": {"ID": "DESC"},
            },
        )
        return clip((result or [])[:limit])

    async def bitrix_crm_get(entity_type: str, id: int) -> str:
        """Карточка одной записи CRM по ID."""
        return clip(await rest(f"{entity(entity_type)}.get", {"id": int(id)}))

    async def bitrix_crm_add_comment(entity_type: str, id: int, comment: str) -> str:
        """Добавить комментарий в таймлайн записи CRM."""
        if entity_type not in TIMELINE_TYPES:
            raise ConnectorError(f"Сущность должна быть одной из: {', '.join(TIMELINE_TYPES)}")
        if not comment.strip():
            raise ConnectorError("Пустой комментарий")
        result = await rest(
            "crm.timeline.comment.add",
            {"fields": {"ENTITY_ID": int(id), "ENTITY_TYPE": TIMELINE_TYPES[entity_type], "COMMENT": comment[:20_000]}},
        )
        return clip({"ok": True, "id": result})

    return [
        ToolSpec("bitrix_crm_list", Level.READ, bitrix_crm_list, bitrix_crm_list.__doc__),
        ToolSpec("bitrix_crm_get", Level.READ, bitrix_crm_get, bitrix_crm_get.__doc__),
        ToolSpec("bitrix_crm_add_comment", Level.WRITE, bitrix_crm_add_comment, bitrix_crm_add_comment.__doc__),
    ]
