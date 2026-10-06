"""Битрикс24 через входящий вебхук.

Вебхук создаётся в портале: Разработчикам → Другое → Входящий вебхук.
Выдайте вебхуку только права CRM. URL вебхука — секрет (RUGW_BITRIX24_WEBHOOK_URL).
Методы REST вызываются только из явного списка ниже; произвольные методы недоступны.

Права шлюза (ресурс): lead, contact, company, а для сделок — deal:<id воронки>
(CATEGORY_ID; 0 — основная воронка). Воронка сделки берётся из ответа портала.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from rugw.access import AccessDenied, current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip, safe_code
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "bitrix24"
ENTITIES = {"deal": "crm.deal", "lead": "crm.lead", "contact": "crm.contact", "company": "crm.company"}
_CATEGORY = re.compile(r"^\d{1,9}$")


def deal_resource(record: Any) -> str | None:
    """deal:<CATEGORY_ID> из ответа портала; None — воронку определить нельзя (доступа нет)."""
    if not isinstance(record, dict):
        return None
    cat = record.get("CATEGORY_ID")
    cat = str(cat) if isinstance(cat, int | str) else None
    return f"deal:{cat}" if cat is not None and _CATEGORY.match(cat) else None


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None) -> list[ToolSpec]:
    if not settings.bitrix24_webhook_url:
        return []

    def url(method: str) -> str:
        return settings.bitrix24_webhook_url.get_secret_value().rstrip("/") + f"/{method}.json"

    async def rest(method: str, payload: dict[str, Any]) -> Any:
        data = await call_json(http, "POST", url(method), system="Битрикс24", json=payload)
        if isinstance(data, dict) and data.get("error"):
            # error_description — произвольный текст портала, наружу не отдаём; только код.
            code = safe_code(data.get("error")) or "UNKNOWN"
            raise ConnectorError(f"Битрикс24: ошибка, код {code}")
        return data.get("result") if isinstance(data, dict) else data

    def entity(name: str) -> str:
        if name not in ENTITIES:
            raise ConnectorError(f"Сущность должна быть одной из: {', '.join(ENTITIES)}")
        return ENTITIES[name]

    def precheck(entity_type: str, level: Level) -> None:
        """Отказ до обращения в портал, если доступа к этому типу записей нет совсем."""
        perms = current_permissions()
        if entity_type == "deal":
            if not perms.may_have(CONNECTOR, "deal:", level):
                raise AccessDenied(f"Нет доступа ({level.value}) к сделкам ни в одной воронке")
        else:
            perms.require(CONNECTOR, entity_type, level)

    def record_resource(entity_type: str, record: Any) -> str | None:
        return deal_resource(record) if entity_type == "deal" else entity_type

    async def get_checked(entity_type: str, record_id: int, level: Level) -> Any:
        entity(entity_type)
        precheck(entity_type, level)
        record = await rest(f"{ENTITIES[entity_type]}.get", {"id": int(record_id)})
        perms = current_permissions()
        if perms.is_admin:
            return record
        resource = record_resource(entity_type, record)
        if resource is None:
            raise AccessDenied("Битрикс24: не удалось определить воронку сделки")
        perms.require(CONNECTOR, resource, level)
        return record

    async def bitrix_crm_list(
        entity_type: str,
        filter: dict[str, Any] | None = None,
        select: list[str] | None = None,
        limit: int = 20,
    ) -> str:
        """Список сделок/лидов/контактов/компаний. entity_type: deal|lead|contact|company.
        filter — фильтр в формате Битрикс24, например {"STAGE_ID": "NEW", ">OPPORTUNITY": 100000}.
        Сделки возвращаются только из воронок, доступных вам в шлюзе."""
        method = entity(entity_type)
        precheck(entity_type, Level.READ)
        limit = max(1, min(limit, 50))
        fields = list(select or ["ID", "TITLE", "STAGE_ID", "OPPORTUNITY", "ASSIGNED_BY_ID"])
        if entity_type == "deal" and "CATEGORY_ID" not in fields and "*" not in fields:
            fields.append("CATEGORY_ID")  # нужно для проверки воронки
        result = await rest(
            f"{method}.list",
            {"filter": filter or {}, "select": fields, "order": {"ID": "DESC"}},
        )
        perms = current_permissions()
        visible, hidden = [], 0
        for rec in result if isinstance(result, list) else []:
            resource = record_resource(entity_type, rec)
            if not perms.is_admin and (resource is None or not perms.allows(CONNECTOR, resource, Level.READ)):
                hidden += 1
                continue
            visible.append(rec)
        out: dict[str, Any] = {"items": visible[:limit]}
        if hidden:
            out["hidden"] = f"{hidden} записей скрыто: нет доступа к их воронкам"
        return clip(out)

    async def bitrix_crm_get(entity_type: str, id: int) -> str:
        """Карточка одной записи CRM по ID."""
        return clip(await get_checked(entity_type, id, Level.READ))

    async def bitrix_crm_add_comment(entity_type: str, id: int, comment: str) -> str:
        """Добавить комментарий в таймлайн записи CRM."""
        if not comment.strip():
            raise ConnectorError("Пустой комментарий")
        await get_checked(entity_type, id, Level.WRITE)  # существует и доступна на запись
        result = await rest(
            "crm.timeline.comment.add",
            {"fields": {"ENTITY_ID": int(id), "ENTITY_TYPE": entity_type, "COMMENT": comment[:20_000]}},
        )
        return clip({"ok": True, "id": result})

    def spec(fn, level: Level) -> ToolSpec:
        return ToolSpec(fn.__name__, level, fn, fn.__doc__, connector=CONNECTOR)

    return [
        spec(bitrix_crm_list, Level.READ),
        spec(bitrix_crm_get, Level.READ),
        spec(bitrix_crm_add_comment, Level.WRITE),
    ]
