"""amoCRM (API v4) по долгосрочному токену.

Документация: https://www.amocrm.ru/developers/content/crm_platform/leads-api
Токен: Настройки → Интеграции → «Создать интеграцию» → долгосрочный токен. Выдайте его
пользователю amoCRM с минимально нужными правами: шлюз не может расширить права токена.

Права шлюза (ресурс): lead:<id воронки>, contact, company.
Воронка сделки берётся из ответа amoCRM (pipeline_id), а не из аргументов.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from rugw.access import AccessDenied, current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.errors import ErrorCode
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "amocrm"
NOTE_ENTITIES = {"lead": "leads", "contact": "contacts", "company": "companies"}
_ID = re.compile(r"^\d{1,12}$")


def lead_resource(lead: Any) -> str | None:
    if not isinstance(lead, dict):
        return None
    pid = lead.get("pipeline_id")
    return f"lead:{pid}" if isinstance(pid, int) and pid >= 0 else None


def _slim_lead(lead: dict) -> dict:
    return {
        k: lead.get(k)
        for k in (
            "id",
            "name",
            "price",
            "status_id",
            "pipeline_id",
            "responsible_user_id",
            "created_at",
            "updated_at",
            "closed_at",
        )
        if k in lead
    }


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None, secrets: Any = None) -> list[ToolSpec]:
    if not (settings.amocrm_base_url and settings.amocrm_token):
        return []
    base = f"{settings.amocrm_base_url}/api/v4"

    def headers() -> dict[str, str]:
        return {"Authorization": f"Bearer {settings.amocrm_token.get_secret_value()}"}

    async def api(method: str, path: str, **kw: Any) -> Any:
        return await call_json(http, method, f"{base}{path}", system="amoCRM", headers=headers(), **kw)

    def check_id(value: int) -> int:
        if not _ID.match(str(value)):
            raise ConnectorError("Некорректный id")
        return int(value)

    async def lead_checked(lead_id: int, level: Level) -> dict:
        perms = current_permissions()
        if not perms.may_have(CONNECTOR, "lead:", level):
            raise AccessDenied(f"Нет доступа ({level.value}) к сделкам ни в одной воронке")
        lead = await api("GET", f"/leads/{check_id(lead_id)}")
        if not isinstance(lead, dict):
            raise ConnectorError("amoCRM: сделка не найдена", ErrorCode.UPSTREAM_NOT_FOUND)
        if not perms.is_admin:
            resource = lead_resource(lead)
            if resource is None:
                raise AccessDenied("amoCRM: не удалось определить воронку сделки")
            perms.require(CONNECTOR, resource, level)
        return lead

    async def amocrm_leads_list(query: str = "", pipeline_id: int | None = None, limit: int = 20) -> str:
        """Сделки amoCRM: поиск по тексту (query) и/или воронке (pipeline_id).
        Возвращаются только сделки из воронок, доступных вам в шлюзе."""
        perms = current_permissions()
        if not perms.may_have(CONNECTOR, "lead:", Level.READ):
            raise AccessDenied("Нет доступа к сделкам ни в одной воронке")
        limit = max(1, min(limit, 50))
        params: dict[str, Any] = {"limit": limit}
        if query:
            params["query"] = query[:200]
        if pipeline_id is not None:
            params["filter[pipeline_id]"] = check_id(pipeline_id)
        data = await api("GET", "/leads", params=params)
        leads = ((data or {}).get("_embedded") or {}).get("leads") or [] if isinstance(data, dict) else []
        visible, hidden = [], 0
        for lead in leads:
            resource = lead_resource(lead)
            if not perms.is_admin and (resource is None or not perms.allows(CONNECTOR, resource, Level.READ)):
                hidden += 1
                continue
            visible.append(_slim_lead(lead))
        out: dict[str, Any] = {"leads": visible}
        if hidden:
            out["hidden"] = f"{hidden} сделок скрыто: нет доступа к их воронкам"
        return clip(out)

    async def amocrm_lead_get(id: int) -> str:
        """Карточка сделки amoCRM по id (со связанными контактами)."""
        return clip(await lead_checked(id, Level.READ))

    async def amocrm_contacts_list(query: str = "", limit: int = 20) -> str:
        """Контакты amoCRM, поиск по имени, телефону, почте."""
        current_permissions().require(CONNECTOR, "contact", Level.READ)
        params: dict[str, Any] = {"limit": max(1, min(limit, 50))}
        if query:
            params["query"] = query[:200]
        data = await api("GET", "/contacts", params=params)
        rows = ((data or {}).get("_embedded") or {}).get("contacts") or [] if isinstance(data, dict) else []
        return clip(
            [{k: c.get(k) for k in ("id", "name", "responsible_user_id", "custom_fields_values")} for c in rows]
        )

    async def amocrm_add_note(entity_type: str, id: int, text: str) -> str:
        """Добавить текстовое примечание к сделке (lead), контакту (contact) или компании (company)."""
        if entity_type not in NOTE_ENTITIES:
            raise ConnectorError(f"entity_type: один из {', '.join(NOTE_ENTITIES)}")
        if not text.strip():
            raise ConnectorError("Пустое примечание")
        entity_id = check_id(id)
        if entity_type == "lead":
            await lead_checked(entity_id, Level.WRITE)  # воронка из ответа amoCRM
        else:
            current_permissions().require(CONNECTOR, entity_type, Level.WRITE)
        data = await api(
            "POST",
            f"/{NOTE_ENTITIES[entity_type]}/notes",
            json=[{"entity_id": entity_id, "note_type": "common", "params": {"text": text[:20_000]}}],
        )
        notes = ((data or {}).get("_embedded") or {}).get("notes") or [] if isinstance(data, dict) else []
        return clip({"ok": True, "id": notes[0].get("id") if notes and isinstance(notes[0], dict) else None})

    def spec(fn, level: Level) -> ToolSpec:
        return ToolSpec(fn.__name__, level, fn, fn.__doc__, connector=CONNECTOR)

    return [
        spec(amocrm_leads_list, Level.READ),
        spec(amocrm_lead_get, Level.READ),
        spec(amocrm_contacts_list, Level.READ),
        spec(amocrm_add_note, Level.WRITE),
    ]
