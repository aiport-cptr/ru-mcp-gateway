"""Яндекс Трекер (REST API v3).

Документация: https://yandex.ru/support/tracker/ru/about-api
Работает от имени сервисной учётной записи (токен в RUGW_TRACKER_TOKEN).
"""

from __future__ import annotations

import re

import httpx

from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}-\d{1,9}$")


def _key(key: str) -> str:
    key = key.strip().upper()
    if not ISSUE_KEY.match(key):
        raise ConnectorError("Ключ задачи должен выглядеть как QUEUE-123")
    return key


def build(settings: Settings, http: httpx.AsyncClient) -> list[ToolSpec]:
    if not (settings.tracker_token and settings.tracker_org_id):
        return []
    base = settings.tracker_api_base.rstrip("/")
    org_header = "X-Cloud-Org-ID" if settings.tracker_org_kind == "cloud" else "X-Org-ID"

    def headers() -> dict[str, str]:
        return {
            "Authorization": f"OAuth {settings.tracker_token.get_secret_value()}",
            org_header: settings.tracker_org_id,
        }

    async def tracker_search_issues(query: str, limit: int = 20) -> str:
        """Поиск задач на языке запросов Трекера, например: Queue: SUP Status: open "Sort By": Updated DESC"""
        limit = max(1, min(limit, 50))
        data = await call_json(
            http,
            "POST",
            f"{base}/issues/_search",
            system="Трекер",
            headers=headers(),
            params={"perPage": limit},
            json={"query": query},
        )
        slim = [
            {
                "key": i.get("key"),
                "summary": i.get("summary"),
                "status": (i.get("status") or {}).get("display"),
                "assignee": (i.get("assignee") or {}).get("display"),
                "updatedAt": i.get("updatedAt"),
            }
            for i in (data or [])[:limit]
        ]
        return clip(slim)

    async def tracker_get_issue(key: str) -> str:
        """Полная карточка задачи по ключу QUEUE-123."""
        return clip(await call_json(http, "GET", f"{base}/issues/{_key(key)}", system="Трекер", headers=headers()))

    async def tracker_get_comments(key: str) -> str:
        """Комментарии к задаче."""
        data = await call_json(http, "GET", f"{base}/issues/{_key(key)}/comments", system="Трекер", headers=headers())
        slim = [
            {
                "author": (c.get("createdBy") or {}).get("display"),
                "createdAt": c.get("createdAt"),
                "text": c.get("text"),
            }
            for c in (data or [])
        ]
        return clip(slim)

    async def tracker_add_comment(key: str, text: str) -> str:
        """Добавить комментарий к задаче."""
        if not text.strip():
            raise ConnectorError("Пустой комментарий")
        if len(text) > 20_000:
            raise ConnectorError("Комментарий длиннее 20 000 символов")
        data = await call_json(
            http,
            "POST",
            f"{base}/issues/{_key(key)}/comments",
            system="Трекер",
            headers=headers(),
            json={"text": text},
        )
        return clip({"ok": True, "id": data.get("id") if isinstance(data, dict) else None})

    return [
        ToolSpec("tracker_search_issues", Level.READ, tracker_search_issues, tracker_search_issues.__doc__),
        ToolSpec("tracker_get_issue", Level.READ, tracker_get_issue, tracker_get_issue.__doc__),
        ToolSpec("tracker_get_comments", Level.READ, tracker_get_comments, tracker_get_comments.__doc__),
        ToolSpec("tracker_add_comment", Level.WRITE, tracker_add_comment, tracker_add_comment.__doc__),
    ]
