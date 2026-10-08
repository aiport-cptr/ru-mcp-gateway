"""Яндекс Трекер (REST API v3).

Документация: https://yandex.ru/support/tracker/ru/about-api

Режимы (RUGW_TRACKER_AUTH_MODE):
  service — общий токен RUGW_TRACKER_TOKEN;
  user    — токен Яндекса сотрудника (credentials.py): действуют и права шлюза, и права в Трекере.

Права шлюза: ресурс — ключ очереди. Очередь задачи берётся из ответа Трекера, а не из
переданного ключа: перемещённая задача доступна по старому ключу, но живёт в другой очереди.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from rugw.access import AccessDenied, current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.credentials import CredentialsUnavailable, YandexCredentials
from rugw.errors import ErrorCode
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "tracker"
ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}-\d{1,9}$")
QUEUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _key(key: str) -> str:
    key = key.strip().upper()
    if not ISSUE_KEY.match(key):
        raise ConnectorError("Ключ задачи должен выглядеть как QUEUE-123")
    return key


def queue_of(issue: Any) -> str | None:
    """Очередь задачи из ответа Трекера; None — если определить нельзя (тогда доступа нет)."""
    if not isinstance(issue, dict):
        return None
    q = issue.get("queue")
    if isinstance(q, dict) and isinstance(q.get("key"), str) and QUEUE_KEY.match(q["key"]):
        return q["key"]
    key = issue.get("key")
    if isinstance(key, str) and ISSUE_KEY.match(key):
        return key.rsplit("-", 1)[0]
    return None


HIDDEN = {"hidden": "задача из очереди, недоступной вам в шлюзе"}


def hide_foreign_issues(value: Any, perms, depth: int = 0) -> Any:
    """Заменить вложенные ссылки на задачи (parent, epic, …) из недоступных очередей заглушкой.

    Верхний уровень — сама задача, её доступ уже проверен. Ссылка на задачу — словарь с полем
    key вида QUEUE-123; её очередь — из поля queue, если есть, иначе из ключа.
    """
    if isinstance(value, list):
        return [hide_foreign_issues(v, perms, depth + 1) for v in value]
    if not isinstance(value, dict):
        return value
    if depth > 0 and isinstance(value.get("key"), str) and ISSUE_KEY.match(value["key"]):
        queue = queue_of(value)
        if queue is None or not perms.allows(CONNECTOR, queue, Level.READ):
            return dict(HIDDEN)
    return {k: hide_foreign_issues(v, perms, depth + 1) for k, v in value.items()}


def build(
    settings: Settings, http: httpx.AsyncClient, credentials: YandexCredentials | None = None, secrets: Any = None
) -> list[ToolSpec]:
    user_mode = settings.tracker_auth_mode == "user"
    if not settings.tracker_org_id:
        return []
    if user_mode and credentials is None:
        raise RuntimeError("tracker_auth_mode=user, но хранилище токенов не настроено")
    if not user_mode and not settings.tracker_token:
        return []
    base = settings.tracker_api_base.rstrip("/")
    org_header = "X-Cloud-Org-ID" if settings.tracker_org_kind == "cloud" else "X-Org-ID"

    async def headers() -> dict[str, str]:
        if user_mode:
            user_id = current_permissions().user_id
            if user_id is None:
                raise ConnectorError("Трекер: не определён пользователь", ErrorCode.INTERNAL)
            try:
                token = await credentials.access_token(user_id)
            except CredentialsUnavailable as exc:
                raise ConnectorError(
                    f"Трекер: {exc} — переподключите шлюз в клиенте (войдите через Яндекс заново)",
                    ErrorCode.RELOGIN_REQUIRED,
                ) from exc
        else:
            token = settings.tracker_token.get_secret_value()
        return {"Authorization": f"OAuth {token}", org_header: settings.tracker_org_id}

    async def get_issue_checked(key: str, level: Level) -> dict:
        perms = current_permissions()
        key = _key(key)
        # Быстрый отказ по ключу — без обращения в Трекер.
        perms.require(CONNECTOR, key.rsplit("-", 1)[0], level)
        issue = await call_json(http, "GET", f"{base}/issues/{key}", system="Трекер", headers=await headers())
        queue = queue_of(issue)
        if queue is None:
            raise AccessDenied("Трекер: не удалось определить очередь задачи")
        # Окончательная проверка — по фактической очереди из ответа.
        perms.require(CONNECTOR, queue, level)
        return issue

    async def tracker_search_issues(query: str, limit: int = 20) -> str:
        """Поиск задач на языке запросов Трекера, например: Queue: SUP Status: open "Sort By": Updated DESC.
        Возвращаются только задачи из очередей, доступных вам в шлюзе."""
        perms = current_permissions()
        limit = max(1, min(limit, 50))
        data = await call_json(
            http,
            "POST",
            f"{base}/issues/_search",
            system="Трекер",
            headers=await headers(),
            params={"perPage": limit},
            json={"query": query},
        )
        visible, hidden = [], 0
        for i in (data if isinstance(data, list) else [])[:limit]:
            queue = queue_of(i)
            if queue is None or not perms.allows(CONNECTOR, queue, Level.READ):
                hidden += 1
                continue
            visible.append(
                {
                    "key": i.get("key"),
                    "summary": i.get("summary"),
                    "status": (i.get("status") or {}).get("display"),
                    "assignee": (i.get("assignee") or {}).get("display"),
                    "updatedAt": i.get("updatedAt"),
                }
            )
        result: dict[str, Any] = {"issues": visible}
        if hidden:
            result["hidden"] = f"{hidden} задач скрыто: нет доступа к их очередям"
        return clip(result)

    async def tracker_get_issue(key: str) -> str:
        """Полная карточка задачи по ключу QUEUE-123. Связанные задачи из недоступных вам очередей скрыты."""
        issue = await get_issue_checked(key, Level.READ)
        return clip(hide_foreign_issues(issue, current_permissions()))

    async def tracker_get_comments(key: str) -> str:
        """Комментарии к задаче."""
        issue = await get_issue_checked(key, Level.READ)
        real_key = _key(issue.get("key") or key)
        data = await call_json(
            http, "GET", f"{base}/issues/{real_key}/comments", system="Трекер", headers=await headers()
        )
        slim = [
            {
                "author": (c.get("createdBy") or {}).get("display"),
                "createdAt": c.get("createdAt"),
                "text": c.get("text"),
            }
            for c in (data if isinstance(data, list) else [])
            if isinstance(c, dict)
        ]
        return clip(slim)

    async def tracker_add_comment(key: str, text: str) -> str:
        """Добавить комментарий к задаче."""
        if not text.strip():
            raise ConnectorError("Пустой комментарий")
        if len(text) > 20_000:
            raise ConnectorError("Комментарий длиннее 20 000 символов")
        issue = await get_issue_checked(key, Level.WRITE)
        real_key = _key(issue.get("key") or key)
        data = await call_json(
            http,
            "POST",
            f"{base}/issues/{real_key}/comments",
            system="Трекер",
            headers=await headers(),
            json={"text": text},
        )
        return clip({"ok": True, "key": real_key, "id": data.get("id") if isinstance(data, dict) else None})

    def spec(fn, level: Level) -> ToolSpec:
        return ToolSpec(fn.__name__, level, fn, fn.__doc__, connector=CONNECTOR)

    return [
        spec(tracker_search_issues, Level.READ),
        spec(tracker_get_issue, Level.READ),
        spec(tracker_get_comments, Level.READ),
        spec(tracker_add_comment, Level.WRITE),
    ]
