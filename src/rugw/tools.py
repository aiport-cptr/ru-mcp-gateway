"""Регистрация инструментов: каждый вызов проходит проверку прав и аудит.

Коннектор описывает инструменты через ToolSpec, указывая уровень (read/write/admin).
Шлюз оборачивает функцию: кто вызывает → разрешено ли роли → вызов → запись в аудит.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from rugw.audit import Auditor
from rugw.config import Settings
from rugw.db import Database, User
from rugw.policy import Level, role_allows
from rugw.security import audit_dump


@dataclass(frozen=True)
class ToolSpec:
    name: str
    level: Level
    fn: Callable[..., Awaitable[Any]]
    description: str


@dataclass(frozen=True)
class Actor:
    user_id: int
    client_id: str
    email: str
    role: str


class ConnectorError(Exception):
    """Ожидаемая ошибка внешней системы. Текст уходит модели, поэтому без секретов."""


class GatewayServer(MCPServer):
    """MCPServer, который показывает пользователю только разрешённые ему инструменты."""

    def __init__(self, *args: Any, db: Database, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._db = db
        self._levels: dict[str, Level] = {}

    async def list_tools(self):  # type: ignore[override]
        tools = await super().list_tools()
        actor = await current_actor(self._db)
        if actor is None:
            return []
        return [t for t in tools if role_allows(actor.role, self._levels.get(t.name, Level.ADMIN))]


async def current_actor(db: Database) -> Actor | None:
    tok = get_access_token()
    user_id = getattr(tok, "user_id", None)
    if tok is None or user_id is None:
        return None
    async with db.session() as s:
        user = await s.get(User, user_id)
        if user is None or user.disabled:
            return None
        return Actor(user_id=user.id, client_id=tok.client_id, email=user.email, role=user.role)


def register(server: GatewayServer, spec: ToolSpec, settings: Settings, auditor: Auditor) -> None:
    if spec.name in server._levels:
        raise ValueError(f"Инструмент {spec.name} зарегистрирован дважды")
    fn = spec.fn

    @functools.wraps(fn)
    async def guarded(**kwargs: Any) -> Any:
        actor = await current_actor(server._db)
        if actor is None:
            raise ToolError("Нет авторизации")
        args_text = audit_dump(kwargs, settings.audit_max_arg_chars)
        if not role_allows(actor.role, spec.level):
            await auditor.log(
                event="tool_call",
                outcome="denied",
                user_id=actor.user_id,
                client_id=actor.client_id,
                target=spec.name,
                detail=args_text,
            )
            raise ToolError(f"Роли «{actor.role}» недоступен инструмент уровня {spec.level.value}")
        t0 = time.monotonic()
        outcome, detail = "ok", args_text
        try:
            return await fn(**kwargs)
        except ConnectorError as exc:
            outcome, detail = "error", f"{args_text} | {exc}"
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            outcome, detail = "error", f"{args_text} | {type(exc).__name__}"
            raise
        finally:
            await auditor.log(
                event="tool_call",
                outcome=outcome,
                user_id=actor.user_id,
                client_id=actor.client_id,
                target=spec.name,
                detail=detail,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    # functools.wraps кладёт __wrapped__, и SDK строит схему по сигнатуре исходной функции.
    guarded.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
    server._levels[spec.name] = spec.level
    server.add_tool(
        guarded,
        name=spec.name,
        description=f"[{spec.level.value}] {spec.description}",
        annotations=ToolAnnotations(
            read_only_hint=spec.level == Level.READ,
            destructive_hint=False,
        ),
    )
