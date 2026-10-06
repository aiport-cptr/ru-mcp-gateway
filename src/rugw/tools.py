"""Регистрация инструментов: каждый вызов проходит проверку прав и аудит.

Коннектор описывает инструменты через ToolSpec, указывая уровень (read/write/admin)
и коннектор. Шлюз оборачивает функцию: кто вызывает → разрешено ли роли и есть ли право
на коннектор → вызов (права на конкретные ресурсы коннектор проверяет сам через
access.current_permissions()) → запись в аудит.
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

from rugw.access import AccessDenied, Permissions, load_permissions, reset_current, set_current
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
    connector: str | None = None  # None — инструмент самого шлюза, права на ресурсы не нужны


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
        self._specs: dict[str, ToolSpec] = {}

    async def list_tools(self):  # type: ignore[override]
        tools = await super().list_tools()
        actor = await current_actor(self._db)
        if actor is None:
            return []
        perms = await load_permissions(self._db, actor.email, actor.role)
        # Инструмент, не прошедший через register(), не защищён guarded — не показываем никому.
        return [t for t in tools if t.name in self._specs and tool_visible(perms, self._specs[t.name])]


def tool_visible(perms: Permissions, spec: ToolSpec) -> bool:
    if spec.connector is None:
        return role_allows(perms.role, spec.level)
    return perms.allows_connector(spec.connector, spec.level)


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
    if spec.name in server._specs:
        raise ValueError(f"Инструмент {spec.name} зарегистрирован дважды")
    fn = spec.fn

    @functools.wraps(fn)
    async def guarded(**kwargs: Any) -> Any:
        actor = await current_actor(server._db)
        if actor is None:
            raise ToolError("Нет авторизации")
        args_text = audit_dump(kwargs, settings.audit_max_arg_chars)
        perms = await load_permissions(server._db, actor.email, actor.role, actor.user_id)

        async def audit(outcome: str, detail: str, duration_ms: int | None = None) -> None:
            await auditor.log(
                event="tool_call",
                outcome=outcome,
                user_id=actor.user_id,
                client_id=actor.client_id,
                target=spec.name,
                detail=detail,
                duration_ms=duration_ms,
            )

        if not tool_visible(perms, spec):
            await audit("denied", args_text)
            what = f"коннектору {spec.connector}" if spec.connector else "инструменту"
            raise ToolError(f"Нет доступа уровня {spec.level.value} к {what} (роль «{actor.role}»)")

        t0 = time.monotonic()
        outcome, detail = "ok", args_text
        ctx = set_current(perms)
        try:
            return await fn(**kwargs)
        except AccessDenied as exc:
            outcome, detail = "denied", f"{args_text} | {exc}"
            raise ToolError(str(exc)) from exc
        except ConnectorError as exc:
            outcome, detail = "error", f"{args_text} | {exc}"
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            outcome, detail = "error", f"{args_text} | {type(exc).__name__}"
            raise
        finally:
            reset_current(ctx)
            await audit(outcome, detail, int((time.monotonic() - t0) * 1000))

    # functools.wraps кладёт __wrapped__, и SDK строит схему по сигнатуре исходной функции.
    guarded.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
    server._specs[spec.name] = spec
    server.add_tool(
        guarded,
        name=spec.name,
        description=f"[{spec.level.value}] {spec.description}",
        annotations=ToolAnnotations(
            read_only_hint=spec.level == Level.READ,
            destructive_hint=False,
        ),
    )
