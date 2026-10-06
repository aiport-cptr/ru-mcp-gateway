"""Права на ресурсы коннекторов. Модель описана в docs/design/0.3-access.md.

Итоговое право = min(потолок роли, max по подходящим правам). Роль admin — доступ ко всему.
Права только разрешающие; нет подходящего права — нет доступа.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass
from fnmatch import fnmatchcase

from sqlalchemy import or_, select

from rugw.config import ROLES
from rugw.db import Database, ResourceGrant
from rugw.policy import Level, role_allows

CONNECTORS = ("tracker", "bitrix24", "onec")
GRANT_LEVELS = (Level.READ, Level.WRITE)
_RANK = {Level.READ: 1, Level.WRITE: 2}

# Шаблоны ресурса: буквы, цифры, _ : - и звёздочка. Без ?, [ ], пробелов — fnmatch видит только *.
_RESOURCE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9_:*-]{1,200}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AccessDenied(Exception):  # noqa: N818 — так понятнее в коде коннекторов
    """Нет права на ресурс. Текст уходит модели и в аудит: без секретов."""


def normalize_subject(subject: str) -> str:
    kind, _, value = subject.strip().partition(":")
    kind, value = kind.lower(), value.strip()
    if kind == "role":
        if value not in ROLES or value == "admin":
            raise ValueError("Роль: readonly или member (admin и так имеет доступ ко всему)")
        return f"role:{value}"
    if kind == "user":
        value = value.lower()
        if not _EMAIL.match(value):
            raise ValueError("Ожидается user:<email>")
        return f"user:{value}"
    raise ValueError("Субъект: role:<роль> или user:<email>")


def validate_grant(subject: str, connector: str, resource: str, level: str) -> tuple[str, str, str, str]:
    subject = normalize_subject(subject)
    if connector != "*" and connector not in CONNECTORS:
        raise ValueError(f"Коннектор: один из {', '.join(CONNECTORS)} или *")
    if not _RESOURCE.match(resource):
        raise ValueError("Ресурс: буквы, цифры, _ : - и * (без пробелов)")
    if level not in GRANT_LEVELS:
        raise ValueError("Уровень: read или write")
    return subject, connector, resource, level


@dataclass(frozen=True)
class _Rule:
    connector: str
    resource: str
    level: Level

    def matches(self, connector: str, resource: str) -> bool:
        return self.connector in ("*", connector) and fnmatchcase(resource, self.resource)

    def touches(self, connector: str) -> bool:
        return self.connector in ("*", connector)


@dataclass(frozen=True)
class Permissions:
    """Права одного пользователя, загруженные на время одного вызова инструмента."""

    role: str
    rules: tuple[_Rule, ...]
    user_id: int | None = None  # кто вызывает: нужно коннекторам с доступом от имени пользователя

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def _ceiling(self, level: Level) -> bool:
        return role_allows(self.role, level)

    def allows(self, connector: str, resource: str, level: Level) -> bool:
        if not self._ceiling(level):
            return False
        if self.is_admin:
            return True
        if level not in _RANK:
            return False
        need = _RANK[level]
        return any(_RANK[r.level] >= need and r.matches(connector, resource) for r in self.rules)

    def allows_connector(self, connector: str, level: Level) -> bool:
        """Есть ли хоть какой-то доступ нужного уровня к коннектору (для списка инструментов)."""
        if not self._ceiling(level):
            return False
        if self.is_admin:
            return True
        if level not in _RANK:  # уровень admin — только для роли admin
            return False
        need = _RANK[level]
        return any(_RANK[r.level] >= need and r.touches(connector) for r in self.rules)

    def may_have(self, connector: str, prefix: str, level: Level) -> bool:
        """Может ли быть доступ хоть к одному ресурсу, начинающемуся с prefix (например deal:).

        Только для быстрого отказа до обращения во внешнюю систему; окончательная проверка —
        allows() по фактическому ресурсу. Правило подходит, если его шаблон начинается
        с prefix или является префиксом prefix со звёздочкой («*», «de*», «deal:*»).
        """
        if not self._ceiling(level):
            return False
        if self.is_admin:
            return True
        if level not in _RANK:
            return False
        need = _RANK[level]
        for r in self.rules:
            if _RANK[r.level] < need or not r.touches(connector):
                continue
            pattern = r.resource
            star = pattern.find("*")
            head = pattern if star < 0 else pattern[:star]
            if pattern.startswith(prefix) or (star >= 0 and prefix.startswith(head)):
                return True
        return False

    def require(self, connector: str, resource: str, level: Level) -> None:
        if not self.allows(connector, resource, level):
            raise AccessDenied(f"Нет доступа ({level.value}) к ресурсу «{resource}» в коннекторе {connector}")


async def load_permissions(db: Database, email: str, role: str, user_id: int | None = None) -> Permissions:
    if role == "admin":
        return Permissions(role=role, rules=(), user_id=user_id)
    async with db.session() as s:
        rows = (
            await s.execute(
                select(ResourceGrant).where(
                    or_(ResourceGrant.subject == f"user:{email.lower()}", ResourceGrant.subject == f"role:{role}")
                )
            )
        ).scalars()
        rules = tuple(_Rule(r.connector, r.resource, Level(r.level)) for r in rows if r.level in GRANT_LEVELS)
    return Permissions(role=role, rules=rules, user_id=user_id)


# Права текущего вызова. Устанавливает обёртка guarded (tools.py) перед вызовом инструмента.
_current: ContextVar[Permissions | None] = ContextVar("rugw_permissions", default=None)


def current_permissions() -> Permissions:
    perms = _current.get()
    if perms is None:  # инструмент вызван вне guarded — это ошибка программиста, а не отказ
        raise RuntimeError("Права не загружены: инструмент вызван в обход guarded")
    return perms


def set_current(perms: Permissions | None):
    return _current.set(perms)


def reset_current(token) -> None:
    _current.reset(token)
