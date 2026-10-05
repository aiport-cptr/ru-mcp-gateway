"""Кто может войти и что может делать.

Модель прав MVP — роли:
  readonly — только инструменты уровня read;
  member   — read и write;
  admin    — всё, включая admin-инструменты шлюза.

Права проверяются на каждом вызове по текущей роли из базы, а не по scopes
токена: понижение роли или блокировка действуют сразу, без перевыпуска токенов.
"""

from __future__ import annotations

from enum import StrEnum

from rugw.config import Settings


class Level(StrEnum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


ROLE_LEVELS: dict[str, frozenset[Level]] = {
    "readonly": frozenset({Level.READ}),
    "member": frozenset({Level.READ, Level.WRITE}),
    "admin": frozenset({Level.READ, Level.WRITE, Level.ADMIN}),
}


def role_allows(role: str, level: Level) -> bool:
    return level in ROLE_LEVELS.get(role, frozenset())


def admission_role(settings: Settings, email: str) -> str | None:
    """Роль для нового пользователя или None, если входить нельзя.

    Совпадение домена проверяется строго по части после последнего '@',
    чтобы 'evil-company.ru' не прошёл как 'company.ru'.
    """
    email = email.strip().lower()
    if "@" not in email:
        return None
    if email in settings.bootstrap_admins:
        return "admin"
    domain = email.rsplit("@", 1)[1]
    if email in settings.allowed_email_set or domain in settings.allowed_domains:
        return settings.default_role
    return None
