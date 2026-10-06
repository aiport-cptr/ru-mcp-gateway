"""Модели и доступ к базе.

Секреты (токены, коды) хранятся только как SHA-256 хеши: утечка базы не даёт
рабочих токенов. Сырые значения существуют только в ответе клиенту.
"""

from __future__ import annotations

import time

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now() -> float:
    return time.time()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    yandex_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    login: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(320), index=True)
    role: Mapped[str] = mapped_column(String(16))  # admin | member | readonly
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[float] = mapped_column(Float, default=now)
    last_login_at: Mapped[float] = mapped_column(Float, default=now)


class OAuthClient(Base):
    """Клиент MCP (Claude Code, Cursor...), зарегистрированный через DCR."""

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    info_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[float] = mapped_column(Float, default=now)


class PendingLogin(Base):
    """Запрос /authorize, ожидающий входа через Яндекс и согласия пользователя."""

    __tablename__ = "pending_logins"

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64))
    params_json: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    # Заполняются после возврата из Яндекса:
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    consent_csrf_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthCode(Base):
    __tablename__ = "auth_codes"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    params_json: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Grant(Base):
    """Одна «сессия авторизации» клиента: связывает цепочку access/refresh токенов.

    Отзыв гранта гасит все его токены. Повторное использование уже
    обменянного refresh-токена считается кражей и отзывает весь грант.
    """

    __tablename__ = "grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scopes: Mapped[list] = mapped_column(JSON)
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Хеш кода авторизации, по которому выдан грант: повтор кода отзывает грант (RFC 6749 §4.1.2).
    auth_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[float] = mapped_column(Float, default=now)


class Token(Base):
    __tablename__ = "tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))  # access | refresh
    grant_id: Mapped[int] = mapped_column(ForeignKey("grants.id"), index=True)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)  # для refresh: уже обменян
    created_at: Mapped[float] = mapped_column(Float, default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[float] = mapped_column(Float, default=now, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event: Mapped[str] = mapped_column(String(64))  # tool_call, login_ok, login_denied, ...
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)  # имя инструмента и т.п.
    outcome: Mapped[str] = mapped_column(String(16))  # ok | denied | error
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class _Transaction:
    """Асинхронный контекст-менеджер на классе, а не на генераторе.

    contextlib.asynccontextmanager при пробросе исключения присваивает ему __traceback__,
    а исключения OAuth из MCP SDK (TokenError и др.) — frozen dataclass: присваивание
    падает с FrozenInstanceError и подменяет исходную ошибку. Здесь исключение
    пробрасывается как есть.
    """

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> AsyncSession:
        self._session = self._factory()
        await self._session.begin()
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        s = self._session
        if s is None:  # __aexit__ без __aenter__ — ошибка программиста
            raise RuntimeError("транзакция не была открыта")
        try:
            if exc_type is None:
                await s.commit()
            else:
                await s.rollback()
        finally:
            await s.close()
        return False  # исключение пробрасывается без изменений


class Database:
    def __init__(self, url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(url, pool_pre_ping=True)
        self._sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> _Transaction:
        """Сессия в транзакции: commit при нормальном выходе, rollback при исключении."""
        return _Transaction(self._sessions)

    async def dispose(self) -> None:
        await self.engine.dispose()
