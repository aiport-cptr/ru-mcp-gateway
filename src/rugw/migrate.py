"""Применение миграций схемы базы (Alembic) на открытом асинхронном соединении."""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Connection

from rugw.db import Database


def _config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "rugw:migrations")
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str:
    return ScriptDirectory.from_config(_config()).get_current_head()


V01_REVISION = "0001"  # схема, которую версия 0.1 создавала через create_all


async def upgrade(db: Database, revision: str = "head") -> None:
    def run(conn: Connection) -> None:
        cfg = _config(conn)
        # База от 0.1: таблицы есть, а версии Alembic нет — помечаем как 0001 и обновляем дальше.
        if MigrationContext.configure(conn).get_current_revision() is None and inspect(conn).has_table("users"):
            command.stamp(cfg, V01_REVISION)
        command.upgrade(cfg, revision)

    async with db.engine.begin() as conn:
        await conn.run_sync(run)


async def current_revision(db: Database) -> str | None:
    def run(conn: Connection) -> str | None:
        return MigrationContext.configure(conn).get_current_revision()

    async with db.engine.connect() as conn:
        return await conn.run_sync(run)


def autogenerate(sync_connection: Connection, message: str) -> None:
    """Для разработчиков: создать новую миграцию по разнице моделей и базы."""
    command.revision(_config(sync_connection), message=message, autogenerate=True)
