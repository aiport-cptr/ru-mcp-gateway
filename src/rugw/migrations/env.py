"""Окружение Alembic.

Миграции запускаются только через rugw.migrate (на уже открытом соединении),
поэтому здесь нет собственного подключения к базе.
"""

from __future__ import annotations

from alembic import context

from rugw.db import Base

config = context.config
connection = config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Запускайте миграции командой: python -m rugw migrate")

context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=connection.dialect.name == "sqlite",  # ALTER TABLE в SQLite
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
