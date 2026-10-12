"""non-repeating credential versions for CAS (review 0.4.1)

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-12 23:10:00
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = {"user_credentials": ("user_id", "provider"), "service_credentials": ("provider",)}


def upgrade() -> None:
    conn = op.get_bind()
    for table, keys in TABLES.items():
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column("version", sa.String(length=32), server_default="", nullable=False))
        # У существующих записей — своя случайная версия, чтобы незавершённые обновления не совпали с ней.
        t = sa.table(table, *(sa.column(k) for k in keys), sa.column("version"))
        for row in conn.execute(sa.select(*(t.c[k] for k in keys))).all():
            cond = sa.and_(*(t.c[k] == v for k, v in zip(keys, row, strict=True)))
            conn.execute(sa.update(t).where(cond).values(version=uuid.uuid4().hex))


def downgrade() -> None:
    for table in TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column("version")
