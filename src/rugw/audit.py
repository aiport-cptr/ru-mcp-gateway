"""Журнал аудита. Запись в аудит не должна ронять основную операцию."""

from __future__ import annotations

import logging

from rugw.db import AuditEvent, Database

log = logging.getLogger(__name__)


class Auditor:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def log(
        self,
        *,
        event: str,
        outcome: str,
        user_id: int | None = None,
        client_id: str | None = None,
        target: str | None = None,
        detail: str | None = None,
        duration_ms: int | None = None,
        request_id: str | None = None,
    ) -> None:
        try:
            async with self.db.session() as s:
                s.add(
                    AuditEvent(
                        event=event,
                        outcome=outcome,
                        user_id=user_id,
                        client_id=client_id,
                        target=target,
                        detail=detail,
                        duration_ms=duration_ms,
                        request_id=request_id,
                    )
                )
        except Exception:  # noqa: BLE001 — аудит не должен ломать запрос, но падение видно в логах
            log.exception("audit write failed: event=%s target=%s", event, target)
