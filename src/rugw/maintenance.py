"""Удаление отслуживших записей.

Что удаляется:
  - незавершённые входы и коды авторизации после истечения срока;
  - access- и refresh-токены после истечения срока. Использованный refresh-токен
    хранится до своего срока: он нужен, чтобы распознать повторное использование;
  - гранты, у которых не осталось ни одного токена;
  - события аудита старше audit_retention_days (если не 0).
Пользователи и зарегистрированные клиенты не удаляются.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from sqlalchemy import delete, exists, select

from rugw.config import Settings
from rugw.db import AuditEvent, AuthCode, Database, Grant, PendingLogin, Token

log = logging.getLogger(__name__)


@dataclass
class CleanupReport:
    pending_logins: int = 0
    auth_codes: int = 0
    tokens: int = 0
    grants: int = 0
    audit_events: int = 0

    def total(self) -> int:
        return self.pending_logins + self.auth_codes + self.tokens + self.grants + self.audit_events


async def cleanup(db: Database, settings: Settings, now: float | None = None) -> CleanupReport:
    now = time.time() if now is None else now
    r = CleanupReport()
    async with db.session() as s:
        r.pending_logins = (await s.execute(delete(PendingLogin).where(PendingLogin.expires_at < now))).rowcount
        r.auth_codes = (await s.execute(delete(AuthCode).where(AuthCode.expires_at < now))).rowcount
        r.tokens = (await s.execute(delete(Token).where(Token.expires_at < now))).rowcount
        has_tokens = exists(select(Token.token_hash).where(Token.grant_id == Grant.id))
        r.grants = (await s.execute(delete(Grant).where(~has_tokens))).rowcount
        if settings.audit_retention_days:
            border = now - settings.audit_retention_days * 86400
            r.audit_events = (await s.execute(delete(AuditEvent).where(AuditEvent.ts < border))).rowcount
    return r


async def cleanup_loop(db: Database, settings: Settings) -> None:
    """Фоновая очистка. Ошибки логируются, цикл не останавливается."""
    while True:
        try:
            report = await cleanup(db, settings)
            if report.total():
                log.info("cleanup: %s", report)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("cleanup failed")
        await asyncio.sleep(settings.cleanup_interval_seconds)
