"""Точка входа.

  python -m rugw serve [--host 127.0.0.1] [--port 8000] [--no-migrate]
  python -m rugw migrate [--status]
  python -m rugw cleanup
  python -m rugw users list
  python -m rugw users set-role <email> <admin|member|readonly>
  python -m rugw users disable <email> | enable <email>
  python -m rugw audit list   [--since 24h] [--user email] [--event tool_call] [--outcome denied] [--limit 50]
  python -m rugw audit export [--since 30d] [--format jsonl|csv] [--output файл]

Управление — только из консоли сервера: у админки нет сетевой поверхности атаки.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import json
import logging
import re
import sys
import time
from collections.abc import AsyncIterator
from typing import TextIO

from sqlalchemy import select

from rugw.config import ROLES, Settings
from rugw.db import AuditEvent, Database, Grant, User
from rugw.maintenance import cleanup
from rugw.migrate import current_revision, head_revision, upgrade

DURATION = re.compile(r"^(\d+)([mhd])$")
AUDIT_FIELDS = ("id", "time", "user", "client_id", "event", "target", "outcome", "duration_ms", "detail")


def parse_since(value: str | None) -> float | None:
    """'15m', '24h', '30d' или дата ISO (2026-10-01) → unix-время."""
    if not value:
        return None
    m = DURATION.match(value)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return time.time() - n * {"m": 60, "h": 3600, "d": 86400}[unit]
    try:
        return dt.datetime.fromisoformat(value).timestamp()
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--since: укажите 15m, 24h, 30d или дату 2026-10-01") from exc


async def _check_schema(db: Database) -> bool:
    current, head = await current_revision(db), head_revision()
    if current != head:
        print(f"Схема базы {current or 'пустая'}, нужна {head}. Выполните: python -m rugw migrate", file=sys.stderr)
        return False
    return True


# ------------------------------------------------------------------ users


async def _users(db: Database, args: argparse.Namespace) -> int:
    async with db.session() as s:
        if args.action == "list":
            for u in (await s.execute(select(User).order_by(User.id))).scalars():
                print(f"{u.id}\t{u.email}\t{u.role}\t{'disabled' if u.disabled else 'active'}")
            return 0
        user = (await s.execute(select(User).where(User.email == args.email.lower()))).scalar_one_or_none()
        if user is None:
            print("Пользователь не найден (он должен хотя бы раз войти)", file=sys.stderr)
            return 1
        if args.action == "set-role":
            if args.role not in ROLES:
                print(f"Роль должна быть одной из {ROLES}", file=sys.stderr)
                return 2
            user.role = args.role
        elif args.action in ("disable", "enable"):
            user.disabled = args.action == "disable"
            if user.disabled:  # сразу гасим все выданные доступы
                for g in (await s.execute(select(Grant).where(Grant.user_id == user.id))).scalars():
                    g.revoked = True
        print(f"OK: {user.email} → role={user.role} disabled={user.disabled}")
        return 0


# ------------------------------------------------------------------ audit


async def iter_audit(db: Database, args: argparse.Namespace, limit: int | None) -> AsyncIterator[dict]:
    q = select(AuditEvent, User.email).outerjoin(User, User.id == AuditEvent.user_id)
    if args.since is not None:
        q = q.where(AuditEvent.ts >= args.since)
    if getattr(args, "user", None):
        q = q.where(User.email == args.user.lower())
    if getattr(args, "event", None):
        q = q.where(AuditEvent.event == args.event)
    if getattr(args, "outcome", None):
        q = q.where(AuditEvent.outcome == args.outcome)
    # list — свежие сверху; export — по порядку времени
    q = q.order_by(AuditEvent.id.desc() if limit else AuditEvent.id)
    if limit:
        q = q.limit(limit)
    async with db.session() as s:
        result = await s.stream(q.execution_options(yield_per=1000))
        async for ev, email in result:
            yield {
                "id": ev.id,
                "time": dt.datetime.fromtimestamp(ev.ts, dt.UTC).isoformat(timespec="seconds"),
                "user": email,
                "client_id": ev.client_id,
                "event": ev.event,
                "target": ev.target,
                "outcome": ev.outcome,
                "duration_ms": ev.duration_ms,
                "detail": ev.detail,
            }


async def _audit(db: Database, args: argparse.Namespace, out: TextIO) -> int:
    if args.action == "list":
        async for row in iter_audit(db, args, limit=max(1, args.limit)):
            detail = (row["detail"] or "")[:80]
            print(
                f"{row['time']}  {row['outcome']:<6} {row['event']:<16} {row['target'] or '-':<28} "
                f"{row['user'] or '-'}  {detail}",
                file=out,
            )
        return 0
    if args.format == "csv":
        w = csv.DictWriter(out, fieldnames=AUDIT_FIELDS)
        w.writeheader()
        async for row in iter_audit(db, args, limit=None):
            w.writerow(row)
    else:
        async for row in iter_audit(db, args, limit=None):
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    return 0


# ------------------------------------------------------------------ main


async def _run(settings: Settings, args: argparse.Namespace, out: TextIO) -> int:
    db = Database(settings.database_url)
    try:
        if args.cmd == "migrate":
            if args.status:
                print(f"текущая: {await current_revision(db) or 'нет'}; последняя: {head_revision()}")
                return 0
            await upgrade(db)
            print(f"OK: схема обновлена до {head_revision()}")
            return 0
        if not await _check_schema(db):
            return 3
        if args.cmd == "cleanup":
            print(f"Удалено: {await cleanup(db, settings)}")
            return 0
        if args.cmd == "users":
            return await _users(db, args)
        if args.cmd == "audit":
            return await _audit(db, args, out)
        raise AssertionError(args.cmd)
    finally:
        await db.dispose()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rugw")
    sub = p.add_subparsers(dest="cmd", required=True)

    sv = sub.add_parser("serve", help="запустить шлюз (сначала применяет миграции)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--no-migrate", action="store_true", help="не применять миграции при старте")

    mg = sub.add_parser("migrate", help="обновить схему базы")
    mg.add_argument("--status", action="store_true")

    sub.add_parser("cleanup", help="удалить отслужившие записи")

    us = sub.add_parser("users", help="управление пользователями")
    us_sub = us.add_subparsers(dest="action", required=True)
    us_sub.add_parser("list")
    sr = us_sub.add_parser("set-role")
    sr.add_argument("email")
    sr.add_argument("role")
    for a in ("disable", "enable"):
        us_sub.add_parser(a).add_argument("email")

    au = sub.add_parser("audit", help="журнал аудита")
    au_sub = au.add_subparsers(dest="action", required=True)
    for name in ("list", "export"):
        a = au_sub.add_parser(name)
        a.add_argument("--since", type=parse_since, default=parse_since("24h") if name == "list" else None)
        a.add_argument("--user")
        a.add_argument("--event")
        a.add_argument("--outcome", choices=["ok", "denied", "error"])
        if name == "list":
            a.add_argument("--limit", type=int, default=50)
        else:
            a.add_argument("--format", choices=["jsonl", "csv"], default="jsonl")
            a.add_argument("--output", help="файл; по умолчанию — stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()  # падает с понятной ошибкой, если конфигурация небезопасна

    if args.cmd != "serve":
        if getattr(args, "output", None):
            with open(args.output, "w", encoding="utf-8", newline="") as f:
                return asyncio.run(_run(settings, args, f))
        return asyncio.run(_run(settings, args, sys.stdout))

    if not args.no_migrate:

        async def _migrate() -> None:
            db = Database(settings.database_url)
            try:
                await upgrade(db)
            finally:
                await db.dispose()

        asyncio.run(_migrate())

    import uvicorn

    from rugw.app import build_app

    uvicorn.run(
        build_app(settings),
        host=args.host,
        port=args.port,
        # Адреса строятся из RUGW_PUBLIC_URL; X-Forwarded-For разбирается только
        # для ограничения частоты и только от доверенных прокси (ratelimit.py).
        proxy_headers=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
