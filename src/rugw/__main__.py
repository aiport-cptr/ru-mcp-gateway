"""Точка входа.

  python -m rugw serve [--host 127.0.0.1] [--port 8000]
  python -m rugw users list
  python -m rugw users set-role <email> <admin|member|readonly>
  python -m rugw users disable <email> | enable <email>

Управление пользователями — только из консоли сервера: так у админки нет
сетевой поверхности атаки.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import select

from rugw.config import ROLES, Settings
from rugw.db import Database, Grant, User


async def _users(settings: Settings, args: argparse.Namespace) -> int:
    db = Database(settings.database_url)
    await db.create_all()
    try:
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
    finally:
        await db.dispose()


def main() -> int:
    p = argparse.ArgumentParser(prog="rugw")
    sub = p.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    us = sub.add_parser("users")
    us_sub = us.add_subparsers(dest="action", required=True)
    us_sub.add_parser("list")
    sr = us_sub.add_parser("set-role")
    sr.add_argument("email")
    sr.add_argument("role")
    for a in ("disable", "enable"):
        us_sub.add_parser(a).add_argument("email")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()  # падает с понятной ошибкой, если конфигурация небезопасна

    if args.cmd == "users":
        return asyncio.run(_users(settings, args))

    import uvicorn

    from rugw.app import build_app

    uvicorn.run(
        build_app(settings),
        host=args.host,
        port=args.port,
        # Адреса строятся из RUGW_PUBLIC_URL, заголовкам X-Forwarded-* не доверяем.
        proxy_headers=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
