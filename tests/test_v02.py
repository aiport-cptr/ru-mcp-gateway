"""Версия 0.2: миграции, очистка, ограничение частоты, аудит из консоли."""

from __future__ import annotations

import io
import json
import time

import httpx
import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from rugw.__main__ import _audit, _users, build_parser
from rugw.app import build_app
from rugw.db import AuditEvent, AuthCode, Base, Database, Grant, PendingLogin, Token, User
from rugw.maintenance import cleanup
from rugw.migrate import current_revision, head_revision, upgrade
from rugw.ratelimit import RateLimitMiddleware, TokenBuckets, client_ip
from tests.conftest import BASE, db_url, make_settings

# ------------------------------------------------------------------ миграции


async def test_migrations_build_schema_matching_models(tmp_path):
    db = Database(db_url(tmp_path, "m"))
    await upgrade(db)
    assert await current_revision(db) == head_revision()

    def diff(conn):
        return compare_metadata(MigrationContext.configure(conn), Base.metadata)

    async with db.engine.connect() as conn:
        assert await conn.run_sync(diff) == [], "модели и миграции разошлись — нужна новая миграция"
    await upgrade(db)  # повторный запуск безопасен
    await db.dispose()


async def test_v01_database_is_adopted(tmp_path):
    """База, созданная версией 0.1 (create_all, без alembic_version), обновляется без потери данных."""
    db = Database(db_url(tmp_path, "old"))
    # Точная схема 0.1 = миграция 0001; убираем отметку Alembic, как было у create_all.
    await upgrade(db, "0001")
    async with db.engine.begin() as conn:
        await conn.execute(sa.text("DROP TABLE alembic_version"))
        await conn.execute(
            sa.text("INSERT INTO users VALUES (1,'y1','old','old@company.ru','admin',false,0,0)"),
        )
    assert await current_revision(db) is None
    await upgrade(db)
    assert await current_revision(db) == head_revision()
    async with db.session() as s:
        assert (await s.get(User, 1)).email == "old@company.ru"
    await db.dispose()


async def test_app_refuses_unmigrated_database(tmp_path):
    app = build_app(make_settings(tmp_path), http=httpx.AsyncClient())
    with pytest.raises(RuntimeError, match="migrate"):
        async with app.router.lifespan_context(app):
            pass


# ------------------------------------------------------------------ очистка


async def _seed(db: Database, now: float) -> None:
    async with db.session() as s:
        s.add(User(id=1, yandex_id="y", login="a", email="a@company.ru", role="member"))
        await s.flush()
        s.add_all(
            [
                PendingLogin(state_hash="p-old", client_id="c", params_json={}, expires_at=now - 1),
                PendingLogin(state_hash="p-new", client_id="c", params_json={}, expires_at=now + 100),
                AuthCode(code_hash="c-old", client_id="c", user_id=1, params_json={}, expires_at=now - 1),
                Grant(id=1, client_id="c", user_id=1, scopes=[]),  # останется пустым → удалить
                Grant(id=2, client_id="c", user_id=1, scopes=[]),  # с живым refresh → оставить
                AuditEvent(ts=now - 400 * 86400, event="tool_call", outcome="ok"),
                AuditEvent(ts=now - 10, event="tool_call", outcome="ok"),
            ]
        )
        await s.flush()
        s.add_all(
            [
                Token(token_hash="t1", kind="access", grant_id=1, expires_at=now - 1),
                Token(token_hash="t2", kind="refresh", grant_id=2, expires_at=now + 100, used=True),
                Token(token_hash="t3", kind="access", grant_id=2, expires_at=0),
            ]
        )


async def test_cleanup_removes_only_dead_records(tmp_path):
    settings = make_settings(tmp_path, audit_retention_days=365)
    db = Database(settings.database_url)
    await upgrade(db)
    now = time.time()
    await _seed(db, now)
    report = await cleanup(db, settings, now=now)
    assert (report.pending_logins, report.auth_codes, report.tokens, report.grants, report.audit_events) == (
        1,
        1,
        2,
        1,
        1,
    )
    async with db.session() as s:
        assert await s.get(PendingLogin, "p-new") is not None
        assert await s.get(Grant, 2) is not None
        # использованный, но не истёкший refresh остаётся: по нему ловится повторное использование
        assert await s.get(Token, "t2") is not None
        assert await s.get(User, 1) is not None
    await db.dispose()


async def test_cleanup_keeps_audit_when_retention_zero(tmp_path):
    settings = make_settings(tmp_path, audit_retention_days=0)
    db = Database(settings.database_url)
    await upgrade(db)
    await _seed(db, time.time())
    assert (await cleanup(db, settings)).audit_events == 0
    await db.dispose()


async def test_refresh_reuse_still_detected_after_cleanup(harness):
    tok = await harness.login("alice@company.ru")
    form = {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": tok["client_id"]}
    new = (await harness.c.post("/token", data=form)).json()
    await cleanup(harness.app.state.db, harness.app.state.settings)
    assert (await harness.c.post("/token", data=form)).status_code == 400
    assert (await harness.rpc(new["access_token"], "tools/list")).status_code == 401


# ------------------------------------------------------------------ ограничение частоты


def test_token_bucket_refills():
    t = [0.0]
    b = TokenBuckets(per_minute=2, clock=lambda: t[0])
    assert b.take("k") == 0 and b.take("k") == 0
    wait = b.take("k")
    assert wait == pytest.approx(30, rel=0.01)
    assert b.take("other") == 0  # ключи независимы
    t[0] = 30.0
    assert b.take("k") == 0


def _scope(peer: str, xff: str | None = None) -> dict:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return {"type": "http", "client": (peer, 1), "headers": headers}


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.5", None, "203.0.113.5"),  # прямое соединение
        ("203.0.113.5", "1.2.3.4", "203.0.113.5"),  # недоверенный не может подставить XFF
        ("172.17.0.1", "198.51.100.7", "198.51.100.7"),  # Caddy на хосте → контейнер
        ("172.17.0.1", "1.1.1.1, 198.51.100.7", "198.51.100.7"),  # левую часть подделал клиент
        ("127.0.0.1", "garbage", "127.0.0.1"),
        ("127.0.0.1", None, "127.0.0.1"),
    ],
)
def test_client_ip(tmp_path, peer, xff, expected):
    trusted = make_settings(tmp_path).trusted_proxies
    assert client_ip(_scope(peer, xff), trusted) == expected


async def _call(app, path: str, peer: str = "203.0.113.5", headers: dict | None = None) -> int:
    transport = httpx.ASGITransport(app=app, client=(peer, 1234))
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
        return (await c.post(path, headers=headers or {})).status_code


async def _ok(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def test_rate_limit_register_per_ip(tmp_path):
    mw = RateLimitMiddleware(_ok, make_settings(tmp_path, rate_register_per_minute=3))
    codes = [await _call(mw, "/register") for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert await _call(mw, "/register", peer="203.0.113.99") == 200  # другой IP не задет
    assert await _call(mw, "/healthz") == 200  # прочие пути не ограничиваются


async def test_rate_limit_mcp_random_tokens_hit_ip_layer(tmp_path):
    """Перебор случайных токенов с одного IP упирается в общий лимит по IP."""
    mw = RateLimitMiddleware(_ok, make_settings(tmp_path, rate_mcp_per_minute=2))
    codes = [await _call(mw, "/mcp", headers={"Authorization": f"Bearer rnd{i}"}) for i in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


async def test_rate_limit_mcp_per_token(tmp_path):
    mw = RateLimitMiddleware(_ok, make_settings(tmp_path, rate_mcp_per_minute=2))
    h = {"Authorization": "Bearer same"}
    assert [await _call(mw, "/mcp", headers=h) for _ in range(3)] == [200, 200, 429]


async def test_rate_limit_response_format(tmp_path):
    mw = RateLimitMiddleware(_ok, make_settings(tmp_path, rate_auth_per_minute=1))
    transport = httpx.ASGITransport(app=mw, client=("203.0.113.5", 1))
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
        await c.post("/token")
        r = await c.post("/token")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1
    assert r.json()["error"] == "rate_limited"


async def test_rate_limit_enabled_in_app(tmp_path):
    settings = make_settings(tmp_path, rate_limit_enabled=True, rate_register_per_minute=1)
    app = build_app(settings, http=httpx.AsyncClient())
    await upgrade(app.state.db)
    async with app.router.lifespan_context(app):
        assert await _call(app, "/register") != 429
        assert await _call(app, "/register") == 429


# ------------------------------------------------------------------ консоль: аудит и пользователи


async def test_cli_audit_list_and_export(harness):
    tok = await harness.login("alice@company.ru")
    await harness.mcp(tok["access_token"], "tools/call", {"name": "test_echo_write", "arguments": {"text": "x"}})
    db = harness.app.state.db
    p = build_parser()

    out = io.StringIO()
    await _audit(db, p.parse_args(["audit", "list", "--outcome", "denied"]), out)
    assert "test_echo_write" in out.getvalue() and "alice@company.ru" in out.getvalue()

    out = io.StringIO()
    await _audit(db, p.parse_args(["audit", "export", "--user", "alice@company.ru"]), out)
    rows = [json.loads(line) for line in out.getvalue().splitlines()]
    assert {r["event"] for r in rows} >= {"login_ok", "consent_granted", "tool_call"}
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)

    out = io.StringIO()
    await _audit(db, p.parse_args(["audit", "export", "--format", "csv", "--event", "tool_call"]), out)
    lines = out.getvalue().splitlines()
    assert lines[0].startswith("id,time,user") and len(lines) == 2


async def test_cli_disable_revokes_tokens(harness):
    tok = await harness.login("alice@company.ru")
    db = harness.app.state.db
    assert await _users(db, build_parser().parse_args(["users", "disable", "alice@company.ru"])) == 0
    await _users(db, build_parser().parse_args(["users", "enable", "alice@company.ru"]))
    # Даже после разблокировки старый грант отозван — нужен новый вход.
    assert (await harness.rpc(tok["access_token"], "tools/list")).status_code == 401


def test_since_parsing():
    from rugw.__main__ import parse_since

    assert time.time() - parse_since("2h") == pytest.approx(7200, abs=5)
    assert parse_since("2026-10-01") > 0
    with pytest.raises(Exception, match="since"):
        parse_since("вчера")
