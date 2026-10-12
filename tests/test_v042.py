"""0.4.2: исправления по проверке 0.4.1 — неповторяющиеся версии токенов, кэш Диадока, даты Диадока."""

import httpx
import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from rugw.connectors import diadoc
from rugw.credentials import TokenCipher
from rugw.db import Database, ServiceCredential, User, UserCredential
from rugw.errors import ErrorCode
from rugw.migrate import upgrade
from rugw.service_credentials import ServiceSecrets
from rugw.tools import ConnectorError
from tests.conftest import db_url
from tests.test_v041 import KEY, _diadoc, diadoc_settings

pytestmark = pytest.mark.anyio


async def test_migration_0008_gives_existing_rows_distinct_versions(tmp_path):
    db = Database(db_url(tmp_path, "m8"))
    await upgrade(db, "0007")
    async with db.engine.begin() as conn:
        await conn.execute(sa.text("INSERT INTO users VALUES (1,'y1','a','a@company.ru','member',false,0,0)"))
        await conn.execute(
            sa.text(
                "INSERT INTO user_credentials (user_id, provider, access_token_enc, scopes, generation, updated_at)"
                " VALUES (1, 'yandex', 'x', '', 1, 0)"
            )
        )
        await conn.execute(
            sa.text(
                "INSERT INTO service_credentials (provider, secret_enc, generation, updated_at)"
                " VALUES ('diadoc', 'x', 1, 0), ('other', 'y', 1, 0)"
            )
        )
    await upgrade(db)
    async with db.session() as s:
        user_v = (await s.get(UserCredential, (1, "yandex"))).version
        service_v = [r.version for r in (await s.execute(sa.select(ServiceCredential))).scalars()]
        assert (await s.get(User, 1)).email == "a@company.ru"
    versions = [user_v, *service_v]
    assert all(len(v) == 32 for v in versions) and len(set(versions)) == 3
    await db.dispose()


async def test_service_versions_never_repeat(tmp_path):
    db = Database(db_url(tmp_path, "sv"))
    await upgrade(db)
    store = ServiceSecrets(db, TokenCipher(SecretStr(KEY)))
    seen = {await store.put("diadoc", "a")}
    _, v = await store.get("diadoc")
    seen.add(await store.cas("diadoc", v, "b"))
    for _ in range(3):
        await store.delete("diadoc")
        seen.add(await store.put("diadoc", "c"))
    assert len(seen) == 5 and None not in seen
    async with db.session() as s:  # запись без версии (вставлена в обход хранилища)
        await s.execute(sa.update(ServiceCredential).values(version=""))
    assert await store.cas("diadoc", "", "x") is None  # пустая версия никогда не совпадает
    assert (await store.get("diadoc"))[0] == "c"
    await db.dispose()


def _token_reply(access: str, refresh: str | None = None) -> dict:
    out = {"access_token": access, "expires_in": 3600}
    if refresh:
        out["refresh_token"] = refresh
    return out


async def test_diadoc_relogin_in_other_process_drops_cached_access(tmp_path, monkeypatch):
    """`rugw diadoc login` в отдельном процессе: работающий сервер берёт access по новому входу."""
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "rt-old")
            tokens = diadoc.DiadocTokens(diadoc_settings(tmp_path), http, store)
            used = []

            async def reply(form):
                used.append(form["refresh_token"])
                return _token_reply(f"at-{form['refresh_token']}")  # новый refresh не выдаётся

            monkeypatch.setattr(tokens, "_token_request", reply)
            assert await tokens.access_token() == "at-rt-old"
            assert await tokens.access_token() == "at-rt-old"  # кэш, пока запись та же
            await store.put("diadoc", "rt-new")  # повторный вход администратора
            assert await tokens.access_token() == "at-rt-new"
            assert used == ["rt-old", "rt-new"]
        finally:
            await db.dispose()


async def test_diadoc_discards_reply_without_rotation_if_login_replaced(tmp_path, monkeypatch):
    """Контур не выдал новый refresh, но вход заменили во время обмена — ответ отброшен."""
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "rt-old")
            tokens = diadoc.DiadocTokens(diadoc_settings(tmp_path), http, store)

            async def reply(form):
                if form["refresh_token"] == "rt-old":
                    await store.put("diadoc", "rt-new")  # вход заменили, пока ждали ответ
                return _token_reply(f"at-{form['refresh_token']}")

            monkeypatch.setattr(tokens, "_token_request", reply)
            assert await tokens.access_token() == "at-rt-new"
        finally:
            await db.dispose()


async def test_diadoc_gives_up_when_login_keeps_changing(tmp_path, monkeypatch):
    async with httpx.AsyncClient() as http:
        db, store, _ = await _diadoc(tmp_path, http)
        try:
            await store.put("diadoc", "rt-0")
            tokens = diadoc.DiadocTokens(diadoc_settings(tmp_path), http, store)
            n = {"i": 0}

            async def reply(form):
                n["i"] += 1
                await store.put("diadoc", f"rt-{n['i']}")
                return _token_reply("at", "rotated")

            monkeypatch.setattr(tokens, "_token_request", reply)
            with pytest.raises(ConnectorError) as e:
                await tokens.access_token()
            assert e.value.code == ErrorCode.RELOGIN_REQUIRED
            assert n["i"] == diadoc.DiadocTokens.ATTEMPTS
            assert (await store.get("diadoc"))[0] == f"rt-{n['i']}"  # чужой вход не перезаписан
        finally:
            await db.dispose()


@pytest.mark.parametrize(
    ("value", "expected"), [("2026-10-01", "01.10.2026"), (" 2024-02-29 ", "29.02.2024"), ("2026-12-31", "31.12.2026")]
)
def test_diadoc_date_format(value, expected):
    assert diadoc.to_diadoc_date(value) == expected


@pytest.mark.parametrize("bad", ["01.10.2026", "2026-02-30", "2026-13-01", "", "сегодня"])
def test_diadoc_date_rejects(bad):
    with pytest.raises(ConnectorError):
        diadoc.to_diadoc_date(bad)


async def test_check_command_reports_without_secrets(tmp_path):
    import io

    from rugw.__main__ import _check
    from tests.conftest import make_settings

    settings = make_settings(tmp_path, moysklad_token="synthetic-moysklad-token")
    db = Database(settings.database_url)
    out = io.StringIO()
    assert await _check(db, settings, out) == 0
    text = out.getvalue()
    assert "пустая → " in text  # схема ещё не создана — обновится при запуске
    assert "moysklad" in text and "synthetic-moysklad-token" not in text
    await upgrade(db)
    out = io.StringIO()
    assert await _check(db, settings, out) == 0
    assert "схема актуальна" in out.getvalue()
    await db.dispose()


async def test_check_command_hides_database_error_details(tmp_path):
    import io

    from rugw.__main__ import _check
    from tests.conftest import make_settings

    settings = make_settings(tmp_path)
    db = Database("postgresql+asyncpg://rugw:synthetic-db-password@127.0.0.1:1/rugw")
    out = io.StringIO()
    assert await _check(db, settings, out) == 1
    assert "база недоступна" in out.getvalue() and "synthetic-db-password" not in out.getvalue()
    await db.dispose()
