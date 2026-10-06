"""0.3: Трекер от имени пользователя — хранение токенов Яндекса (docs/design/0.3-access.md, раздел 2)."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError
from sqlalchemy import select, update

from rugw.__main__ import _users, build_parser
from rugw.credentials import TokenCipher, rotate_all
from rugw.db import AuditEvent, User, UserCredential
from tests.conftest import make_settings

pytestmark = pytest.mark.anyio

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()
TRACKER = "https://api.tracker.yandex.net/v3"
USER_MODE = {
    "tracker_auth_mode": "user",
    "tracker_org_id": "42",
    "yandex_extra_scopes": "tracker:read tracker:write",
    "token_encryption_keys": KEY_A,
}


@pytest.fixture
def harness_settings():
    return dict(USER_MODE)


# ------------------------------------------------------------------ конфигурация


@pytest.mark.parametrize(
    "over",
    [
        {"token_encryption_keys": None},  # без ключа — нельзя
        {"yandex_extra_scopes": ""},  # без прав Трекера — нельзя
        {"yandex_extra_scopes": "cloud_api:disk.read"},
        {"tracker_org_id": None},
        {"token_encryption_keys": "not-a-fernet-key"},
        {"token_encryption_keys": f"{KEY_A},broken"},
        {"yandex_extra_scopes": "tracker:read login:email"},  # login:* запрашиваются всегда
        {"yandex_extra_scopes": "tracker:read; DROP"},
    ],
)
def test_user_mode_config_fail_closed(tmp_path, over):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, **{**USER_MODE, **over})


def test_user_mode_config_ok(tmp_path):
    make_settings(tmp_path, **USER_MODE)
    make_settings(tmp_path, **{**USER_MODE, "token_encryption_keys": f"{KEY_B}, {KEY_A}"})


# ------------------------------------------------------------------ вход и хранение


async def test_authorize_requests_extra_scopes(harness):
    cid = await harness.register_client()
    r = await harness.c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "http://127.0.0.1:33418/callback",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "s",
        },
    )
    scope = parse_qs(urlparse(r.headers["location"]).query)["scope"][0].split()
    assert scope == ["login:email", "login:info", "tracker:read", "tracker:write"]


async def _cred(harness, email: str) -> UserCredential | None:
    async with harness.app.state.db.session() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
        return await s.get(UserCredential, (user.id, "yandex"))


async def test_login_stores_tokens_encrypted(harness):
    await harness.login("alice@company.ru")
    ycode = harness.ycodes["alice@company.ru"]
    row = await _cred(harness, "alice@company.ru")
    assert row is not None
    # В базе нет открытого токена — ни access, ни refresh
    for value in (row.access_token_enc, row.refresh_token_enc):
        assert ycode not in value and "ya-" not in value and "yr-" not in value
    cipher = TokenCipher(SecretStr(KEY_A))
    assert cipher.decrypt(row.access_token_enc) == f"ya-{ycode}"
    assert cipher.decrypt(row.refresh_token_enc) == f"yr-{ycode}"
    assert row.scopes == "tracker:read tracker:write"
    assert row.expires_at > time.time()


async def test_tokens_not_stored_without_delegation(tmp_path):
    """В обычном режиме (без ключей и доп. прав) токены Яндекса не сохраняются вовсе."""
    from rugw.app import build_app

    app = build_app(make_settings(tmp_path), http=httpx.AsyncClient())
    assert app.state.credentials is None


# ------------------------------------------------------------------ вызовы Трекера


async def test_tracker_called_with_each_users_own_token(harness):
    seen: list[str] = []

    def issue(request: httpx.Request):
        seen.append(request.headers["Authorization"])
        assert request.headers["X-Org-ID"] == "42"
        return httpx.Response(200, json={"key": "SUP-1"})

    harness.mock.get(f"{TRACKER}/issues/SUP-1").mock(side_effect=issue)
    call = {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    alice = await harness.login("alice@company.ru")
    bob = await harness.login("bob@company.ru")
    assert (await harness.mcp(alice["access_token"], "tools/call", call)).get("isError") is False
    assert (await harness.mcp(bob["access_token"], "tools/call", call)).get("isError") is False
    assert seen == [f"OAuth ya-{harness.ycodes['alice@company.ru']}", f"OAuth ya-{harness.ycodes['bob@company.ru']}"]


async def test_expired_token_is_refreshed_and_resaved(harness):
    seen: list[str] = []
    harness.mock.get(f"{TRACKER}/issues/SUP-1").mock(
        side_effect=lambda r: (seen.append(r.headers["Authorization"]), httpx.Response(200, json={"key": "SUP-1"}))[1]
    )
    tok = await harness.login("alice@company.ru")
    ycode = harness.ycodes["alice@company.ru"]
    async with harness.app.state.db.session() as s:
        await s.execute(update(UserCredential).values(expires_at=time.time() - 10))

    call = {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    assert (await harness.mcp(tok["access_token"], "tools/call", call)).get("isError") is False
    assert harness.refreshes == [f"yr-{ycode}"]
    assert seen == [f"OAuth ya-{ycode}~1"]
    row = await _cred(harness, "alice@company.ru")
    assert TokenCipher(SecretStr(KEY_A)).decrypt(row.refresh_token_enc) == f"yr-{ycode}~1"
    assert row.expires_at > time.time()

    # Следующий вызов — без нового обновления
    await harness.mcp(tok["access_token"], "tools/call", call)
    assert len(harness.refreshes) == 1


async def test_missing_credentials_ask_to_relogin(harness):
    tok = await harness.login("alice@company.ru")
    route = harness.mock.get(f"{TRACKER}/issues/SUP-1").mock(return_value=httpx.Response(200, json={"key": "SUP-1"}))
    async with harness.app.state.db.session() as s:
        await s.execute(UserCredential.__table__.delete())
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    )
    assert res.get("isError") is True
    assert "заново" in str(res)
    assert not route.called


async def test_unreadable_after_key_change_asks_to_relogin(harness):
    tok = await harness.login("alice@company.ru")
    # Подменяем шифр хранилища на другой ключ, как если бы ключ сменили без перешифровки
    harness.app.state.credentials.cipher = TokenCipher(SecretStr(KEY_B))
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    )
    assert res.get("isError") is True and "заново" in str(res)


async def test_narrower_stored_scopes_ask_to_relogin(harness):
    tok = await harness.login("alice@company.ru")
    async with harness.app.state.db.session() as s:
        await s.execute(update(UserCredential).values(scopes="tracker:read"))
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    )
    assert res.get("isError") is True and "заново" in str(res)


async def test_refresh_failure_asks_to_relogin_and_is_audited(harness):
    tok = await harness.login("alice@company.ru")
    async with harness.app.state.db.session() as s:
        await s.execute(update(UserCredential).values(expires_at=time.time() - 10))
    harness.mock.post("https://oauth.yandex.ru/token").mock(return_value=httpx.Response(400, json={"error": "x"}))
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    )
    assert res.get("isError") is True and "заново" in str(res)
    async with harness.app.state.db.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.target == "tracker_get_issue"))).scalars().all()
    assert [e.outcome for e in ev] == ["error"]


async def test_disable_user_deletes_stored_tokens(harness):
    await harness.login("alice@company.ru")
    assert await _cred(harness, "alice@company.ru") is not None
    db = harness.app.state.db
    assert await _users(db, build_parser().parse_args(["users", "disable", "alice@company.ru"])) == 0
    assert await _cred(harness, "alice@company.ru") is None


async def test_rotate_keys(harness):
    await harness.login("alice@company.ru")
    ycode = harness.ycodes["alice@company.ru"]
    db = harness.app.state.db
    # Новый ключ B первым, старый A вторым — перешифровываем
    assert await rotate_all(db, TokenCipher(SecretStr(f"{KEY_B},{KEY_A}"))) == 1
    row = await _cred(harness, "alice@company.ru")
    # Теперь читается одним новым ключом, старым — нет
    assert TokenCipher(SecretStr(KEY_B)).decrypt(row.access_token_enc) == f"ya-{ycode}"
    with pytest.raises(Exception):  # noqa: B017
        TokenCipher(SecretStr(KEY_A)).decrypt(row.access_token_enc)


async def test_yandex_tokens_never_in_audit_or_tool_output(harness):
    harness.mock.get(f"{TRACKER}/issues/SUP-1").mock(return_value=httpx.Response(200, json={"key": "SUP-1"}))
    tok = await harness.login("alice@company.ru")
    ycode = harness.ycodes["alice@company.ru"]
    res = await harness.mcp(
        tok["access_token"], "tools/call", {"name": "tracker_get_issue", "arguments": {"key": "SUP-1"}}
    )
    assert ycode not in str(res)
    async with harness.app.state.db.session() as s:
        details = [e.detail or "" for e in (await s.execute(select(AuditEvent))).scalars()]
    assert all(ycode not in d for d in details)


def test_config_error_output_has_no_secret_values(tmp_path):
    from rugw.__main__ import config_errors

    secret = "SUPER-SECRET-yandex-value-123"
    with pytest.raises(ValidationError) as exc:
        make_settings(tmp_path, yandex_client_secret=secret, tracker_auth_mode="user", tracker_org_id="1")
    text = "\n".join(config_errors(exc.value))
    assert "token_encryption_keys" in text
    assert secret not in text


# ------------------------------------------------------------------ гонки (проверка 0.3, находки 1–2)


async def _expire_and_pause_refresh(harness, monkeypatch, store, access="old-refreshed"):
    """Просрочить токен alice и подменить refresh Яндекса на управляемый. Возвращает (user_id, started, release)."""
    import asyncio

    from rugw.auth.yandex import YandexTokens

    await harness.login("alice@company.ru")
    async with harness.app.state.db.session() as s:
        user = (await s.execute(select(User).where(User.email == "alice@company.ru"))).scalar_one()
        await s.execute(update(UserCredential).values(expires_at=0))
    started, release = asyncio.Event(), asyncio.Event()
    calls: list[str] = []

    async def refresh(token):
        calls.append(token)
        started.set()
        await release.wait()
        return YandexTokens(f"{access}-{len(calls)}", f"{access}-refresh-{len(calls)}", 3600)

    monkeypatch.setattr(store.yandex, "refresh", refresh)
    return user.id, started, release, calls


async def test_refresh_caller_gets_new_login_token_after_conflict(harness, monkeypatch):
    import asyncio

    from rugw.auth.yandex import YandexTokens

    store = harness.app.state.credentials
    user_id, started, release, _ = await _expire_and_pause_refresh(harness, monkeypatch, store)
    task = asyncio.create_task(store.access_token(user_id))
    await started.wait()
    assert await store.save(user_id, YandexTokens("new-login", "new-login-refresh", 3600)) is True
    release.set()
    # Вызов, начавший обновление, получает актуальный токен нового входа, а не устаревший результат.
    assert await task == "new-login"


async def test_refresh_after_delete_raises_and_does_not_recreate(harness, monkeypatch):
    import asyncio

    store = harness.app.state.credentials
    user_id, started, release, _ = await _expire_and_pause_refresh(harness, monkeypatch, store)
    task = asyncio.create_task(store.access_token(user_id))
    await started.wait()
    await store.delete(user_id)
    release.set()
    with pytest.raises(Exception, match="нет сохранённого доступа"):
        await task
    async with harness.app.state.db.session() as s:
        assert await s.get(UserCredential, (user_id, "yandex")) is None


async def test_two_processes_refreshing_keep_single_consistent_chain(harness, monkeypatch):
    """Два экземпляра хранилища (как два процесса) — без общей asyncio-блокировки. Сохраняется ровно одна цепочка."""
    import asyncio

    from rugw.credentials import YandexCredentials

    a = harness.app.state.credentials
    b = YandexCredentials(a.db, a.cipher, a.yandex, a.scopes)  # отдельные блокировки
    user_id, started, release, calls = await _expire_and_pause_refresh(harness, monkeypatch, a)
    t1 = asyncio.create_task(a.access_token(user_id))
    t2 = asyncio.create_task(b.access_token(user_id))
    await started.wait()
    await asyncio.sleep(0.05)
    release.set()
    r1, r2 = await asyncio.gather(t1, t2)
    assert len(calls) == 2  # оба процесса сходили в Яндекс
    assert r1 == r2  # но оба используют один и тот же сохранённый результат
    async with harness.app.state.db.session() as s:
        row = await s.get(UserCredential, (user_id, "yandex"))
    assert a.cipher.decrypt(row.access_token_enc) == r1


async def test_save_refuses_disabled_user(harness):
    from rugw.auth.yandex import YandexTokens

    await harness.login("alice@company.ru")
    db = harness.app.state.db
    await _users(db, build_parser().parse_args(["users", "disable", "alice@company.ru"]))
    async with db.session() as s:
        user_id = (await s.execute(select(User.id).where(User.email == "alice@company.ru"))).scalar_one()
    assert await harness.app.state.credentials.save(user_id, YandexTokens("x", "y", 3600)) is False
    async with db.session() as s:
        assert await s.get(UserCredential, (user_id, "yandex")) is None


async def test_generation_increments(harness):
    await harness.login("alice@company.ru")
    first = await _cred(harness, "alice@company.ru")
    await harness.login("alice@company.ru")
    second = await _cred(harness, "alice@company.ru")
    assert second.generation == first.generation + 1


async def test_pg_login_save_waits_for_concurrent_disable(harness):
    """PostgreSQL: save() ждёт незавершённую транзакцию блокировки (FOR UPDATE) и затем ничего не пишет."""
    import asyncio

    from rugw.auth.yandex import YandexTokens

    db = harness.app.state.db
    if db.engine.dialect.name != "postgresql":
        pytest.skip("блокировки строк проверяются на PostgreSQL")
    await harness.login("alice@company.ru")
    async with db.session() as s:
        user_id = (await s.execute(select(User.id).where(User.email == "alice@company.ru"))).scalar_one()

    async with db.engine.connect() as conn:  # «другой процесс»: CLI users disable, ещё не зафиксирован
        tx = await conn.begin()
        await conn.execute(update(User).where(User.id == user_id).values(disabled=True))
        await conn.execute(UserCredential.__table__.delete().where(UserCredential.user_id == user_id))
        task = asyncio.create_task(harness.app.state.credentials.save(user_id, YandexTokens("late", "late-r", 3600)))
        await asyncio.sleep(0.3)
        assert not task.done(), "save должен ждать блокировку строки пользователя"
        await tx.commit()
    assert await task is False
    async with db.session() as s:
        assert await s.get(UserCredential, (user_id, "yandex")) is None
