from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import threading
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from rugw.app import build_app
from rugw.config import Settings
from rugw.migrate import upgrade
from rugw.policy import Level
from rugw.tools import ToolSpec

BASE = "http://localhost:8000"
REDIRECT = "http://127.0.0.1:33418/callback"
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


# Если задан RUGW_TEST_PG_URL (например postgresql+asyncpg://rugw@127.0.0.1:5432),
# каждый тест получает отдельную чистую базу PostgreSQL; иначе — файл SQLite.
PG_URL = os.environ.get("RUGW_TEST_PG_URL", "").rstrip("/")
_created: set[str] = set()


def _run_sync(coro) -> None:
    """Выполнить корутину в отдельном потоке (тест может уже крутить свой event loop)."""
    err: list[BaseException] = []

    def target() -> None:
        try:
            asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)

    th = threading.Thread(target=target)
    th.start()
    th.join()
    if err:
        raise err[0]


def db_url(tmp_path, name: str = "t") -> str:
    if not PG_URL:
        return f"sqlite+aiosqlite:///{tmp_path}/{name}.db"
    db_name = "t_" + hashlib.sha1(f"{tmp_path}/{name}".encode()).hexdigest()[:20]  # noqa: S324
    if db_name not in _created:
        import asyncpg

        async def create() -> None:
            conn = await asyncpg.connect(PG_URL.replace("+asyncpg", "") + "/postgres")
            try:
                await conn.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
                await conn.execute(f'CREATE DATABASE "{db_name}"')
            finally:
                await conn.close()

        _run_sync(create())
        _created.add(db_name)
    return f"{PG_URL}/{db_name}"


def make_settings(tmp_path, **over) -> Settings:
    env = dict(
        rate_limit_enabled=False,  # лимиты проверяются отдельными тестами
        public_url=BASE,
        dev_mode=True,
        database_url=db_url(tmp_path),
        yandex_client_id="yid",
        yandex_client_secret="ysecret-real",
        allowed_email_domains="company.ru",
        bootstrap_admin_emails="boss@company.ru",
        default_role="readonly",
    )
    env.update(over)
    return Settings(_env_file=None, **env)


class Harness:
    """Гоняет приложение в процессе и подменяет Яндекс через respx."""

    refreshes: list[str] = []  # refresh-токены Яндекса, по которым шлюз обновлял доступ

    def __init__(self, app, client: httpx.AsyncClient, yandex_users: dict[str, dict]):
        self.app = app
        self.c = client
        self.yandex_users = yandex_users  # код Яндекса -> профиль
        self.ycodes: dict[str, str] = {}

    async def register_client(self, name: str = "Test Client") -> str:
        r = await self.c.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT],
                "client_name": name,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert r.status_code == 201, r.text
        return r.json()["client_id"]

    async def start_authorize(self, client_id: str) -> tuple[str, str]:
        """Возвращает (state Яндекса, code_verifier клиента)."""
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        r = await self.c.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "client-state",
                "resource": f"{BASE}/mcp",
            },
        )
        assert r.status_code == 302, r.text
        loc = urlparse(r.headers["location"])
        assert loc.netloc == "oauth.yandex.ru"
        return parse_qs(loc.query)["state"][0], verifier

    async def yandex_return(self, ystate: str, email: str) -> httpx.Response:
        ycode = secrets.token_hex(8)
        self.yandex_users[ycode] = {"id": str(abs(hash(email))), "login": email.split("@")[0], "default_email": email}
        self.ycodes[email] = ycode  # токен Яндекса этого входа: ya-<ycode>
        return await self.c.get("/auth/yandex/callback", params={"state": ystate, "code": ycode})

    async def login(self, email: str, client_id: str | None = None) -> dict:
        """Полный вход: возвращает ответ /token."""
        client_id = client_id or await self.register_client()
        ystate, verifier = await self.start_authorize(client_id)
        page = await self.yandex_return(ystate, email)
        assert page.status_code == 200, page.text
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        r = await self.c.post("/auth/consent", data={"state": ystate, "csrf": csrf, "decision": "allow"})
        assert r.status_code == 302, r.text
        q = parse_qs(urlparse(r.headers["location"]).query)
        assert q["state"] == ["client-state"]
        tok = await self.c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": q["code"][0],
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": f"{BASE}/mcp",
            },
        )
        assert tok.status_code == 200, tok.text
        return {**tok.json(), "client_id": client_id}

    async def rpc(self, token: str | None, method: str, params: dict | None = None, session: str | None = None):
        headers = dict(ACCEPT)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if session:
            headers["Mcp-Session-Id"] = session
        body = {"jsonrpc": "2.0", "id": secrets.randbelow(10**6), "method": method, "params": params or {}}
        return await self.c.post("/mcp", headers=headers, content=json.dumps(body))

    async def mcp(self, token: str, method: str, params: dict | None = None) -> dict:
        """initialize + один вызов. Возвращает result."""
        init = await self.rpc(
            token,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        )
        assert init.status_code == 200, init.text
        sid = init.headers.get("mcp-session-id")
        r = await self.rpc(token, method, params, session=sid)
        assert r.status_code == 200, r.text
        return _parse(r)


def _parse(r: httpx.Response) -> dict:
    text = r.text
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        datas = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = datas[-1]
    msg = json.loads(text)
    assert "error" not in msg, msg
    return msg["result"]


async def echo_write(text: str) -> str:
    """Тестовый инструмент записи."""
    return f"wrote:{text}"


def pytest_collection_modifyitems(items):
    # Все async-тесты гоняем через anyio: его фикстуры живут в той же задаче, что и тест,
    # иначе lifespan MCP SDK (task group) не закрывается корректно.
    import inspect

    for item in items:
        if inspect.iscoroutinefunction(getattr(item, "function", None)):
            item.add_marker(pytest.mark.anyio)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def harness_settings() -> dict:
    """Переопределите в модуле тестов, чтобы включить коннекторы и т.п."""
    return {}


@pytest.fixture
async def harness(tmp_path, harness_settings):
    settings = make_settings(tmp_path, **harness_settings)
    yandex_users: dict[str, dict] = {}
    with respx.mock(assert_all_called=False) as mock:

        def token_route(request: httpx.Request):
            form = parse_qs(request.content.decode())
            assert form["client_secret"] == ["ysecret-real"]
            if form["grant_type"] == ["refresh_token"]:
                old = form["refresh_token"][0]  # yr-<код>[-n]
                code = old.removeprefix("yr-").split("~")[0]
                n = int(old.split("~")[1]) + 1 if "~" in old else 1
                Harness.refreshes.append(old)
                return httpx.Response(
                    200, json={"access_token": f"ya-{code}~{n}", "refresh_token": f"yr-{code}~{n}", "expires_in": 3600}
                )
            code = form["code"][0]
            assert form.get("code_verifier"), "PKCE к Яндексу должен передаваться"
            return httpx.Response(
                200, json={"access_token": f"ya-{code}", "refresh_token": f"yr-{code}", "expires_in": 3600}
            )

        def info_route(request: httpx.Request):
            code = request.headers["Authorization"].removeprefix("OAuth ya-")
            return httpx.Response(200, json=yandex_users[code])

        mock.post("https://oauth.yandex.ru/token").mock(side_effect=token_route)
        mock.get("https://login.yandex.ru/info").mock(side_effect=info_route)

        http = httpx.AsyncClient()
        app = build_app(settings, http=http, extra_tools=[ToolSpec("test_echo_write", Level.WRITE, echo_write, "echo")])
        await upgrade(app.state.db)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=BASE, follow_redirects=False) as c:
                h = Harness(app, c, yandex_users)
                h.mock = mock
                Harness.refreshes = []
                yield h


@pytest.fixture
async def as_admin():
    """Права admin для прямого вызова функций коннекторов (в обход guarded) в юнит-тестах."""
    from rugw.access import Permissions, reset_current, set_current

    token = set_current(Permissions(role="admin", rules=(), user_id=None))
    yield
    reset_current(token)


@pytest.fixture
async def as_user():
    """Фабрика: выставить права произвольного пользователя для прямого вызова коннекторов."""
    from rugw.access import Permissions, _Rule, reset_current, set_current
    from rugw.policy import Level

    tokens = []

    def apply(role: str, *rules: tuple[str, str, str], user_id: int | None = None) -> None:
        perms = Permissions(role=role, rules=tuple(_Rule(c, r, Level(lv)) for c, r, lv in rules), user_id=user_id)
        tokens.append(set_current(perms))

    yield apply
    for t in reversed(tokens):
        reset_current(t)
