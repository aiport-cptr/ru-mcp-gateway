"""0.4.1: группы, служебные токены, Диадок, СБИС, Яндекс 360 (Диск, Почта)."""

from __future__ import annotations

import imaplib
import io
import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError
from sqlalchemy import delete

from rugw.__main__ import _groups, build_parser
from rugw.access import AccessDenied, load_permissions
from rugw.connectors import diadoc, sbis, yandex360
from rugw.credentials import CredentialsUnavailable, TokenCipher, rotate_all
from rugw.db import Database, ResourceGrant, ServiceCredential
from rugw.errors import ErrorCode
from rugw.migrate import upgrade
from rugw.policy import Level
from rugw.service_credentials import ServiceSecrets
from rugw.tools import ConnectorError
from tests.conftest import db_url, make_settings

pytestmark = pytest.mark.anyio

KEY = Fernet.generate_key().decode()
IDENT = "https://identity.kontur.ru"
DD = "https://diadoc-api.kontur.ru"
SBIS_AUTH = "https://online.sbis.ru/auth/service/"
SBIS_SRV = "https://online.sbis.ru/service/?srv=1"
DISK = "https://cloud-api.yandex.net/v1/disk"


async def fresh_db(tmp_path, name="x") -> Database:
    db = Database(db_url(tmp_path, name))
    await upgrade(db)
    return db


# ================================================================== группы


async def test_group_grants_apply_to_members(tmp_path):
    db = await fresh_db(tmp_path)
    p = build_parser()
    async with db.session() as s:
        await s.execute(delete(ResourceGrant))
        s.add(ResourceGrant(subject="group:sales", connector="amocrm", resource="lead:*", level="write"))
    assert await _groups(db, p.parse_args(["groups", "add", "Sales", "Ivan@Company.RU"]), io.StringIO()) == 0
    ivan = await load_permissions(db, "ivan@company.ru", "member")
    olga = await load_permissions(db, "olga@company.ru", "member")
    assert ivan.allows("amocrm", "lead:5", Level.WRITE)
    assert not olga.allows("amocrm", "lead:5", Level.READ)
    # потолок роли действует и для групп
    assert not (await load_permissions(db, "ivan@company.ru", "readonly")).allows("amocrm", "lead:5", Level.WRITE)
    out = io.StringIO()
    await _groups(db, p.parse_args(["groups", "list"]), out)
    assert out.getvalue().strip() == "sales\tivan@company.ru"
    assert await _groups(db, p.parse_args(["groups", "remove", "sales", "ivan@company.ru"]), io.StringIO()) == 0
    assert not (await load_permissions(db, "ivan@company.ru", "member")).allows("amocrm", "lead:5", Level.READ)
    assert await _groups(db, p.parse_args(["groups", "add", "bad name", "x@y.ru"]), io.StringIO()) == 2
    assert await _groups(db, p.parse_args(["groups", "add", "ok", "not-an-email"]), io.StringIO()) == 2
    await db.dispose()


# ================================================================== настройки


@pytest.mark.parametrize(
    "over",
    [
        {"yandex360_services": "disk"},  # нет ключей и прав
        {"yandex360_services": "disk", "token_encryption_keys": KEY},  # нет cloud_api:disk.read
        {"yandex360_services": "calendar", "token_encryption_keys": KEY, "yandex_extra_scopes": "calendar:all"},
        {"diadoc_client_id": "app"},  # без секрета
        {"diadoc_client_id": "app", "diadoc_client_secret": "s"},  # без ключей шифрования
        {
            "diadoc_client_id": "app",
            "diadoc_client_secret": "s",
            "token_encryption_keys": KEY,
            "diadoc_scope": "openid",
        },
        {"sbis_login": "robot"},  # без пароля
    ],
)
def test_new_configs_fail_closed(tmp_path, over):
    with pytest.raises(ValidationError):
        make_settings(tmp_path, **over)


def test_new_configs_ok(tmp_path):
    make_settings(
        tmp_path,
        yandex360_services="disk, mail",
        token_encryption_keys=KEY,
        yandex_extra_scopes="cloud_api:disk.read mail:imap_ro",
        diadoc_client_id="app",
        diadoc_client_secret="s",
        sbis_login="robot",
        sbis_password="p",
    )


# ================================================================== служебные токены


async def test_service_secrets_encrypted_cas_and_rotation(tmp_path):
    db = await fresh_db(tmp_path)
    store = ServiceSecrets(db, TokenCipher(SecretStr(KEY)))
    await store.put("diadoc", "refresh-1")
    async with db.session() as s:
        row = await s.get(ServiceCredential, "diadoc")
    assert "refresh-1" not in row.secret_enc
    value, gen = await store.get("diadoc")
    assert value == "refresh-1"
    assert await store.cas("diadoc", gen, "refresh-2") is True
    assert await store.cas("diadoc", gen, "refresh-stale") is False  # устаревшее поколение
    assert (await store.get("diadoc"))[0] == "refresh-2"
    new_key = Fernet.generate_key().decode()
    assert await rotate_all(db, TokenCipher(SecretStr(f"{new_key},{KEY}"))) == 1
    assert (await ServiceSecrets(db, TokenCipher(SecretStr(new_key))).get("diadoc"))[0] == "refresh-2"
    await db.dispose()


# ================================================================== Диадок


def diadoc_settings(tmp_path):
    return make_settings(tmp_path, diadoc_client_id="app", diadoc_client_secret="dd-secret", token_encryption_keys=KEY)


async def _diadoc(tmp_path, http):
    db = await fresh_db(tmp_path, "dd")
    store = ServiceSecrets(db, TokenCipher(SecretStr(KEY)))
    tools = {t.name: t for t in diadoc.build(diadoc_settings(tmp_path), http, None, store)}
    return db, store, tools


async def test_diadoc_refresh_rotation_cache_and_box_filter(tmp_path, as_user):
    as_user("member", ("diadoc", "box-1@diadoc.ru", "read"))
    async with httpx.AsyncClient() as http:
        db, store, t = await _diadoc(tmp_path, http)
        await store.put("diadoc", "rt-1")
        with respx.mock(assert_all_called=False) as m:
            tok = m.post(f"{IDENT}/connect/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "at-1", "refresh_token": "rt-2", "expires_in": 3600}
                )
            )
            orgs = {
                "Organizations": [
                    {
                        "FullName": "ООО Ромашка",
                        "Inn": "7700000000",
                        "Boxes": [{"BoxId": "box-1@diadoc.ru", "Title": "А"}],
                    },
                    {
                        "FullName": "ООО Чужая",
                        "Inn": "7711111111",
                        "Boxes": [{"BoxId": "box-2@diadoc.ru", "Title": "Б"}],
                    },
                ]
            }
            gm = m.get(f"{DD}/GetMyOrganizations").mock(return_value=httpx.Response(200, json=orgs))
            out = json.loads(await t["diadoc_boxes"].fn())
            await t["diadoc_boxes"].fn()
        assert [o["FullName"] for o in out] == ["ООО Ромашка"]
        assert tok.call_count == 1  # access-токен закэширован
        form = parse_qs(tok.calls[0].request.content.decode())
        assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == ["rt-1"]
        assert gm.calls[0].request.url.params["autoRegister"] == "false"
        assert gm.calls[0].request.headers["Authorization"] == "Bearer at-1"
        assert (await store.get("diadoc"))[0] == "rt-2"  # refresh повёрнут и сохранён
        await db.dispose()


async def test_diadoc_documents_body_and_box_grant(tmp_path, as_user):
    as_user("member", ("diadoc", "box-1@diadoc.ru", "read"))
    async with httpx.AsyncClient() as http:
        db, store, t = await _diadoc(tmp_path, http)
        await store.put("diadoc", "rt-1")
        with respx.mock(assert_all_called=False) as m:
            m.post(f"{IDENT}/connect/token").mock(
                return_value=httpx.Response(200, json={"access_token": "at", "expires_in": 3600})
            )
            docs = m.post(f"{DD}/V4/GetDocuments").mock(
                return_value=httpx.Response(
                    200, json={"Documents": [{"Title": "УПД", "Content": "x" * 99}], "TotalCount": 1}
                )
            )
            out = json.loads(
                await t["diadoc_documents"].fn(box_id="box-1@diadoc.ru", from_date="2026-10-01", count=500)
            )
            assert out["Documents"] == [{"Title": "УПД"}]
            req = docs.calls[0].request
            assert req.url.params["boxId"] == "box-1@diadoc.ru"
            assert json.loads(req.content) == {
                "DocumentCategory": "Incoming",
                "Count": 100,
                "FromDocumentDate": "2026-10-01",
            }
            with pytest.raises(AccessDenied):
                await t["diadoc_documents"].fn(box_id="box-2@diadoc.ru")
            assert docs.call_count == 1
            for bad in ({"box_id": "../x"}, {"box_id": "box-1@diadoc.ru", "from_date": "01.10.2026"}):
                with pytest.raises(ConnectorError):
                    await t["diadoc_documents"].fn(**bad)
        await db.dispose()


async def test_diadoc_relogin_required(tmp_path, as_admin):
    async with httpx.AsyncClient() as http:
        db, store, t = await _diadoc(tmp_path, http)
        with pytest.raises(ConnectorError) as e:  # вход не выполнялся
            await t["diadoc_boxes"].fn()
        assert e.value.code == ErrorCode.RELOGIN_REQUIRED and "diadoc login" in str(e.value)
        await store.put("diadoc", "rt-old")
        with respx.mock:
            respx.post(f"{IDENT}/connect/token").mock(return_value=httpx.Response(400, json={"error": "invalid_grant"}))
            with pytest.raises(ConnectorError) as e:
                await t["diadoc_boxes"].fn()
        assert e.value.code == ErrorCode.RELOGIN_REQUIRED
        await db.dispose()


async def test_diadoc_concurrent_rotation_retries_with_new_token(tmp_path, as_admin):
    """Другой процесс обменял refresh раньше нас: наш старый отвергнут, но поколение сменилось — повторяем."""
    async with httpx.AsyncClient() as http:
        db, store, t = await _diadoc(tmp_path, http)
        await store.put("diadoc", "rt-old")
        seen = []

        def token(request):
            rt = parse_qs(request.content.decode())["refresh_token"][0]
            seen.append(rt)
            if rt == "rt-old":
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt-3", "expires_in": 3600})

        orig_get = store.get
        calls = {"n": 0}

        async def get_and_race(provider):
            calls["n"] += 1
            if calls["n"] == 2:  # между нашим чтением и отказом другой процесс сохранил новый refresh
                await store.put("diadoc", "rt-new")
            return await orig_get(provider)

        store.get = get_and_race
        with respx.mock:
            respx.post(f"{IDENT}/connect/token").mock(side_effect=token)
            respx.get(f"{DD}/GetMyOrganizations").mock(return_value=httpx.Response(200, json={"Organizations": []}))
            await t["diadoc_boxes"].fn()
        assert seen == ["rt-old", "rt-new"]
        store.get = orig_get
        assert (await store.get("diadoc"))[0] == "rt-3"
        await db.dispose()


async def test_diadoc_device_login(tmp_path, monkeypatch):
    monkeypatch.setattr(diadoc.asyncio, "sleep", _no_sleep)
    async with httpx.AsyncClient() as http:
        db = await fresh_db(tmp_path, "dl")
        store = ServiceSecrets(db, TokenCipher(SecretStr(KEY)))
        tokens = diadoc.DiadocTokens(diadoc_settings(tmp_path), http, store)
        replies = iter(
            [
                httpx.Response(400, json={"error": "authorization_pending"}),
                httpx.Response(200, json={"access_token": "at", "refresh_token": "rt-device"}),
            ]
        )
        shown = []
        with respx.mock:
            dev = respx.post(f"{IDENT}/connect/deviceauthorization").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "device_code": "dc",
                        "user_code": "ABCD",
                        "verification_uri_complete": "https://id/x",
                        "interval": 1,
                        "expires_in": 60,
                    },
                )
            )
            respx.post(f"{IDENT}/connect/token").mock(side_effect=lambda r: next(replies))
            await tokens.device_login(lambda url, code: shown.append((url, code)))
        assert shown == [("https://id/x", "ABCD")]
        assert "offline_access" in parse_qs(dev.calls[0].request.content.decode())["scope"][0]
        assert (await store.get("diadoc"))[0] == "rt-device"
        await db.dispose()


async def _no_sleep(_):
    return None


# ================================================================== СБИС


def _sbis(tmp_path, http):
    s = make_settings(tmp_path, sbis_login="robot", sbis_password="SBIS-PASS")
    return {t.name: t for t in sbis.build(s, http)}


async def test_sbis_login_session_relogin_and_slim(tmp_path, as_user):
    as_user("member", ("sbis", "ДокОтгрВх", "read"))
    sids = iter(["sid-1", "sid-2"])
    async with httpx.AsyncClient() as http:
        t = _sbis(tmp_path, http)
        with respx.mock(assert_all_called=False) as m:
            auth = m.post(SBIS_AUTH).mock(side_effect=lambda r: httpx.Response(200, json={"result": next(sids)}))
            calls = []

            bodies = []

            def srv(request):
                calls.append(request.headers["X-SBISSessionID"])
                bodies.append(json.loads(request.content))
                if len(calls) == 1:
                    return httpx.Response(401)  # сессия истекла
                return httpx.Response(
                    200,
                    json={
                        "result": {
                            "Документ": [
                                {
                                    "Идентификатор": "d1",
                                    "Номер": "15",
                                    "Дата": "01.10.2026",
                                    "Состояние": {"Код": "7", "Название": "Выполнение завершено"},
                                    "Контрагент": {"СвЮЛ": {"Название": "ООО Поставщик"}},
                                    "Вложение": [{"Файл": {"Ссылка": "https://online.sbis.ru/secret-signed-link"}}],
                                }
                            ],
                            "Навигация": {"ЕстьЕще": "Нет"},
                        }
                    },
                )

            m.post(SBIS_SRV).mock(side_effect=srv)
            out = json.loads(await t["sbis_documents"].fn(doc_type="ДокОтгрВх", date_from="2026-10-01", page_size=500))
        assert calls == ["sid-1", "sid-2"] and auth.call_count == 2
        body = bodies[-1]
        assert body["method"] == "СБИС.СписокДокументов"
        assert body["params"]["Фильтр"] == {"Тип": "ДокОтгрВх", "ДатаС": "01.10.2026"}
        assert body["params"]["Навигация"]["РазмерСтраницы"] == "200"
        doc = out["Документы"][0]
        assert doc["Контрагент"] == "ООО Поставщик" and doc["Состояние"] == "Выполнение завершено"
        assert "secret-signed-link" not in json.dumps(out, ensure_ascii=False)
        login = json.loads(auth.calls[0].request.content)
        assert login["method"] == "СБИС.Аутентифицировать" and login["params"]["Параметр"]["Логин"] == "robot"


async def test_sbis_errors_and_grants(tmp_path, as_user):
    as_user("member", ("sbis", "ДокОтгрВх", "read"))
    async with httpx.AsyncClient() as http:
        t = _sbis(tmp_path, http)
        with respx.mock(assert_all_called=False) as m:
            m.post(SBIS_AUTH).mock(return_value=httpx.Response(200, json={"result": "sid"}))
            srv = m.post(SBIS_SRV).mock(
                return_value=httpx.Response(200, json={"error": {"code": -32000, "message": "SBIS-PASS утёк"}})
            )
            with pytest.raises(ConnectorError) as e:
                await t["sbis_documents"].fn(doc_type="ДокОтгрВх")
            assert e.value.code == ErrorCode.UPSTREAM_ERROR and "утёк" not in str(e.value)
            with pytest.raises(AccessDenied):
                await t["sbis_documents"].fn(doc_type="ДокОтгрИсх")
            assert srv.call_count == 1
            with pytest.raises(ConnectorError, match="Дата"):
                await t["sbis_documents"].fn(doc_type="ДокОтгрВх", date_from="01.10.2026")
        with respx.mock:
            respx.post(SBIS_AUTH).mock(return_value=httpx.Response(200, json={"error": {"code": 1}}))
            with pytest.raises(ConnectorError) as e:
                await _sbis(tmp_path, http)["sbis_documents"].fn(doc_type="ДокОтгрВх")
        assert e.value.code == ErrorCode.UPSTREAM_AUTH and "SBIS-PASS" not in str(e.value)


# ================================================================== Яндекс 360


class FakeCreds:
    def __init__(self, token="ya-user-token", fail=False):  # noqa: S107 — тестовое значение
        self.token, self.fail, self.users = token, fail, []

    async def access_token(self, user_id):
        self.users.append(user_id)
        if self.fail:
            raise CredentialsUnavailable("доступ выдан с меньшим набором прав")
        return self.token


def y360(tmp_path, http, services="disk,mail", creds=None, imap=None):
    s = make_settings(
        tmp_path,
        yandex360_services=services,
        token_encryption_keys=KEY,
        yandex_extra_scopes="cloud_api:disk.read mail:imap_ro",
    )
    kw = {"imap_factory": imap} if imap else {}
    return {t.name: t for t in yandex360.build(s, http, creds or FakeCreds(), None, **kw)}


async def test_disk_list_uses_users_token_and_paths(tmp_path, as_user):
    as_user("member", ("yandex360", "disk", "read"), user_id=7, email="ann@company.ru")
    creds = FakeCreds()
    async with httpx.AsyncClient() as http:
        t = y360(tmp_path, http, creds=creds)
        with respx.mock:
            r = respx.get(f"{DISK}/resources").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "_embedded": {
                            "total": 1,
                            "items": [
                                {
                                    "name": "a.txt",
                                    "path": "disk:/Док/a.txt",
                                    "type": "file",
                                    "file": "https://downloader.disk.yandex.ru/secret",
                                }
                            ],
                        }
                    },
                )
            )
            out = json.loads(await t["disk_list"].fn(path="Док"))
        assert r.calls[0].request.headers["Authorization"] == "OAuth ya-user-token"
        assert r.calls[0].request.url.params["path"] == "disk:/Док"
        assert creds.users == [7]
        assert "secret" not in json.dumps(out)  # подписанные ссылки не отдаются
        for bad in ("/a/../b", "/a\\b", "/x\x00"):
            with pytest.raises(ConnectorError):
                yandex360.disk_path(bad)


async def test_disk_needs_grant_and_relogin(tmp_path, as_user):
    as_user("member", ("yandex360", "mail", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        with pytest.raises(AccessDenied):
            await y360(tmp_path, http)["disk_list"].fn()
    as_user("member", ("yandex360", "disk", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        with pytest.raises(ConnectorError) as e:
            await y360(tmp_path, http, creds=FakeCreds(fail=True))["disk_list"].fn()
    assert e.value.code == ErrorCode.RELOGIN_REQUIRED


async def test_disk_read_text_safe_download(tmp_path, as_user):
    as_user("member", ("yandex360", "disk", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        t = y360(tmp_path, http)
        with respx.mock(assert_all_called=False) as m:
            m.get(f"{DISK}/resources/download").mock(
                return_value=httpx.Response(200, json={"href": "https://downloader.disk.yandex.ru/d/abc"})
            )
            dl = m.get("https://downloader.disk.yandex.ru/d/abc").mock(return_value=httpx.Response(200, text="привет"))
            out = json.loads(await t["disk_read_text"].fn(path="/notes.md"))
            assert out["text"] == "привет"
            assert "Authorization" not in dl.calls[0].request.headers  # токен сотрудника на ссылку не уходит

            m.get(f"{DISK}/resources/download").mock(
                return_value=httpx.Response(200, json={"href": "https://evil.ru/x"})
            )
            with pytest.raises(ConnectorError, match="неожиданная ссылка"):
                await t["disk_read_text"].fn(path="/notes.md")

            m.get(f"{DISK}/resources/download").mock(
                return_value=httpx.Response(200, json={"href": "https://downloader.disk.yandex.ru/d/big"})
            )
            m.get("https://downloader.disk.yandex.ru/d/big").mock(
                return_value=httpx.Response(200, content=b"x" * 1_100_000)
            )
            with pytest.raises(ConnectorError, match="1 МБ"):
                await t["disk_read_text"].fn(path="/big.txt")
            with pytest.raises(ConnectorError, match="текстовые"):
                await t["disk_read_text"].fn(path="/photo.jpg")


class FakeIMAP:
    """Поддельный IMAP: записывает команды; ящик с двумя письмами."""

    instances: list[FakeIMAP] = []
    MSG = (
        "From: =?utf-8?b?0JjQstCw0L0=?= <ivan@corp.ru>\r\nTo: ann@company.ru\r\n"
        "Subject: =?utf-8?b?0J7RgtGH0ZHRgg==?=\r\n"
        "Date: Thu, 08 Oct 2026 10:00:00 +0300\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><style>p{}</style><p>Сумма <b>100</b></p><script>alert(1)</script></html>"
    ).encode()

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.log, self.literal, self.auth = host, port, [], None, None
        FakeIMAP.instances.append(self)

    def authenticate(self, mech, cb):
        self.auth = (mech, cb(b""))
        if b"bad-token" in self.auth[1]:
            raise imaplib.IMAP4.error("AUTHENTICATE failed")
        return "OK", [b""]

    def select(self, mailbox, readonly=False):
        self.log.append(("select", mailbox, readonly))
        return ("OK", [b"2"]) if mailbox == '"INBOX"' else ("NO", [b""])

    def uid(self, cmd, *args):
        self.log.append(("uid", cmd, args, self.literal))
        if cmd == "SEARCH":
            return "OK", [b"11 12"]
        if "RFC822.SIZE" in args[1] and "BODY" not in args[1]:
            size = 9_000_000 if args[0] == "12" else 500
            return "OK", [f"1 (UID {args[0]} RFC822.SIZE {size})".encode()]
        return "OK", [(b"1 (UID 11 BODY[] {100}", self.MSG), b")"]

    def logout(self):
        self.log.append(("logout",))


async def test_mail_list_and_read_readonly(tmp_path, as_user):
    FakeIMAP.instances = []
    as_user("member", ("yandex360", "mail", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        t = y360(tmp_path, http, imap=FakeIMAP)
        rows = json.loads(await t["mail_list"].fn(subject="Отчёт", since="2026-10-01", from_addr="ivan@corp.ru"))
        assert [r["uid"] for r in rows] == ["12", "11"]  # новые сверху
        assert rows[0]["from"].startswith("Иван") and rows[0]["subject"] == "Отчёт"
        imap = FakeIMAP.instances[0]
        assert imap.auth == ("XOAUTH2", b"user=ann@company.ru\x01auth=Bearer ya-user-token\x01\x01")
        assert ("select", '"INBOX"', True) in imap.log  # EXAMINE — только чтение
        search = next(e for e in imap.log if e[0] == "uid" and e[1] == "SEARCH")
        assert search[2] == ("CHARSET", "UTF-8", "SINCE", "01-Oct-2026", "FROM", '"ivan@corp.ru"', "SUBJECT")
        assert search[3] == "Отчёт".encode()  # тема — литералом, без подстановки в команду
        assert all("PEEK" in e[2][1] for e in imap.log if e[0] == "uid" and e[1] == "FETCH" and "BODY" in e[2][1])
        assert imap.log[-1] == ("logout",)

        msg = json.loads(await t["mail_read"].fn(uid="11"))
        assert "Сумма 100" in msg["text"] and "alert" not in msg["text"] and "<p>" not in msg["text"]
        big = json.loads(await t["mail_read"].fn(uid="12"))
        assert "больше 5 МБ" in big["text"]
        fetches = [e[2][1] for e in FakeIMAP.instances[-1].log if e[0] == "uid" and e[1] == "FETCH"]
        assert fetches[-1] == "(BODY.PEEK[HEADER])"


@pytest.mark.parametrize(
    "kwargs",
    [{"folder": 'INBOX" DELETE "x'}, {"from_addr": "a@b.ru) (OR"}, {"since": "1 Oct"}, {"subject": "x\r\nA DELETE"}],
)
async def test_mail_input_validation(tmp_path, as_user, kwargs):
    as_user("member", ("yandex360", "mail", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        with pytest.raises(ConnectorError):
            await y360(tmp_path, http, imap=FakeIMAP)["mail_list"].fn(**kwargs)


async def test_mail_uid_and_auth_errors(tmp_path, as_user):
    as_user("member", ("yandex360", "mail", "read"), user_id=7, email="ann@company.ru")
    async with httpx.AsyncClient() as http:
        with pytest.raises(ConnectorError):
            await y360(tmp_path, http, imap=FakeIMAP)["mail_read"].fn(uid="1:*")
        t = y360(tmp_path, http, imap=FakeIMAP, creds=FakeCreds(token="bad-token"))
        with pytest.raises(ConnectorError) as e:
            await t["mail_list"].fn()
    assert e.value.code == ErrorCode.RELOGIN_REQUIRED


def test_only_configured_services(tmp_path):
    t = y360(tmp_path, httpx.AsyncClient(), services="disk")
    assert set(t) == {"disk_list", "disk_recent", "disk_read_text"}


# ================================================================== сквозной: всё регистрируется


async def test_all_new_tools_registered(tmp_path):
    from rugw.app import build_app

    s = make_settings(
        tmp_path,
        yandex360_services="disk,mail",
        token_encryption_keys=KEY,
        yandex_extra_scopes="cloud_api:disk.read mail:imap_ro",
        diadoc_client_id="a",
        diadoc_client_secret="s",
        sbis_login="r",
        sbis_password="p",
    )
    app = build_app(s, http=httpx.AsyncClient())
    names = set(app.state.server._specs)
    assert {
        "diadoc_boxes",
        "diadoc_documents",
        "sbis_documents",
        "disk_list",
        "disk_recent",
        "disk_read_text",
        "mail_list",
        "mail_read",
    } <= names
    assert all(
        app.state.server._specs[n].level == Level.READ
        for n in names
        if n.startswith(("diadoc", "sbis", "disk", "mail"))
    )
    assert app.state.secrets is not None and app.state.credentials is not None
