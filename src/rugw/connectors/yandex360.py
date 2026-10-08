"""Яндекс 360 от имени сотрудника: Диск и Почта. Только чтение.

Токен — собственный токен Яндекса сотрудника (credentials.py), полученный при входе в шлюз
с дополнительными правами: cloud_api:disk.read (Диск), mail:imap_ro (Почта).
Права шлюза (ресурс): disk, mail — разрешено ли вообще давать ИИ доступ к своему Диску/Почте.

Диск — REST API: https://cloud-api.yandex.net/v1/disk (заголовок Authorization: OAuth <токен>).
  Ссылка на скачивание подписана и сама по себе даёт доступ к файлу: модели не отдаётся,
  файл читает шлюз (только текстовые форматы, до 1 МБ).
Почта — IMAP с XOAUTH2 (https://yandex.ru/support/yandex-360/business/mail/ru/web/security/oauth):
  ящик открывается командой EXAMINE (только чтение), письма читаются BODY.PEEK — не помечаются
  прочитанными. Вложения не отдаются. В ящике должен быть включён доступ по IMAP.

Календарь не реализован: вход в CalDAV Яндекса по OAuth-токену официально не описан.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import email
import email.policy
import imaplib
import re
from collections.abc import Callable
from email.header import decode_header, make_header
from typing import Any
from urllib.parse import urlparse

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.credentials import CredentialsUnavailable, YandexCredentials
from rugw.errors import ErrorCode
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "yandex360"
TEXT_EXT = (".txt", ".md", ".csv", ".json", ".xml", ".log", ".tsv", ".yaml", ".yml", ".ini")
MAX_FILE_BYTES = 1_000_000
MAX_MAIL_BYTES = 5_000_000
MAX_BODY_CHARS = 20_000
FOLDER = re.compile(r"^[A-Za-z0-9&,+_.\- /]{1,100}$")  # имена IMAP-папок (modified UTF-7)
ASCII_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def disk_path(path: str) -> str:
    path = (path or "/").strip()
    if path.startswith("disk:"):
        path = path[5:]
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 500 or any(ord(c) < 32 for c in path) or "/../" in path + "/" or "\\" in path:
        raise ConnectorError("Некорректный путь на Диске")
    return "disk:" + path


def safe_download_url(href: Any) -> str:
    """Ссылка на скачивание — только https на домене Яндекса (защита от подмены адреса в ответе)."""
    if not isinstance(href, str):
        raise ConnectorError("Яндекс Диск: нет ссылки на скачивание", ErrorCode.UPSTREAM_BAD_RESPONSE)
    u = urlparse(href)
    host = u.hostname or ""
    if u.scheme != "https" or not (host.endswith(".yandex.net") or host.endswith(".yandex.ru")):
        raise ConnectorError("Яндекс Диск: неожиданная ссылка на скачивание", ErrorCode.UPSTREAM_BAD_RESPONSE)
    return href


def _hdr(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:  # noqa: BLE001 — кривой заголовок не должен ронять чтение
        return str(value)


def _text_of(msg: email.message.Message) -> str:
    part = msg.get_body(preferencelist=("plain", "html")) if hasattr(msg, "get_body") else None
    if part is None:
        return ""
    try:
        text = part.get_content()
    except (LookupError, ValueError):
        payload = part.get_payload(decode=True) or b""
        text = payload.decode("utf-8", "replace")
    if part.get_content_type() == "text/html":
        text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"[ \t]+", " ", text)
    text = text.strip()
    return text[:MAX_BODY_CHARS] + ("…[обрезано]" if len(text) > MAX_BODY_CHARS else "")


def imap_date(value: str) -> str:
    try:
        d = dt.date.fromisoformat(value.strip())
    except ValueError as exc:
        raise ConnectorError("Дата: ГГГГ-ММ-ДД") from exc
    return f"{d.day:02d}-{MONTHS[d.month - 1]}-{d.year}"


def xoauth2(user: str, token: str) -> bytes:
    return f"user={user}\x01auth=Bearer {token}\x01\x01".encode()


class Mailbox:
    """Синхронная работа с IMAP; вызывается из потока (asyncio.to_thread)."""

    def __init__(self, factory: Callable[..., Any], host: str, user: str, token: str) -> None:
        self.factory, self.host, self.user, self.token = factory, host, user, token

    def _open(self, folder: str):
        conn = self.factory(self.host, 993, timeout=20)
        try:
            conn.authenticate("XOAUTH2", lambda _: xoauth2(self.user, self.token))
            status, _ = conn.select(f'"{folder}"', readonly=True)  # EXAMINE
            if status != "OK":
                raise ConnectorError("Почта: папка не найдена", ErrorCode.UPSTREAM_NOT_FOUND)
        except imaplib.IMAP4.error as exc:
            conn.logout()
            raise ConnectorError(
                "Почта: вход не выполнен — проверьте, что в ящике включён IMAP, и переподключите шлюз",
                ErrorCode.RELOGIN_REQUIRED,
            ) from exc
        return conn

    def search(self, folder: str, criteria: list[str], literal: str | None, limit: int) -> list[dict]:
        conn = self._open(folder)
        try:
            if literal is not None:
                conn.literal = literal.encode()
                status, data = conn.uid("SEARCH", "CHARSET", "UTF-8", *criteria)
            else:
                status, data = conn.uid("SEARCH", *(criteria or ["ALL"]))
            if status != "OK":
                raise ConnectorError("Почта: поиск не выполнен", ErrorCode.UPSTREAM_ERROR)
            uids = (data[0] or b"").split()[-limit:][::-1]  # новые сверху
            out = []
            for uid in uids:
                status, parts = conn.uid("FETCH", uid, "(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)])")
                raw = next((p[1] for p in parts if isinstance(p, tuple)), b"") if status == "OK" else b""
                msg = email.message_from_bytes(raw, policy=email.policy.default)
                out.append(
                    {
                        "uid": uid.decode(),
                        "from": _hdr(msg["From"]),
                        "subject": _hdr(msg["Subject"]),
                        "date": _hdr(msg["Date"]),
                    }
                )
            return out
        finally:
            conn.logout()

    def read(self, folder: str, uid: str) -> dict:
        conn = self._open(folder)
        try:
            status, parts = conn.uid("FETCH", uid, "(RFC822.SIZE)")
            meta = b" ".join(p if isinstance(p, bytes) else p[0] for p in parts or [] if p) if status == "OK" else b""
            m = re.search(rb"RFC822\.SIZE (\d+)", meta)
            if not m:
                raise ConnectorError("Почта: письмо не найдено", ErrorCode.UPSTREAM_NOT_FOUND)
            if int(m.group(1)) > MAX_MAIL_BYTES:
                spec = "(BODY.PEEK[HEADER])"
            else:
                spec = "(BODY.PEEK[])"
            status, parts = conn.uid("FETCH", uid, spec)
            raw = next((p[1] for p in parts if isinstance(p, tuple)), b"") if status == "OK" else b""
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            attachments = [_hdr(p.get_filename()) for p in msg.iter_attachments()] if spec == "(BODY.PEEK[])" else []
            return {
                "from": _hdr(msg["From"]),
                "to": _hdr(msg["To"]),
                "subject": _hdr(msg["Subject"]),
                "date": _hdr(msg["Date"]),
                "text": _text_of(msg)
                if spec == "(BODY.PEEK[])"
                else "[письмо больше 5 МБ — показаны только заголовки]",
                "attachments": [a for a in attachments if a],
            }
        finally:
            conn.logout()


def build(
    settings: Settings,
    http: httpx.AsyncClient,
    credentials: YandexCredentials | None = None,
    secrets: Any = None,
    imap_factory: Callable[..., Any] = imaplib.IMAP4_SSL,
) -> list[ToolSpec]:
    services = settings.yandex360_set
    if not services:
        return []
    if credentials is None:
        raise RuntimeError("Яндекс 360 включён, но хранилище токенов сотрудников не настроено")
    base = settings.yandex_disk_api_base.rstrip("/")

    async def user_token(resource: str) -> tuple[str, str]:
        perms = current_permissions()
        perms.require(CONNECTOR, resource, Level.READ)
        if perms.user_id is None or not perms.email:
            raise ConnectorError("Яндекс 360: не определён пользователь", ErrorCode.INTERNAL)
        try:
            return await credentials.access_token(perms.user_id), perms.email
        except CredentialsUnavailable as exc:
            raise ConnectorError(
                f"Яндекс 360: {exc} — переподключите шлюз в клиенте (войдите через Яндекс заново)",
                ErrorCode.RELOGIN_REQUIRED,
            ) from exc

    specs: list[ToolSpec] = []

    if "disk" in services:

        async def disk_get(path: str, params: dict) -> Any:
            token, _ = await user_token("disk")
            return await call_json(
                http,
                "GET",
                f"{base}{path}",
                system="Яндекс Диск",
                headers={"Authorization": f"OAuth {token}"},
                params=params,
            )

        def item(i: dict) -> dict:
            return {k: i.get(k) for k in ("name", "path", "type", "size", "mime_type", "modified") if k in i}

        async def disk_list(path: str = "/", limit: int = 50, offset: int = 0) -> str:
            """Содержимое папки на вашем Яндекс Диске (например "/" или "/Документы")."""
            data = await disk_get(
                "/resources",
                {"path": disk_path(path), "limit": max(1, min(limit, 200)), "offset": max(0, offset)},
            )
            embedded = (data or {}).get("_embedded") or {} if isinstance(data, dict) else {}
            items = embedded.get("items") or []
            return clip({"total": embedded.get("total"), "items": [item(i) for i in items if isinstance(i, dict)]})

        async def disk_recent(limit: int = 20) -> str:
            """Последние загруженные файлы на вашем Яндекс Диске."""
            data = await disk_get("/resources/last-uploaded", {"limit": max(1, min(limit, 100))})
            items = (data or {}).get("items") or [] if isinstance(data, dict) else []
            return clip([item(i) for i in items if isinstance(i, dict)])

        async def disk_read_text(path: str) -> str:
            """Прочитать текстовый файл с Диска (txt, md, csv, json, xml и т.п., до 1 МБ)."""
            full = disk_path(path)
            if not full.lower().endswith(TEXT_EXT):
                raise ConnectorError(f"Читаются только текстовые файлы: {', '.join(TEXT_EXT)}")
            data = await disk_get("/resources/download", {"path": full})
            url = safe_download_url(data.get("href") if isinstance(data, dict) else None)
            try:
                # Ссылка подписана — токен сотрудника на неё не отправляем.
                async with http.stream("GET", url, timeout=30, follow_redirects=True) as r:
                    if r.status_code != 200:
                        raise ConnectorError(
                            f"Яндекс Диск: файл не скачан (HTTP {r.status_code})", ErrorCode.UPSTREAM_ERROR
                        )
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > MAX_FILE_BYTES:
                            raise ConnectorError("Файл больше 1 МБ — откройте его на Диске")
            except httpx.HTTPError as exc:
                raise ConnectorError("Яндекс Диск: файл не скачан", ErrorCode.UPSTREAM_UNAVAILABLE) from exc
            return clip({"path": full, "text": bytes(buf).decode("utf-8", "replace")})

        specs += [
            ToolSpec(f.__name__, Level.READ, f, f.__doc__, CONNECTOR) for f in (disk_list, disk_recent, disk_read_text)
        ]

    if "mail" in services:

        def folder_ok(folder: str) -> str:
            if not FOLDER.match(folder) or '"' in folder:
                raise ConnectorError("Некорректное имя папки (например INBOX, Sent)")
            return folder

        async def mail_list(
            folder: str = "INBOX", from_addr: str = "", subject: str = "", since: str = "", limit: int = 20
        ) -> str:
            """Письма в вашем ящике Яндекс Почты (новые сверху): отправитель, тема, дата, uid.
            Фильтры: from_addr — адрес отправителя, subject — слово из темы, since — с даты ГГГГ-ММ-ДД."""
            token, user = await user_token("mail")
            criteria: list[str] = []
            if since:
                criteria += ["SINCE", imap_date(since)]
            if from_addr:
                if not ASCII_EMAIL.match(from_addr):
                    raise ConnectorError("from_addr: адрес вида name@example.ru")
                criteria += ["FROM", f'"{from_addr}"']
            literal = None
            if subject:
                if len(subject) > 200 or any(ord(c) < 32 for c in subject):
                    raise ConnectorError("subject: до 200 символов, без управляющих")
                criteria += ["SUBJECT"]  # значение — IMAP-литералом (безопасно для любых символов)
                literal = subject
            box = Mailbox(imap_factory, settings.yandex_imap_host, user, token)
            rows = await asyncio.to_thread(box.search, folder_ok(folder), criteria, literal, max(1, min(limit, 50)))
            return clip(rows)

        async def mail_read(uid: str, folder: str = "INBOX") -> str:
            """Прочитать письмо по uid (из mail_list): заголовки и текст (до 20 000 символов), имена вложений.
            Письмо не помечается прочитанным."""
            if not re.fullmatch(r"\d{1,10}", uid or ""):
                raise ConnectorError("uid: число из mail_list")
            token, user = await user_token("mail")
            box = Mailbox(imap_factory, settings.yandex_imap_host, user, token)
            return clip(await asyncio.to_thread(box.read, folder_ok(folder), uid))

        specs += [ToolSpec(f.__name__, Level.READ, f, f.__doc__, CONNECTOR) for f in (mail_list, mail_read)]

    return specs
