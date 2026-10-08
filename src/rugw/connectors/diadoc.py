"""Диадок (Контур). Только чтение.

Документация: https://developer.kontur.ru/doc/diadoc-api/authentication.html
Вход — OpenID Connect через identity.kontur.ru. Администратор один раз выполняет
`rugw diadoc login` (Device Authorization Flow): шлюз сохраняет refresh-токен зашифрованным.
Дальше access-токен получается по refresh; Контур выдаёт новый refresh при каждом обмене —
он сохраняется условно по поколению (CAS), как токены сотрудников.

Права шлюза (ресурс): идентификатор ящика (BoxId) организации.
GetMyOrganizations вызывается с autoRegister=false: иначе Диадок может зарегистрировать
пользователя в организации по сертификату — побочный эффект, недопустимый для чтения.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.errors import ErrorCode
from rugw.policy import Level
from rugw.service_credentials import ServiceSecrets, ServiceSecretUnavailable
from rugw.tools import ConnectorError, ToolSpec

log = logging.getLogger(__name__)

CONNECTOR = "diadoc"
PROVIDER = "diadoc"
BOX_ID = re.compile(r"^[A-Za-z0-9@.\-]{1,64}$")
CATEGORY = re.compile(r"^[A-Za-z.]{1,40}$")
INDEX_KEY = re.compile(r"^[A-Za-z0-9+/=_\-]{1,200}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DOC_FIELDS = (
    "MessageId",
    "EntityId",
    "DocumentType",
    "TypeNamedId",
    "CounteragentBoxId",
    "Title",
    "DocumentDate",
    "DocumentNumber",
    "CreationTimestamp",
    "IndexKey",
    "DocflowStatus",
)
RELOGIN = "Диадок: нужен повторный вход администратора — выполните на сервере `rugw diadoc login`"


class DiadocTokens:
    """Access-токен в памяти + ротация refresh в базе."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient, secrets: ServiceSecrets) -> None:
        self.s = settings
        self.http = http
        self.secrets = secrets
        self._access: str | None = None
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def _token_request(self, form: dict[str, str]) -> dict:
        try:
            r = await self.http.post(
                f"{self.s.diadoc_identity_base.rstrip('/')}/connect/token",
                data={
                    **form,
                    "client_id": self.s.diadoc_client_id,
                    "client_secret": self.s.diadoc_client_secret.get_secret_value(),
                },
                timeout=20,
            )
        except httpx.HTTPError as exc:
            raise ConnectorError("Диадок: сервер входа Контура недоступен", ErrorCode.UPSTREAM_UNAVAILABLE) from exc
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code != 200 or not isinstance(data, dict) or not data.get("access_token"):
            err = data.get("error") if isinstance(data, dict) else None
            if err in ("invalid_grant", "invalid_client", "unauthorized_client"):
                raise ConnectorError(RELOGIN, ErrorCode.RELOGIN_REQUIRED)
            raise ConnectorError(f"Диадок: вход не выполнен (HTTP {r.status_code})", ErrorCode.UPSTREAM_AUTH)
        return data

    async def access_token(self) -> str:
        async with self._lock:
            if self._access and self._expires - 120 > time.time():
                return self._access
            for _ in range(2):
                try:
                    refresh, generation = await self.secrets.get(PROVIDER)
                except ServiceSecretUnavailable as exc:
                    raise ConnectorError(f"{RELOGIN} ({exc})", ErrorCode.RELOGIN_REQUIRED) from exc
                try:
                    data = await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh})
                except ConnectorError as exc:
                    if exc.code != ErrorCode.RELOGIN_REQUIRED:
                        raise
                    # Возможно, другой процесс уже обменял этот refresh: если поколение сменилось — повторяем.
                    _, current = await self.secrets.get(PROVIDER)
                    if current != generation:
                        continue
                    raise
                new_refresh = data.get("refresh_token")
                if isinstance(new_refresh, str) and new_refresh and new_refresh != refresh:
                    if not await self.secrets.cas(PROVIDER, generation, new_refresh):
                        log.info("diadoc refresh token changed concurrently; keeping the stored one")
                self._access = data["access_token"]
                expires = data.get("expires_in")
                self._expires = time.time() + (
                    int(expires) if isinstance(expires, int | float) and expires > 0 else 600
                )
                return self._access
            raise ConnectorError(RELOGIN, ErrorCode.RELOGIN_REQUIRED)

    async def device_login(self, show) -> None:
        """Device Authorization Flow для `rugw diadoc login`. show(url, code) печатает инструкцию."""
        base = self.s.diadoc_identity_base.rstrip("/")
        auth = {"client_id": self.s.diadoc_client_id, "client_secret": self.s.diadoc_client_secret.get_secret_value()}
        r = await self.http.post(
            f"{base}/connect/deviceauthorization", data={**auth, "scope": self.s.diadoc_scope}, timeout=20
        )
        if r.status_code != 200:
            raise ConnectorError(f"Диадок: не удалось начать вход (HTTP {r.status_code})", ErrorCode.UPSTREAM_AUTH)
        d = r.json()
        show(d.get("verification_uri_complete") or d.get("verification_uri"), d.get("user_code"))
        interval = max(1, int(d.get("interval") or 5))
        deadline = time.time() + int(d.get("expires_in") or 600)
        while time.time() < deadline:
            await asyncio.sleep(interval)
            t = await self.http.post(
                f"{base}/connect/token",
                data={
                    **auth,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": d.get("device_code", ""),
                    "scope": self.s.diadoc_scope,
                },
                timeout=20,
            )
            body = t.json() if t.content else {}
            if t.status_code == 200 and body.get("refresh_token"):
                await self.secrets.put(PROVIDER, body["refresh_token"])
                self._access, self._expires = None, 0.0
                return
            err = body.get("error")
            if err == "slow_down":
                interval += 5
            elif err != "authorization_pending":
                raise ConnectorError(f"Диадок: вход отклонён ({safe(err)})", ErrorCode.UPSTREAM_AUTH)
        raise ConnectorError("Диадок: время на подтверждение входа истекло", ErrorCode.UPSTREAM_TIMEOUT)


def safe(value: Any) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[a-z_]{1,40}", value) else "ошибка"


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None, secrets: ServiceSecrets | None = None):
    if not (settings.diadoc_client_id and settings.diadoc_client_secret):
        return []
    if secrets is None:
        raise RuntimeError("Диадок включён, но хранилище служебных токенов не настроено")
    tokens = DiadocTokens(settings, http, secrets)
    base = settings.diadoc_api_base.rstrip("/")

    async def headers() -> dict[str, str]:
        return {"Authorization": f"Bearer {await tokens.access_token()}", "Accept": "application/json"}

    async def diadoc_boxes() -> str:
        """Организации и их ящики Диадока, доступные вам в шлюзе (BoxId нужен для diadoc_documents)."""
        perms = current_permissions()
        data = await call_json(
            http,
            "GET",
            f"{base}/GetMyOrganizations",
            system="Диадок",
            headers=await headers(),
            params={"autoRegister": "false"},
        )
        out = []
        for org in (data or {}).get("Organizations", []) if isinstance(data, dict) else []:
            if not isinstance(org, dict):
                continue
            boxes = [
                {"BoxId": b.get("BoxId"), "Title": b.get("Title")}
                for b in org.get("Boxes") or []
                if isinstance(b, dict)
                and isinstance(b.get("BoxId"), str)
                and perms.allows(CONNECTOR, b["BoxId"], Level.READ)
            ]
            if boxes:
                out.append(
                    {"FullName": org.get("FullName"), "Inn": org.get("Inn"), "Kpp": org.get("Kpp"), "Boxes": boxes}
                )
        return clip(out)

    async def diadoc_documents(
        box_id: str,
        category: str = "Incoming",
        from_date: str = "",
        to_date: str = "",
        count: int = 50,
        after_index_key: str = "",
    ) -> str:
        """Документы в ящике Диадока. category — категория документов Диадока (например Incoming, Outgoing).
        Даты — ГГГГ-ММ-ДД. Для следующей страницы передайте after_index_key = IndexKey последнего документа."""
        if not BOX_ID.match(box_id):
            raise ConnectorError("Некорректный BoxId")
        current_permissions().require(CONNECTOR, box_id, Level.READ)
        if not CATEGORY.match(category):
            raise ConnectorError("category: латиница и точки")
        body: dict[str, Any] = {"DocumentCategory": category, "Count": max(1, min(count, 100))}
        for key, value in (("FromDocumentDate", from_date), ("ToDocumentDate", to_date)):
            if value:
                if not DATE.match(value):
                    raise ConnectorError("Дата: ГГГГ-ММ-ДД")
                body[key] = value
        if after_index_key:
            if not INDEX_KEY.match(after_index_key):
                raise ConnectorError("Некорректный after_index_key")
            body["AfterIndexKey"] = after_index_key
        data = await call_json(
            http,
            "POST",
            f"{base}/V4/GetDocuments",
            system="Диадок",
            headers=await headers(),
            params={"boxId": box_id},
            json=body,
        )
        docs = (data or {}).get("Documents", []) if isinstance(data, dict) else []
        return clip(
            {
                "TotalCount": (data or {}).get("TotalCount") if isinstance(data, dict) else None,
                "HasMoreResults": (data or {}).get("HasMoreResults") if isinstance(data, dict) else None,
                "Documents": [{k: d.get(k) for k in DOC_FIELDS if k in d} for d in docs if isinstance(d, dict)],
            }
        )

    return [
        ToolSpec("diadoc_boxes", Level.READ, diadoc_boxes, diadoc_boxes.__doc__, CONNECTOR),
        ToolSpec("diadoc_documents", Level.READ, diadoc_documents, diadoc_documents.__doc__, CONNECTOR),
    ]
