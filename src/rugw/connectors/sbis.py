"""СБИС (Saby) — JSON-RPC API. Только чтение.

Документация: https://saby.ru/help/integration/api/sequence/auth,
https://saby.ru/help/integration/api/all_methods/list_doc/
Вход: СБИС.Аутентифицировать (логин и пароль служебного пользователя) → идентификатор сессии,
передаётся заголовком X-SBISSessionID. Сессия кэшируется в памяти; при 401 — повторный вход
(одна попытка). У пользователя СБИС не больше 5 активных сессий: держите один экземпляр шлюза.

Права шлюза (ресурс): тип документа СБИС («Тип» в фильтре), например ДокОтгрВх, ДокОтгрИсх.
Ссылки на вложения и подписи в ответе не отдаются: по документации они действуют месяц
и дают доступ к файлам без входа.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip, safe_code
from rugw.errors import ErrorCode
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "sbis"
DOC_TYPE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9]{1,50}$")
DOC_FIELDS = (
    "Идентификатор",
    "Название",
    "Дата",
    "Номер",
    "Сумма",
    "Тип",
    "Направление",
    "ДатаВремяСоздания",
    "Удален",
)


def to_sbis_date(value: str) -> str:
    try:
        return dt.date.fromisoformat(value.strip()).strftime("%d.%m.%Y")
    except ValueError as exc:
        raise ConnectorError("Дата: ГГГГ-ММ-ДД") from exc


def counterparty_name(c: Any) -> str | None:
    if not isinstance(c, dict):
        return None
    ul, fl = c.get("СвЮЛ"), c.get("СвФЛ")
    if isinstance(ul, dict):
        return ul.get("Название") or ul.get("НазваниеПолное")
    if isinstance(fl, dict):
        return " ".join(str(fl.get(k)) for k in ("Фамилия", "Имя", "Отчество") if fl.get(k)) or None
    return None


def slim_doc(d: dict) -> dict:
    out = {k: d[k] for k in DOC_FIELDS if k in d}
    state = d.get("Состояние")
    if isinstance(state, dict):
        out["Состояние"] = state.get("Название")
    name = counterparty_name(d.get("Контрагент"))
    if name:
        out["Контрагент"] = name
    return out


class SbisSession:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self.s = settings
        self.http = http
        self._sid: str | None = None
        self._lock = asyncio.Lock()

    async def _login(self) -> str:
        data = await call_json(
            self.http,
            "POST",
            self.s.sbis_auth_url,
            system="СБИС",
            json={
                "jsonrpc": "2.0",
                "method": "СБИС.Аутентифицировать",
                "params": {"Параметр": {"Логин": self.s.sbis_login, "Пароль": self.s.sbis_password.get_secret_value()}},
                "id": 0,
            },
        )
        sid = data.get("result") if isinstance(data, dict) else None
        if not isinstance(sid, str) or not sid:
            raise ConnectorError(
                "СБИС: вход не выполнен — проверьте логин и пароль коннектора", ErrorCode.UPSTREAM_AUTH
            )
        return sid

    async def session_id(self, renew: bool = False) -> str:
        async with self._lock:
            if renew or self._sid is None:
                self._sid = await self._login()
            return self._sid

    async def call(self, method: str, params: dict) -> Any:
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 0}
        for attempt in range(2):
            sid = await self.session_id(renew=attempt > 0)
            try:
                data = await call_json(
                    self.http,
                    "POST",
                    self.s.sbis_service_url,
                    system="СБИС",
                    headers={"X-SBISSessionID": sid},
                    json=body,
                )
            except ConnectorError as exc:
                if exc.code == ErrorCode.UPSTREAM_AUTH and attempt == 0:
                    continue  # сессия истекла — входим заново и повторяем
                raise
            if isinstance(data, dict) and data.get("error"):
                err = data["error"]
                code = safe_code(str(err.get("code"))) if isinstance(err, dict) else None
                raise ConnectorError(f"СБИС: ошибка{f', код {code}' if code else ''}", ErrorCode.UPSTREAM_ERROR)
            return data.get("result") if isinstance(data, dict) else None
        raise ConnectorError("СБИС: вход не выполнен", ErrorCode.UPSTREAM_AUTH)


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None, secrets: Any = None) -> list[ToolSpec]:
    if not (settings.sbis_login and settings.sbis_password):
        return []
    session = SbisSession(settings, http)

    async def sbis_documents(
        doc_type: str, date_from: str = "", date_to: str = "", page: int = 0, page_size: int = 50
    ) -> str:
        """Документы СБИС указанного типа (например ДокОтгрВх — входящие реализации, ДокОтгрИсх — исходящие).
        Даты — ГГГГ-ММ-ДД. Страницы с 0; в ответе ЕстьЕще=Да — есть следующая страница."""
        if not DOC_TYPE.match(doc_type):
            raise ConnectorError("Некорректный тип документа СБИС")
        current_permissions().require(CONNECTOR, doc_type, Level.READ)
        flt: dict[str, Any] = {"Тип": doc_type}
        if date_from:
            flt["ДатаС"] = to_sbis_date(date_from)
        if date_to:
            flt["ДатаПо"] = to_sbis_date(date_to)
        result = await session.call(
            "СБИС.СписокДокументов",
            {
                "Фильтр": flt,
                "Навигация": {"РазмерСтраницы": str(max(1, min(page_size, 200))), "Страница": str(max(0, page))},
            },
        )
        docs = result.get("Документ", []) if isinstance(result, dict) else []
        nav = result.get("Навигация", {}) if isinstance(result, dict) else {}
        return clip(
            {
                "ЕстьЕще": nav.get("ЕстьЕще") if isinstance(nav, dict) else None,
                "Документы": [slim_doc(d) for d in docs if isinstance(d, dict)],
            }
        )

    return [ToolSpec("sbis_documents", Level.READ, sbis_documents, sbis_documents.__doc__, CONNECTOR)]
