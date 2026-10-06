"""Контур.Фокус (API 3.0): сведения о компаниях и ИП по ИНН/ОГРН. Только чтение.

Документация: https://developer.kontur.ru/doc/focus
Ключ передаётся параметром key в адресе запроса — поэтому лог httpx на уровне INFO
отключён (__main__.py), а ошибки не содержат адреса.

Права шлюза (ресурс): метод API — req, egrDetails, analytics, briefReport, buh, licences.
Методы платные по-разному: выдавайте только нужные.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from rugw.access import current_permissions
from rugw.config import Settings
from rugw.connectors.base import call_json, clip
from rugw.policy import Level
from rugw.tools import ConnectorError, ToolSpec

CONNECTOR = "focus"
METHODS = {
    "req": "реквизиты (действующие и исторические)",
    "egrDetails": "расширенные сведения ЕГРЮЛ/ЕГРИП",
    "analytics": "аналитика и маркеры риска",
    "briefReport": "экспресс-отчёт",
    "buh": "бухгалтерская отчётность",
    "licences": "лицензии",
}
INN = re.compile(r"^(\d{10}|\d{12})$")
OGRN = re.compile(r"^(\d{13}|\d{15})$")
MAX_IDS = 10


def parse_ids(value: str) -> tuple[list[str], list[str]]:
    """'7707083893, 1027700132195' → (ИНН, ОГРН). Проверяется формат каждого."""
    inns, ogrns = [], []
    for raw in value.replace(";", ",").split(","):
        item = raw.strip()
        if not item:
            continue
        if INN.match(item):
            inns.append(item)
        elif OGRN.match(item):
            ogrns.append(item)
        else:
            raise ConnectorError(f"«{item[:20]}» — не ИНН (10/12 цифр) и не ОГРН (13/15 цифр)")
    if not inns and not ogrns:
        raise ConnectorError("Укажите хотя бы один ИНН или ОГРН")
    if len(inns) + len(ogrns) > MAX_IDS:
        raise ConnectorError(f"Не больше {MAX_IDS} компаний за запрос")
    return inns, ogrns


def build(settings: Settings, http: httpx.AsyncClient, credentials: Any = None) -> list[ToolSpec]:
    if not settings.focus_key:
        return []
    base = settings.focus_api_base.rstrip("/")

    async def focus_lookup(inn_or_ogrn: str, method: str = "req") -> str:
        """Сведения о компаниях/ИП из Контур.Фокуса. inn_or_ogrn — один или несколько ИНН/ОГРН
        через запятую (до 10). method: req (реквизиты), egrDetails (ЕГРЮЛ/ЕГРИП), analytics (риски),
        briefReport (экспресс-отчёт), buh (отчётность), licences (лицензии)."""
        if method not in METHODS:
            raise ConnectorError(f"method: один из {', '.join(METHODS)}")
        current_permissions().require(CONNECTOR, method, Level.READ)
        inns, ogrns = parse_ids(inn_or_ogrn)
        params: dict[str, str] = {"key": settings.focus_key.get_secret_value()}
        if inns:
            params["inn"] = ",".join(inns)
        if ogrns:
            params["ogrn"] = ",".join(ogrns)
        data = await call_json(http, "GET", f"{base}/{method}", system="Контур.Фокус", params=params)
        return clip(data)

    return [ToolSpec("focus_lookup", Level.READ, focus_lookup, focus_lookup.__doc__, CONNECTOR)]
