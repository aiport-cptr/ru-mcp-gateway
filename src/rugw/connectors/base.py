"""Общее для коннекторов: HTTP-вызов с понятными ошибками и ограничение объёма ответа.

Тексты ошибок внешних систем в ответ модели и в аудит НЕ попадают: тело ответа
может содержать секреты, персональные данные или диагностику. Наружу уходят только
система, HTTP-статус, безопасный код ошибки и идентификатор запроса — по ним
администратор найдёт подробности в журнале внешней системы.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from rugw.errors import ErrorCode, current_request_id
from rugw.tools import ConnectorError

log = logging.getLogger(__name__)

MAX_RESPONSE_CHARS = 60_000  # не заливаем в контекст модели мегабайты

# Код ошибки (NOT_FOUND, ACCESS_DENIED, -1…) и идентификатор запроса пропускаем, только если
# они выглядят как короткие идентификаторы — без пробелов, разметки и произвольного текста.
_SAFE_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_REQUEST_ID_HEADERS = ("x-request-id", "x-req-id", "x-trace-id", "x-correlation-id")


def safe_code(value: Any) -> str | None:
    return value if isinstance(value, str) and _SAFE_CODE.match(value) else None


def _request_id(r: httpx.Response) -> str | None:
    for h in _REQUEST_ID_HEADERS:
        rid = safe_code(r.headers.get(h))
        if rid:
            return rid
    return None


def _error_code(r: httpx.Response) -> str | None:
    """Короткий код ошибки из JSON-тела (Битрикс24: error; OData: odata.error.code / error.code)."""
    try:
        data = r.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    for candidate in (data.get("error"), data.get("code"), data.get("odata.error")):
        if isinstance(candidate, dict):
            candidate = candidate.get("code")
        code = safe_code(candidate)
        if code:
            return code
    return None


def _status_code(status: int) -> ErrorCode:
    if status in (401, 403):
        return ErrorCode.UPSTREAM_AUTH
    if status == 404:
        return ErrorCode.UPSTREAM_NOT_FOUND
    if status == 429:
        return ErrorCode.UPSTREAM_RATE_LIMIT
    if 400 <= status < 500:
        return ErrorCode.UPSTREAM_BAD_REQUEST
    return ErrorCode.UPSTREAM_ERROR


def upstream_error(system: str, r: httpx.Response, hint: str = "") -> ConnectorError:
    parts = [f"{system}: ошибка HTTP {r.status_code}"]
    code = _error_code(r)
    if code:
        parts.append(f"код системы {code}")
    rid = _request_id(r)
    if rid:
        parts.append(f"id запроса в системе {rid}")
    gw = current_request_id()
    log.warning(
        "upstream error request_id=%s system=%s status=%s code=%s upstream_request_id=%s",
        gw,
        system,
        r.status_code,
        code,
        rid,
    )
    log.debug("upstream error body request_id=%s system=%s: %.300s", gw, system, r.text)
    return ConnectorError(", ".join(parts) + (f" — {hint}" if hint else ""), _status_code(r.status_code))


async def call_json(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    system: str,
    **kwargs: Any,
) -> Any:
    try:
        r = await http.request(method, url, timeout=30, **kwargs)
    except httpx.TimeoutException as exc:
        raise ConnectorError(f"{system}: превышено время ожидания", ErrorCode.UPSTREAM_TIMEOUT) from exc
    except httpx.HTTPError as exc:
        raise ConnectorError(f"{system}: сеть недоступна", ErrorCode.UPSTREAM_UNAVAILABLE) from exc
    if r.status_code in (401, 403):
        raise upstream_error(system, r, "нет доступа, проверьте учётные данные коннектора")
    if r.status_code == 404:
        raise upstream_error(system, r, "не найдено")
    if r.status_code == 429:
        raise upstream_error(system, r, "превышен лимит запросов, попробуйте позже")
    if 400 <= r.status_code < 500:
        raise upstream_error(system, r, "проверьте параметры запроса")
    if r.status_code >= 500:
        raise upstream_error(system, r, "сбой на стороне внешней системы")
    if r.status_code == 204 or not r.content:
        return None  # например, amoCRM отвечает 204 на пустой список
    try:
        return r.json()
    except ValueError as exc:
        raise ConnectorError(f"{system}: ответ не в формате JSON", ErrorCode.UPSTREAM_BAD_RESPONSE) from exc


def clip(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    if len(text) > MAX_RESPONSE_CHARS:
        return text[:MAX_RESPONSE_CHARS] + f"\n…[обрезано, всего {len(text)} символов — уточните запрос]"
    return text
