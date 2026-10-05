"""Общее для коннекторов: HTTP-вызов с понятными ошибками и ограничение объёма ответа."""

from __future__ import annotations

import json
from typing import Any

import httpx

from rugw.tools import ConnectorError

MAX_RESPONSE_CHARS = 60_000  # не заливаем в контекст модели мегабайты


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
        raise ConnectorError(f"{system}: превышено время ожидания") from exc
    except httpx.HTTPError as exc:
        raise ConnectorError(f"{system}: сеть недоступна") from exc
    if r.status_code in (401, 403):
        raise ConnectorError(f"{system}: нет доступа (HTTP {r.status_code}) — проверьте учётные данные коннектора")
    if r.status_code == 404:
        raise ConnectorError(f"{system}: не найдено")
    if r.status_code == 429:
        raise ConnectorError(f"{system}: превышен лимит запросов, попробуйте позже")
    if r.status_code >= 400:
        # Тело ошибки может содержать полезное описание, но обрезаем его.
        raise ConnectorError(f"{system}: ошибка HTTP {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except ValueError as exc:
        raise ConnectorError(f"{system}: ответ не в формате JSON") from exc


def clip(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    if len(text) > MAX_RESPONSE_CHARS:
        return text[:MAX_RESPONSE_CHARS] + f"\n…[обрезано, всего {len(text)} символов — уточните запрос]"
    return text
