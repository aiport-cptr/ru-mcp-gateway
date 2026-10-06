"""Стабильные коды ошибок шлюза и номер запроса (correlation ID).

Каждый вызов инструмента получает номер запроса `rq-…`. Он попадает в ответ модели при
ошибке, в журнал аудита и в лог сервера. Сотрудник пересылает администратору код и номер —
администратор находит подробности командой `rugw audit list --request rq-…`, а сырые ответы
внешних систем при этом наружу не уходят.

Коды стабильны: их можно использовать в инструкциях и скриптах. Новые коды добавляются,
существующие не меняют смысла.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar
from enum import StrEnum


class ErrorCode(StrEnum):
    BAD_INPUT = "BAD_INPUT"  # некорректные аргументы инструмента
    ACCESS_DENIED = "ACCESS_DENIED"  # нет прав в шлюзе (роль, коннектор, ресурс)
    RELOGIN_REQUIRED = "RELOGIN_REQUIRED"  # нужен повторный вход через Яндекс
    UPSTREAM_AUTH = "UPSTREAM_AUTH"  # внешняя система отклонила учётные данные коннектора (401/403)
    UPSTREAM_NOT_FOUND = "UPSTREAM_NOT_FOUND"  # 404
    UPSTREAM_RATE_LIMIT = "UPSTREAM_RATE_LIMIT"  # 429
    UPSTREAM_BAD_REQUEST = "UPSTREAM_BAD_REQUEST"  # прочие 4xx
    UPSTREAM_ERROR = "UPSTREAM_ERROR"  # 5xx или ошибка в теле ответа
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"  # сеть, DNS, TLS
    UPSTREAM_BAD_RESPONSE = "UPSTREAM_BAD_RESPONSE"  # ответ не в ожидаемом формате
    INTERNAL = "INTERNAL"  # ошибка в самом шлюзе


_request_id: ContextVar[str | None] = ContextVar("rugw_request_id", default=None)


def new_request_id() -> str:
    return "rq-" + secrets.token_hex(6)


def set_request_id(rid: str | None):
    return _request_id.set(rid)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def current_request_id() -> str | None:
    return _request_id.get()


def tag(message: str, code: ErrorCode, request_id: str | None) -> str:
    """Текст ошибки для модели: сообщение + код + номер запроса."""
    suffix = f"код {code.value}" + (f", запрос {request_id}" if request_id else "")
    return f"{message} [{suffix}]"
