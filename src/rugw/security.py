"""Генерация и хеширование секретов, редактирование логов."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any

TOKEN_BYTES = 32  # 256 бит энтропии


def new_secret() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_secret(value: str) -> str:
    """SHA-256 достаточен: значения случайные и длинные, перебор бессмыслен."""
    return hashlib.sha256(value.encode()).hexdigest()


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


_SECRET_KEYS = re.compile(r"(token|secret|password|passwd|authorization|cookie|api[_-]?key|code)", re.I)


def redact(value: Any) -> Any:
    """Скрывает значения под ключами, похожими на секреты."""
    if isinstance(value, dict):
        return {k: ("***" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def audit_dump(args: dict[str, Any], limit: int) -> str:
    text = json.dumps(redact(args), ensure_ascii=False, default=str)
    if len(text) > limit:
        text = text[:limit] + f"…(+{len(text) - limit})"
    return text
