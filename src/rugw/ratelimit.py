"""Ограничение частоты запросов (token bucket в памяти процесса).

Рассчитано на один экземпляр шлюза. При нескольких репликах лимит действует
на каждую отдельно — для этого случая нужен общий счётчик (Redis), см. ROADMAP.

Ключ:
  /register                         — IP клиента
  /authorize, /token, /revoke, /auth — IP клиента
  /mcp                              — хеш токена (или IP, если токена нет) и, дополнительно,
                                      IP с лимитом ×5: перебор случайных токенов с одного адреса
                                      не обходит ограничение (офис за одним NAT при этом не страдает)

IP берётся из X-Forwarded-For, только если соединение пришло от доверенного прокси;
иначе — адрес соединения. Из X-Forwarded-For берётся самый правый адрес,
который не является доверенным прокси (левые части клиент может подделать).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import time
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from rugw.config import Settings
from rugw.security import hash_secret

log = logging.getLogger(__name__)

MAX_KEYS = 50_000  # защита памяти от перебора ключей


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBuckets:
    def __init__(self, per_minute: int, clock=time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.clock = clock
        self._b: dict[str, _Bucket] = {}

    def take(self, key: str) -> float:
        """0 — запрос разрешён; иначе — через сколько секунд повторить."""
        now = self.clock()
        b = self._b.get(key)
        if b is None:
            if len(self._b) >= MAX_KEYS:
                self._prune(now)
            b = self._b[key] = _Bucket(self.capacity, now)
        else:
            b.tokens = min(self.capacity, b.tokens + (now - b.updated) * self.rate)
            b.updated = now
        if b.tokens >= 1:
            b.tokens -= 1
            return 0.0
        return (1 - b.tokens) / self.rate

    def _prune(self, now: float) -> None:
        # Удаляем вёдра, которые уже успели наполниться: их состояние равно новому.
        full_after = self.capacity / self.rate
        stale = [k for k, b in self._b.items() if now - b.updated >= full_after]
        for k in stale:
            del self._b[k]
        if len(self._b) >= MAX_KEYS:  # под атакой: сбрасываем самые старые
            for k, _ in sorted(self._b.items(), key=lambda kv: kv[1].updated)[: MAX_KEYS // 10]:
                del self._b[k]


def client_ip(scope: Scope, trusted: tuple) -> str:
    peer = (scope.get("client") or ("0.0.0.0", 0))[0]  # noqa: S104 — значение-заглушка, не bind

    def is_trusted(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in trusted)

    if not is_trusted(peer):
        return peer
    xff = ""
    for name, value in scope.get("headers") or []:
        if name == b"x-forwarded-for":
            xff = (xff + "," if xff else "") + value.decode("latin-1")
    for candidate in reversed([p.strip() for p in xff.split(",") if p.strip()]):
        if not is_trusted(candidate):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return peer  # мусор в заголовке — не доверяем
    return peer


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings, clock=time.monotonic) -> None:
        self.app = app
        self.trusted = settings.trusted_proxies
        self.register = TokenBuckets(settings.rate_register_per_minute, clock)
        self.auth = TokenBuckets(settings.rate_auth_per_minute, clock)
        self.mcp = TokenBuckets(settings.rate_mcp_per_minute, clock)
        self.mcp_ip = TokenBuckets(settings.rate_mcp_per_minute * 5, clock)

    def _classify(self, scope: Scope) -> list[tuple[TokenBuckets, str]]:
        path: str = scope.get("path", "")
        if path == "/register":
            return [(self.register, "ip:" + client_ip(scope, self.trusted))]
        if path in ("/authorize", "/token", "/revoke") or path.startswith("/auth/"):
            return [(self.auth, "ip:" + client_ip(scope, self.trusted))]
        if path == "/mcp" or path.startswith("/mcp/"):
            ip = "ip:" + client_ip(scope, self.trusted)
            for name, value in scope.get("headers") or []:
                if name == b"authorization" and value[:7].lower() == b"bearer ":
                    return [(self.mcp_ip, ip), (self.mcp, "tok:" + hash_secret(value[7:].decode("latin-1")))]
            return [(self.mcp_ip, ip), (self.mcp, ip)]
        return []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for buckets, key in self._classify(scope):
            wait = buckets.take(key)
            if wait > 0:
                retry = str(max(1, math.ceil(wait)))
                log.warning("rate limited path=%s key=%s", scope.get("path"), key[:20])
                body = json.dumps(
                    {"error": "rate_limited", "error_description": "Слишком много запросов, повторите позже"},
                    ensure_ascii=False,
                ).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": [
                            (b"content-type", b"application/json; charset=utf-8"),
                            (b"retry-after", retry.encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)
