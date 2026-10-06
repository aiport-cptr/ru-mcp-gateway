"""Клиент Яндекс OAuth: узнать, кто вошёл, и (в режиме «от имени пользователя»)
получить и обновлять токен Яндекса сотрудника.

Токен Яндекса сохраняется, только если включены дополнительные права
(RUGW_YANDEX_EXTRA_SCOPES), и только зашифрованным (credentials.py).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from rugw.config import Settings


@dataclass(frozen=True)
class YandexIdentity:
    yandex_id: str
    login: str
    email: str


@dataclass(frozen=True, repr=False)  # repr=False: токены не должны попасть в логи через repr
class YandexTokens:
    access_token: str
    refresh_token: str | None
    expires_in: int | None


def _parse_tokens(data: object) -> YandexTokens:
    if not isinstance(data, dict):
        raise YandexAuthError("Яндекс вернул неожиданный ответ")
    access = data.get("access_token")
    if not isinstance(access, str) or not access:
        raise YandexAuthError("Яндекс не вернул access_token")
    refresh = data.get("refresh_token")
    expires = data.get("expires_in")
    return YandexTokens(
        access_token=access,
        refresh_token=refresh if isinstance(refresh, str) and refresh else None,
        expires_in=int(expires) if isinstance(expires, int | float) and expires > 0 else None,
    )


class YandexAuthError(Exception):
    pass


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class YandexOAuth:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self.s = settings
        self.http = http

    def authorize_url(self, state: str, code_verifier: str) -> str:
        q = {
            "response_type": "code",
            "client_id": self.s.yandex_client_id,
            "redirect_uri": self.s.yandex_callback_url,
            "state": state,
            "code_challenge": pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
            "scope": " ".join(["login:email", "login:info", *self.s.yandex_extra_scopes.split()]),
            "force_confirm": "no",
        }
        return f"{self.s.yandex_oauth_base}/authorize?{urlencode(q)}"

    async def _token_request(self, data: dict) -> YandexTokens:
        try:
            r = await self.http.post(
                f"{self.s.yandex_oauth_base}/token",
                data={
                    **data,
                    "client_id": self.s.yandex_client_id,
                    "client_secret": self.s.yandex_client_secret.get_secret_value(),
                },
                timeout=15,
            )
        except httpx.HTTPError as exc:
            raise YandexAuthError("Яндекс OAuth недоступен") from exc
        if r.status_code != 200:
            raise YandexAuthError(f"Яндекс отклонил запрос токена (HTTP {r.status_code})")
        try:
            return _parse_tokens(r.json())
        except ValueError as exc:
            raise YandexAuthError("Яндекс вернул не JSON") from exc

    async def exchange_code(self, code: str, code_verifier: str) -> YandexTokens:
        return await self._token_request(
            {"grant_type": "authorization_code", "code": code, "code_verifier": code_verifier}
        )

    async def refresh(self, refresh_token: str) -> YandexTokens:
        return await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def profile(self, access_token: str) -> YandexIdentity:
        try:
            info = await self.http.get(
                f"{self.s.yandex_login_base}/info",
                params={"format": "json"},
                headers={"Authorization": f"OAuth {access_token}"},
                timeout=15,
            )
        except httpx.HTTPError as exc:
            raise YandexAuthError("Не удалось получить профиль Яндекса") from exc
        if info.status_code != 200:
            raise YandexAuthError(f"Профиль Яндекса недоступен (HTTP {info.status_code})")
        data = info.json()
        yid = str(data.get("id") or "")
        email = str(data.get("default_email") or "").strip().lower()
        login = str(data.get("login") or "")
        if not yid or not email:
            raise YandexAuthError("В профиле Яндекса нет id или email (нужны права login:email)")
        return YandexIdentity(yandex_id=yid, login=login, email=email)

    async def identify(self, code: str, code_verifier: str) -> tuple[YandexIdentity, YandexTokens]:
        tokens = await self.exchange_code(code, code_verifier)
        return await self.profile(tokens.access_token), tokens
