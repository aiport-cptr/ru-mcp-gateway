"""Минимальный клиент Яндекс OAuth: только чтобы узнать, кто вошёл.

Токен Яндекса используется один раз для запроса профиля и нигде не сохраняется.
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
            "scope": "login:email login:info",
            "force_confirm": "no",
        }
        return f"{self.s.yandex_oauth_base}/authorize?{urlencode(q)}"

    async def identify(self, code: str, code_verifier: str) -> YandexIdentity:
        try:
            r = await self.http.post(
                f"{self.s.yandex_oauth_base}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self.s.yandex_client_id,
                    "client_secret": self.s.yandex_client_secret.get_secret_value(),
                    "code_verifier": code_verifier,
                },
                timeout=15,
            )
        except httpx.HTTPError as exc:
            raise YandexAuthError("Яндекс OAuth недоступен") from exc
        if r.status_code != 200:
            raise YandexAuthError(f"Яндекс отклонил код (HTTP {r.status_code})")
        access = r.json().get("access_token")
        if not access:
            raise YandexAuthError("Яндекс не вернул access_token")

        try:
            info = await self.http.get(
                f"{self.s.yandex_login_base}/info",
                params={"format": "json"},
                headers={"Authorization": f"OAuth {access}"},
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
