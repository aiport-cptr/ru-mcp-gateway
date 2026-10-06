"""Хранилище токенов Яндекса сотрудников для доступа «от имени пользователя».

- Токены шифруются Fernet (AES-128-CBC + HMAC-SHA256) ключами RUGW_TOKEN_ENCRYPTION_KEYS.
  Первый ключ шифрует, любой расшифровывает — так меняется ключ без потери токенов.
- Расшифрованный токен живёт только в памяти на время вызова инструмента.
- Истёкший токен обновляется по refresh-токену Яндекса и пересохраняется.
- Два одновременных обновления одного пользователя сериализуются блокировкой в процессе.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import SecretStr
from sqlalchemy import delete, select

from rugw.auth.yandex import YandexAuthError, YandexOAuth, YandexTokens
from rugw.config import Settings
from rugw.db import Database, UserCredential

log = logging.getLogger(__name__)

PROVIDER_YANDEX = "yandex"
REFRESH_MARGIN_SECONDS = 300  # обновляем заранее, чтобы токен не истёк посреди запроса


class CredentialsUnavailable(Exception):  # noqa: N818
    """Нет пригодного токена пользователя — нужно войти в шлюз заново."""


class TokenCipher:
    def __init__(self, keys: SecretStr) -> None:
        parts = [k.strip() for k in keys.get_secret_value().split(",") if k.strip()]
        if not parts:
            raise ValueError("Нужен хотя бы один ключ шифрования")
        self._f = MultiFernet([Fernet(k) for k in parts])

    def encrypt(self, value: str) -> str:
        return self._f.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        return self._f.decrypt(value.encode()).decode()

    def rotate(self, value: str) -> str:
        """Перешифровать первым (новым) ключом."""
        return self._f.rotate(value.encode()).decode()


class YandexCredentials:
    def __init__(self, db: Database, cipher: TokenCipher, yandex: YandexOAuth, scopes: str) -> None:
        self.db = db
        self.cipher = cipher
        self.yandex = yandex
        self.scopes = scopes
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def save(self, user_id: int, tokens: YandexTokens) -> None:
        expires_at = time.time() + tokens.expires_in if tokens.expires_in else None
        async with self.db.session() as s:
            row = await s.get(UserCredential, (user_id, PROVIDER_YANDEX))
            refresh_enc = self.cipher.encrypt(tokens.refresh_token) if tokens.refresh_token else None
            if row is None:
                s.add(
                    UserCredential(
                        user_id=user_id,
                        provider=PROVIDER_YANDEX,
                        access_token_enc=self.cipher.encrypt(tokens.access_token),
                        refresh_token_enc=refresh_enc,
                        expires_at=expires_at,
                        scopes=self.scopes,
                        updated_at=time.time(),
                    )
                )
            else:
                row.access_token_enc = self.cipher.encrypt(tokens.access_token)
                # Яндекс может не прислать новый refresh при обновлении — тогда сохраняем прежний.
                if refresh_enc is not None:
                    row.refresh_token_enc = refresh_enc
                row.expires_at = expires_at
                row.scopes = self.scopes
                row.updated_at = time.time()

    async def delete(self, user_id: int) -> None:
        async with self.db.session() as s:
            await s.execute(delete(UserCredential).where(UserCredential.user_id == user_id))

    async def access_token(self, user_id: int) -> str:
        async with self._locks[user_id]:
            async with self.db.session() as s:
                row = await s.get(UserCredential, (user_id, PROVIDER_YANDEX))
                if row is None:
                    raise CredentialsUnavailable("нет сохранённого доступа")
                if not set(self.scopes.split()) <= set(row.scopes.split()):
                    raise CredentialsUnavailable("доступ выдан с меньшим набором прав")
                try:
                    access = self.cipher.decrypt(row.access_token_enc)
                    refresh = self.cipher.decrypt(row.refresh_token_enc) if row.refresh_token_enc else None
                except InvalidToken as exc:
                    # Ключ шифрования сменили без перешифровки — сохранённые токены не прочитать.
                    log.error("cannot decrypt credentials of user_id=%s: unknown key", user_id)
                    raise CredentialsUnavailable("сохранённый доступ не читается") from exc
                expires_at = row.expires_at

            if expires_at is None or expires_at - REFRESH_MARGIN_SECONDS > time.time():
                return access
            if refresh is None:
                raise CredentialsUnavailable("срок доступа истёк")
            try:
                tokens = await self.yandex.refresh(refresh)
            except YandexAuthError as exc:
                log.warning("yandex token refresh failed for user_id=%s: %s", user_id, exc)
                raise CredentialsUnavailable("не удалось обновить доступ") from exc
            await self.save(user_id, tokens)
            return tokens.access_token


async def rotate_all(db: Database, cipher: TokenCipher) -> int:
    """Перешифровать все сохранённые токены первым ключом. Возвращает число записей."""
    n = 0
    async with db.session() as s:
        for row in (await s.execute(select(UserCredential))).scalars():
            row.access_token_enc = cipher.rotate(row.access_token_enc)
            if row.refresh_token_enc:
                row.refresh_token_enc = cipher.rotate(row.refresh_token_enc)
            n += 1
    return n


def build_credentials(settings: Settings, db: Database, yandex: YandexOAuth) -> YandexCredentials | None:
    """Хранилище включается, если заданы ключ шифрования и дополнительные права Яндекса."""
    if settings.token_encryption_keys is None or not settings.yandex_extra_scopes.split():
        return None
    return YandexCredentials(db, TokenCipher(settings.token_encryption_keys), yandex, settings.yandex_extra_scopes)
