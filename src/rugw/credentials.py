"""Хранилище токенов Яндекса сотрудников для доступа «от имени пользователя».

- Токены шифруются Fernet (AES-128-CBC + HMAC-SHA256) ключами RUGW_TOKEN_ENCRYPTION_KEYS.
  Первый ключ шифрует, любой расшифровывает — так меняется ключ без потери токенов.
- Расшифрованный токен живёт только в памяти на время вызова инструмента.
- Истёкший токен обновляется по refresh-токену Яндекса и пересохраняется.

Согласованность (в том числе между несколькими процессами шлюза):
- Новый вход (save) пишет токены, только если пользователь не заблокирован, держа блокировку
  строки пользователя (SELECT … FOR UPDATE) — так он не пересекается с `users disable`.
- Обновление по refresh пишет результат условным UPDATE по поколению записи (CAS) и никогда
  не создаёт запись заново. Если запись удалили (блокировка) или заменили (новый вход) —
  результат обновления отбрасывается, берётся актуальное состояние.
- Блокировка asyncio.Lock на пользователя — только чтобы в одном процессе не ходить в Яндекс
  дважды; корректность от неё не зависит.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import SecretStr
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from rugw.auth.yandex import YandexAuthError, YandexOAuth, YandexTokens
from rugw.config import Settings
from rugw.db import Database, User, UserCredential

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

    def _encrypted(self, tokens: YandexTokens) -> dict:
        values = {
            "access_token_enc": self.cipher.encrypt(tokens.access_token),
            "expires_at": time.time() + tokens.expires_in if tokens.expires_in else None,
            "scopes": self.scopes,
            "updated_at": time.time(),
        }
        # Яндекс может не прислать новый refresh при обновлении — тогда прежний остаётся.
        if tokens.refresh_token:
            values["refresh_token_enc"] = self.cipher.encrypt(tokens.refresh_token)
        return values

    async def save(self, user_id: int, tokens: YandexTokens) -> bool:
        """Сохранить токены нового входа. False — пользователь заблокирован или удалён, ничего не записано."""
        values = self._encrypted(tokens)
        for attempt in range(2):
            try:
                async with self.db.session() as s:
                    # Блокировка строки пользователя: `users disable` (UPDATE users) ждёт нас или мы — его.
                    user = (
                        await s.execute(select(User).where(User.id == user_id).with_for_update())
                    ).scalar_one_or_none()
                    if user is None or user.disabled:
                        return False
                    row = await s.get(UserCredential, (user_id, PROVIDER_YANDEX), with_for_update=True)
                    if row is None:
                        s.add(UserCredential(user_id=user_id, provider=PROVIDER_YANDEX, generation=1, **values))
                    else:
                        for key, value in values.items():
                            setattr(row, key, value)
                        if "refresh_token_enc" not in values:
                            row.refresh_token_enc = None  # у нового входа нет refresh — старый не нужен
                        row.generation = (row.generation or 0) + 1
                return True
            except IntegrityError:
                # Параллельный вход того же пользователя успел вставить запись — повторяем как обновление.
                if attempt:
                    raise
        return False  # недостижимо; для анализатора

    async def _save_refreshed(self, user_id: int, generation: int, tokens: YandexTokens) -> bool:
        """CAS: записать результат обновления, только если запись не менялась с момента чтения."""
        async with self.db.session() as s:
            res = await s.execute(
                update(UserCredential)
                .where(
                    UserCredential.user_id == user_id,
                    UserCredential.provider == PROVIDER_YANDEX,
                    UserCredential.generation == generation,
                )
                .values(**self._encrypted(tokens), generation=generation + 1)
            )
            return res.rowcount == 1

    async def delete(self, user_id: int) -> None:
        async with self.db.session() as s:
            await s.execute(delete(UserCredential).where(UserCredential.user_id == user_id))

    async def _read(self, user_id: int) -> tuple[str, str | None, float | None, int]:
        """(access, refresh, expires_at, generation) или CredentialsUnavailable."""
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
            return access, refresh, row.expires_at, row.generation

    @staticmethod
    def _fresh(expires_at: float | None) -> bool:
        return expires_at is None or expires_at - REFRESH_MARGIN_SECONDS > time.time()

    async def access_token(self, user_id: int) -> str:
        async with self._locks[user_id]:
            access, refresh, expires_at, generation = await self._read(user_id)
            if self._fresh(expires_at):
                return access
            if refresh is None:
                raise CredentialsUnavailable("срок доступа истёк")
            try:
                tokens = await self.yandex.refresh(refresh)
            except YandexAuthError as exc:
                log.warning("yandex token refresh failed for user_id=%s: %s", user_id, exc)
                raise CredentialsUnavailable("не удалось обновить доступ") from exc
            if await self._save_refreshed(user_id, generation, tokens):
                return tokens.access_token
            # Пока ждали Яндекс, запись удалили (блокировка) или заменили (новый вход):
            # результат обновления устарел — не сохраняем и не используем его.
            log.info("credentials of user_id=%s changed during refresh; refreshed tokens discarded", user_id)
            access, _, expires_at, _ = await self._read(user_id)  # нет записи → CredentialsUnavailable
            if self._fresh(expires_at):
                return access
            raise CredentialsUnavailable("доступ изменился во время обновления, повторите запрос")


async def rotate_all(db: Database, cipher: TokenCipher) -> int:
    """Перешифровать первым ключом все токены: сотрудников и служебных интеграций. Возвращает число записей."""
    from rugw.db import ServiceCredential

    n = 0
    async with db.session() as s:
        for row in (await s.execute(select(UserCredential))).scalars():
            row.access_token_enc = cipher.rotate(row.access_token_enc)
            if row.refresh_token_enc:
                row.refresh_token_enc = cipher.rotate(row.refresh_token_enc)
            n += 1
        for srow in (await s.execute(select(ServiceCredential))).scalars():
            srow.secret_enc = cipher.rotate(srow.secret_enc)
            n += 1
    return n


def build_credentials(settings: Settings, db: Database, yandex: YandexOAuth) -> YandexCredentials | None:
    """Хранилище включается, если заданы ключ шифрования и дополнительные права Яндекса."""
    if settings.token_encryption_keys is None or not settings.yandex_extra_scopes.split():
        return None
    return YandexCredentials(db, TokenCipher(settings.token_encryption_keys), yandex, settings.yandex_extra_scopes)
