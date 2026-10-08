"""Токены служебных интеграций (Диадок и т.п.) — зашифрованно, с поколением для CAS.

Тот же подход, что у токенов сотрудников (credentials.py, разбор проверки 0.3):
- значение хранится только зашифрованным (ключи RUGW_TOKEN_ENCRYPTION_KEYS);
- вход администратора (`rugw diadoc login`) записывает безусловно и увеличивает поколение;
- обновление по refresh записывает результат только если поколение не изменилось (CAS)
  и никогда не создаёт запись заново.
"""

from __future__ import annotations

import time

from cryptography.fernet import InvalidToken
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from rugw.config import Settings
from rugw.credentials import TokenCipher
from rugw.db import Database, ServiceCredential


class ServiceSecretUnavailable(Exception):  # noqa: N818
    pass


class ServiceSecrets:
    def __init__(self, db: Database, cipher: TokenCipher) -> None:
        self.db = db
        self.cipher = cipher

    async def get(self, provider: str) -> tuple[str, int]:
        async with self.db.session() as s:
            row = await s.get(ServiceCredential, provider)
            if row is None:
                raise ServiceSecretUnavailable("не выполнен вход администратора")
            try:
                return self.cipher.decrypt(row.secret_enc), row.generation
            except InvalidToken as exc:
                raise ServiceSecretUnavailable("сохранённый токен не читается (сменили ключ шифрования?)") from exc

    async def put(self, provider: str, secret: str) -> None:
        """Безусловная запись (вход администратора)."""
        enc = self.cipher.encrypt(secret)
        for attempt in range(2):
            try:
                async with self.db.session() as s:
                    row = await s.get(ServiceCredential, provider, with_for_update=True)
                    if row is None:
                        s.add(
                            ServiceCredential(provider=provider, secret_enc=enc, generation=1, updated_at=time.time())
                        )
                    else:
                        row.secret_enc = enc
                        row.generation = (row.generation or 0) + 1
                        row.updated_at = time.time()
                return
            except IntegrityError:
                if attempt:
                    raise

    async def cas(self, provider: str, generation: int, secret: str) -> bool:
        async with self.db.session() as s:
            res = await s.execute(
                update(ServiceCredential)
                .where(ServiceCredential.provider == provider, ServiceCredential.generation == generation)
                .values(secret_enc=self.cipher.encrypt(secret), generation=generation + 1, updated_at=time.time())
            )
            return res.rowcount == 1

    async def delete(self, provider: str) -> None:
        async with self.db.session() as s:
            row = await s.get(ServiceCredential, provider)
            if row is not None:
                await s.delete(row)


def build_service_secrets(settings: Settings, db: Database) -> ServiceSecrets | None:
    if settings.token_encryption_keys is None:
        return None
    return ServiceSecrets(db, TokenCipher(settings.token_encryption_keys))
