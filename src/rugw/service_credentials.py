"""Токены служебных интеграций (Диадок и т.п.) — зашифрованно, с версией для CAS.

Тот же подход, что у токенов сотрудников (credentials.py, разбор проверки 0.3):
- значение хранится только зашифрованным (ключи RUGW_TOKEN_ENCRYPTION_KEYS);
- вход администратора (`rugw diadoc login`) записывает безусловно и выдаёт новую версию;
- обновление по refresh записывает результат только если версия не изменилась (CAS)
  и никогда не создаёт запись заново. Версия — случайный uuid4, а не счётчик: после
  `diadoc logout` и нового входа она не может совпасть со старой (ABA, проверка 0.4.1).
"""

from __future__ import annotations

import time

from cryptography.fernet import InvalidToken
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from rugw.config import Settings
from rugw.credentials import TokenCipher, new_version
from rugw.db import Database, ServiceCredential


class ServiceSecretUnavailable(Exception):  # noqa: N818
    pass


class ServiceSecrets:
    def __init__(self, db: Database, cipher: TokenCipher) -> None:
        self.db = db
        self.cipher = cipher

    async def get(self, provider: str) -> tuple[str, str]:
        """(секрет, версия записи) или ServiceSecretUnavailable."""
        async with self.db.session() as s:
            row = await s.get(ServiceCredential, provider)
            if row is None:
                raise ServiceSecretUnavailable("не выполнен вход администратора")
            try:
                return self.cipher.decrypt(row.secret_enc), row.version
            except InvalidToken as exc:
                raise ServiceSecretUnavailable("сохранённый токен не читается (сменили ключ шифрования?)") from exc

    async def version(self, provider: str) -> str | None:
        """Текущая версия записи без расшифровки; None — записи нет (выполнен logout)."""
        async with self.db.session() as s:
            row = await s.get(ServiceCredential, provider)
            return None if row is None else row.version

    async def put(self, provider: str, secret: str) -> str:
        """Безусловная запись (вход администратора). Возвращает новую версию."""
        enc = self.cipher.encrypt(secret)
        version = new_version()
        for attempt in range(2):
            try:
                async with self.db.session() as s:
                    row = await s.get(ServiceCredential, provider, with_for_update=True)
                    if row is None:
                        s.add(
                            ServiceCredential(
                                provider=provider, secret_enc=enc, generation=1, version=version, updated_at=time.time()
                            )
                        )
                    else:
                        row.secret_enc = enc
                        row.generation = (row.generation or 0) + 1
                        row.version = version
                        row.updated_at = time.time()
                return version
            except IntegrityError:
                if attempt:
                    raise
        raise RuntimeError("недостижимо")

    async def cas(self, provider: str, version: str, secret: str) -> str | None:
        """Записать secret, только если версия записи всё ещё version. Возвращает новую версию или None."""
        if not version:
            return None
        new = new_version()
        async with self.db.session() as s:
            res = await s.execute(
                update(ServiceCredential)
                .where(ServiceCredential.provider == provider, ServiceCredential.version == version)
                .values(
                    secret_enc=self.cipher.encrypt(secret),
                    generation=ServiceCredential.generation + 1,
                    version=new,
                    updated_at=time.time(),
                )
            )
            return new if res.rowcount == 1 else None

    async def delete(self, provider: str) -> None:
        async with self.db.session() as s:
            row = await s.get(ServiceCredential, provider)
            if row is not None:
                await s.delete(row)


def build_service_secrets(settings: Settings, db: Database) -> ServiceSecrets | None:
    if settings.token_encryption_keys is None:
        return None
    return ServiceSecrets(db, TokenCipher(settings.token_encryption_keys))
