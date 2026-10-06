"""Конфигурация шлюза.

Принцип: fail-closed. Если конфигурация небезопасна, процесс не стартует.
Режима «авторизация выключена» нет вообще — ни флагом, ни переменной.
"""

from __future__ import annotations

import ipaddress
import re
from functools import cached_property
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_MARKERS = ("change-me", "changeme", "example.com", "example.ru", "<", ">")
ROLES = ("admin", "member", "readonly")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RUGW_", env_file=".env", extra="ignore")

    # --- Публичные адреса ---
    public_url: str = Field(description="Внешний адрес шлюза, например https://mcp.company.ru")

    # --- Режим разработки: разрешает http только для localhost ---
    dev_mode: bool = False

    # --- База ---
    database_url: str = Field(description="postgresql+asyncpg://... или sqlite+aiosqlite:///... (только dev)")

    # --- Вход через Яндекс ---
    yandex_client_id: str
    yandex_client_secret: SecretStr
    yandex_oauth_base: str = "https://oauth.yandex.ru"
    yandex_login_base: str = "https://login.yandex.ru"

    # --- Кого пускать ---
    # Через запятую: домены почты (company.ru) и/или точные адреса.
    allowed_email_domains: str = ""
    allowed_emails: str = ""
    # Адреса, которые при первом входе получают роль admin.
    bootstrap_admin_emails: str = ""
    # Роль для новых пользователей из разрешённых доменов.
    default_role: str = "readonly"

    # --- Время жизни ---
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 30 * 24 * 3600
    auth_code_ttl_seconds: int = 300
    pending_login_ttl_seconds: int = 600

    # --- Коннекторы (сервисные учётные данные, MVP) ---
    tracker_token: SecretStr | None = None
    tracker_org_id: str | None = None
    tracker_org_kind: str = "360"  # "360" -> X-Org-ID, "cloud" -> X-Cloud-Org-ID
    tracker_api_base: str = "https://api.tracker.yandex.net/v3"
    # service — общий токен tracker_token; user — токен Яндекса каждого сотрудника (docs/design/0.3-access.md)
    tracker_auth_mode: Literal["service", "user"] = "service"

    # --- Доступ от имени пользователя ---
    # Дополнительные права Яндекса, запрашиваемые при входе, например "tracker:read tracker:write".
    yandex_extra_scopes: str = ""
    # Ключи Fernet через запятую: первый шифрует, любой расшифровывает (ротация).
    # Сгенерировать: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    token_encryption_keys: SecretStr | None = None

    bitrix24_webhook_url: SecretStr | None = None

    onec_odata_url: str | None = None
    onec_username: str | None = None
    onec_password: SecretStr | None = None

    # --- Аудит ---
    audit_max_arg_chars: int = 2000
    # Сколько дней хранить журнал аудита; 0 — бессрочно.
    audit_retention_days: int = Field(default=365, ge=0)

    # --- Обслуживание ---
    cleanup_interval_seconds: int = Field(default=3600, ge=60)

    # --- Ограничение частоты запросов (в минуту) ---
    rate_limit_enabled: bool = True
    rate_register_per_minute: int = Field(default=10, ge=1)  # на IP
    rate_auth_per_minute: int = Field(default=30, ge=1)  # /authorize, /token, /revoke, /auth/* на IP
    rate_mcp_per_minute: int = Field(default=300, ge=1)  # /mcp на токен (или IP без токена)
    # Прокси, которым верим в X-Forwarded-For (CIDR через запятую).
    # По умолчанию: localhost и сеть Docker по умолчанию (Caddy на хосте → контейнер).
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128,172.16.0.0/12"

    # ------------------------------------------------------------------ validators

    @field_validator("default_role")
    @classmethod
    def _role_known(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"default_role должен быть одним из {ROLES}")
        if v == "admin":
            raise ValueError("default_role=admin запрещён: админы назначаются явно")
        return v

    @field_validator("yandex_extra_scopes")
    @classmethod
    def _scopes_valid(cls, v: str) -> str:
        for scope in v.split():
            if not re.fullmatch(r"[a-z0-9_]+:[a-z0-9_]+", scope):
                raise ValueError(f"Некорректное право Яндекса: {scope!r} (ожидается вида tracker:read)")
            if scope in ("login:email", "login:info"):
                raise ValueError(f"{scope} запрашивается всегда, указывать не нужно")
        return v

    @field_validator("token_encryption_keys")
    @classmethod
    def _keys_valid(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None or not v.get_secret_value().strip():
            return None
        from cryptography.fernet import Fernet

        for key in v.get_secret_value().split(","):
            try:
                Fernet(key.strip())
            except (ValueError, TypeError) as exc:
                raise ValueError("token_encryption_keys: каждый ключ должен быть ключом Fernet") from exc
        return v

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def _cidrs_valid(cls, v: str) -> str:
        for part in v.split(","):
            if part.strip():
                ipaddress.ip_network(part.strip(), strict=False)  # ValueError при ошибке
        return v

    @model_validator(mode="after")
    def _fail_closed(self) -> Settings:
        url = urlparse(self.public_url)
        if url.scheme not in ("http", "https") or not url.hostname:
            raise ValueError("public_url должен быть полным URL")
        if url.path not in ("", "/"):
            raise ValueError("public_url не должен содержать путь")
        local = url.hostname in ("localhost", "127.0.0.1", "::1")
        if url.scheme != "https" and not (self.dev_mode and local):
            raise ValueError("public_url должен быть https (http допустим только при dev_mode и localhost)")
        if self.dev_mode and not local:
            raise ValueError("dev_mode разрешён только для localhost")
        if not self.dev_mode:
            for marker in PLACEHOLDER_MARKERS:
                if marker in self.public_url:
                    raise ValueError("public_url похож на заглушку из примера")
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite допустим только в dev_mode")
        secret = self.yandex_client_secret.get_secret_value()
        if not secret or any(m in secret.lower() for m in PLACEHOLDER_MARKERS):
            raise ValueError("yandex_client_secret не задан или похож на заглушку")
        if self.tracker_auth_mode == "user":
            if self.token_encryption_keys is None:
                raise ValueError("tracker_auth_mode=user требует token_encryption_keys")
            if not set(self.yandex_extra_scopes.split()) & {"tracker:read", "tracker:write"}:
                raise ValueError("tracker_auth_mode=user требует tracker:read или tracker:write в yandex_extra_scopes")
            if not self.tracker_org_id:
                raise ValueError("tracker_auth_mode=user требует tracker_org_id")
        if not (self.allowed_domains or self.allowed_email_set or self.bootstrap_admins):
            raise ValueError("Не задан ни один разрешённый домен или адрес — войти будет некому")
        return self

    # ------------------------------------------------------------------ helpers

    @property
    def issuer_url(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def resource_url(self) -> str:
        return f"{self.issuer_url}/mcp"

    @property
    def yandex_callback_url(self) -> str:
        return f"{self.issuer_url}/auth/yandex/callback"

    @property
    def public_host(self) -> str:
        u = urlparse(self.public_url)
        return u.netloc

    @staticmethod
    def _csv(value: str) -> frozenset[str]:
        return frozenset(x.strip().lower() for x in value.split(",") if x.strip())

    @cached_property
    def allowed_domains(self) -> frozenset[str]:
        return self._csv(self.allowed_email_domains)

    @cached_property
    def allowed_email_set(self) -> frozenset[str]:
        return self._csv(self.allowed_emails)

    @cached_property
    def bootstrap_admins(self) -> frozenset[str]:
        return self._csv(self.bootstrap_admin_emails)

    @cached_property
    def trusted_proxies(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(
            ipaddress.ip_network(p.strip(), strict=False) for p in self.trusted_proxy_cidrs.split(",") if p.strip()
        )
