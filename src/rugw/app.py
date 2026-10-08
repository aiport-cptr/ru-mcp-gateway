"""Сборка приложения: MCP-сервер + OAuth + маршруты входа + /healthz."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

import httpx
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from rugw import __version__
from rugw.access import current_permissions
from rugw.audit import Auditor
from rugw.auth.provider import GATEWAY_SCOPE, GatewayOAuthProvider
from rugw.auth.routes import AuthRoutes
from rugw.auth.yandex import YandexOAuth
from rugw.config import Settings
from rugw.connectors import build_all
from rugw.credentials import build_credentials
from rugw.db import Database
from rugw.maintenance import cleanup_loop
from rugw.migrate import current_revision, head_revision
from rugw.policy import Level, role_allows
from rugw.ratelimit import RateLimitMiddleware
from rugw.service_credentials import build_service_secrets
from rugw.tools import GatewayServer, ToolSpec, current_actor, register

log = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Корпоративный шлюз к системам компании (Яндекс Трекер, Битрикс24, 1С и др.). "
    "Видны только инструменты, разрешённые вашей роли. Перед записью (уровень write) "
    "покажите пользователю, что именно будет изменено, и дождитесь подтверждения."
)


def build_app(
    settings: Settings,
    http: httpx.AsyncClient | None = None,
    extra_tools: list[ToolSpec] | None = None,
) -> Starlette:
    http = http or httpx.AsyncClient(headers={"User-Agent": f"ru-mcp-gateway/{__version__}"})
    db = Database(settings.database_url)
    auditor = Auditor(db)
    yandex = YandexOAuth(settings, http)
    provider = GatewayOAuthProvider(settings, db, yandex)
    credentials = build_credentials(settings, db, yandex)
    secrets = build_service_secrets(settings, db)
    routes = AuthRoutes(settings, db, yandex, provider, auditor, credentials)

    server = GatewayServer(
        name="ru-mcp-gateway",
        version=__version__,
        instructions=INSTRUCTIONS,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=settings.issuer_url,
            resource_server_url=settings.resource_url,
            validate_token_resource=True,
            required_scopes=[GATEWAY_SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[GATEWAY_SCOPE], default_scopes=[GATEWAY_SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
        db=db,
    )

    # ---- инструменты самого шлюза
    async def gateway_whoami() -> dict:
        """Кто я в шлюзе: email, роль и к каким ресурсам коннекторов у меня есть доступ."""
        actor = await current_actor(db)
        if actor is None:
            return {}
        perms = current_permissions()
        if perms.is_admin:
            access: object = "все ресурсы всех коннекторов"
        else:
            access = [
                {"connector": r.connector, "resource": r.resource, "level": r.level.value}
                for r in perms.rules
                if role_allows(actor.role, r.level)  # право выше потолка роли не показываем как доступное
            ]
        return {"email": actor.email, "role": actor.role, "access": access}

    register(server, ToolSpec("gateway_whoami", Level.READ, gateway_whoami, gateway_whoami.__doc__), settings, auditor)

    # ---- коннекторы
    specs = build_all(settings, http, credentials, secrets) + list(extra_tools or [])
    for spec in specs:
        register(server, spec, settings, auditor)
    log.info("connectors: %d tools enabled: %s", len(specs), ", ".join(s.name for s in specs) or "—")

    # ---- маршруты
    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        # Авторизация в этом шлюзе не отключается; поле оставлено для совместимости проверок.
        return JSONResponse({"ok": True, "auth_enabled": True, "version": __version__})

    server.custom_route("/auth/yandex/callback", methods=["GET"])(routes.yandex_callback)
    server.custom_route("/auth/consent", methods=["POST"])(routes.consent)

    app = server.streamable_http_app(
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[settings.public_host],
            allowed_origins=[settings.issuer_url],
        ),
    )

    if settings.rate_limit_enabled:
        # Внешний слой: отсекаем поток запросов до проверки токенов и обращений к базе.
        app.add_middleware(RateLimitMiddleware, settings=settings)

    inner_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a: Starlette) -> AsyncIterator[None]:
        current, head = await current_revision(db), head_revision()
        if current != head:
            raise RuntimeError(f"Схема базы {current or 'пустая'}, нужна {head}. Выполните: python -m rugw migrate")
        cleaner = asyncio.create_task(cleanup_loop(db, settings), name="rugw-cleanup")
        async with inner_lifespan(a):
            try:
                yield
            finally:
                cleaner.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await cleaner
                await http.aclose()
                await db.dispose()

    app.router.lifespan_context = lifespan
    app.state.db = db
    app.state.settings = settings
    app.state.provider = provider
    app.state.server = server
    app.state.auditor = auditor
    app.state.credentials = credentials
    app.state.secrets = secrets
    return app
