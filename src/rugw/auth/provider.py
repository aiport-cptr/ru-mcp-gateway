"""OAuth-сервер авторизации для MCP-клиентов.

Протокольную часть (/authorize, /token, /register, /revoke, metadata, PKCE)
делает официальный MCP SDK. Здесь — только хранилище и решения:

  1. Клиент зовёт /authorize → мы сохраняем запрос и отправляем браузер в Яндекс.
  2. Яндекс возвращает в /auth/yandex/callback → узнаём пользователя,
     проверяем допуск, показываем экран согласия (routes.py).
  3. Пользователь нажал «Разрешить» → выдаём одноразовый код клиенту.
  4. Клиент меняет код на access+refresh (здесь).
"""

from __future__ import annotations

import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from sqlalchemy import select, update

from rugw.auth.yandex import YandexOAuth
from rugw.config import Settings
from rugw.db import AuthCode, Database, Grant, OAuthClient, PendingLogin, Token, User
from rugw.security import hash_secret, new_secret

GATEWAY_SCOPE = "gateway"


class GatewayAuthCode(AuthorizationCode):
    user_id: int


class GatewayRefreshToken(RefreshToken):
    grant_id: int


class GatewayAccessToken(AccessToken):
    grant_id: int
    user_id: int


class GatewayOAuthProvider:
    def __init__(self, settings: Settings, db: Database, yandex: YandexOAuth) -> None:
        self.s = settings
        self.db = db
        self.yandex = yandex

    # ------------------------------------------------------------ clients (DCR)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        async with self.db.session() as s:
            row = await s.get(OAuthClient, client_id)
            return OAuthClientInformationFull.model_validate(row.info_json) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        async with self.db.session() as s:
            s.add(OAuthClient(client_id=client_info.client_id, info_json=client_info.model_dump(mode="json")))

    # ------------------------------------------------------------ authorize

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and params.resource.rstrip("/") != self.s.resource_url:
            raise AuthorizeError("invalid_target", "Неизвестный resource")
        state = new_secret()
        verifier = new_secret()
        payload = params.model_dump(mode="json")
        payload["_yandex_verifier"] = verifier
        async with self.db.session() as s:
            s.add(
                PendingLogin(
                    state_hash=hash_secret(state),
                    client_id=client.client_id,
                    params_json=payload,
                    expires_at=time.time() + self.s.pending_login_ttl_seconds,
                )
            )
        return self.yandex.authorize_url(state=state, code_verifier=verifier)

    async def issue_auth_code(self, pending: PendingLogin) -> tuple[str, dict]:
        """Вызывается после согласия пользователя. Возвращает (code, params)."""
        code = new_secret()
        params = {k: v for k, v in pending.params_json.items() if not k.startswith("_")}
        async with self.db.session() as s:
            s.add(
                AuthCode(
                    code_hash=hash_secret(code),
                    client_id=pending.client_id,
                    user_id=pending.user_id,
                    params_json=params,
                    expires_at=time.time() + self.s.auth_code_ttl_seconds,
                )
            )
        return code, params

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> GatewayAuthCode | None:
        async with self.db.session() as s:
            row = await s.get(AuthCode, hash_secret(authorization_code))
            if row is None or row.client_id != client.client_id or row.used or row.expires_at < time.time():
                return None
            p = row.params_json
            return GatewayAuthCode(
                code=authorization_code,
                scopes=[GATEWAY_SCOPE],
                expires_at=row.expires_at,
                client_id=row.client_id,
                code_challenge=p["code_challenge"],
                redirect_uri=p["redirect_uri"],
                redirect_uri_provided_explicitly=p["redirect_uri_provided_explicitly"],
                resource=p.get("resource") or self.s.resource_url,
                subject=str(row.user_id),
                user_id=row.user_id,
            )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: GatewayAuthCode
    ) -> OAuthToken:
        async with self.db.session() as s:
            # Атомарно помечаем код использованным: повторный обмен не пройдёт.
            res = await s.execute(
                update(AuthCode)
                .where(AuthCode.code_hash == hash_secret(authorization_code.code), AuthCode.used.is_(False))
                .values(used=True)
            )
            if res.rowcount != 1:
                raise TokenError("invalid_grant", "Код уже использован")
            if not await self._user_active(s, authorization_code.user_id):
                raise TokenError("invalid_grant", "Пользователь заблокирован")
            grant = Grant(
                client_id=client.client_id,
                user_id=authorization_code.user_id,
                scopes=[GATEWAY_SCOPE],
                resource=authorization_code.resource,
            )
            s.add(grant)
            await s.flush()
            return self._mint(s, grant.id)

    # ------------------------------------------------------------ refresh

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> GatewayRefreshToken | None:
        async with self.db.session() as s:
            tok = await s.get(Token, hash_secret(refresh_token))
            if tok is None or tok.kind != "refresh":
                return None
            grant = await s.get(Grant, tok.grant_id)
            if grant is None or grant.client_id != client.client_id or grant.revoked:
                return None
            if tok.used:
                # Повторное использование обменянного refresh-токена: вероятна кража.
                grant.revoked = True
                return None
            if tok.expires_at < time.time():
                return None
            return GatewayRefreshToken(
                token=refresh_token,
                client_id=grant.client_id,
                scopes=list(grant.scopes),
                expires_at=int(tok.expires_at),
                resource=grant.resource,
                subject=str(grant.user_id),
                grant_id=grant.id,
            )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: GatewayRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        if scopes and not set(scopes) <= {GATEWAY_SCOPE}:
            raise TokenError("invalid_scope", "Неизвестный scope")
        async with self.db.session() as s:
            res = await s.execute(
                update(Token)
                .where(Token.token_hash == hash_secret(refresh_token.token), Token.used.is_(False))
                .values(used=True)
            )
            if res.rowcount != 1:
                raise TokenError("invalid_grant", "Refresh-токен уже использован")
            grant = await s.get(Grant, refresh_token.grant_id)
            if grant is None or grant.revoked or not await self._user_active(s, grant.user_id):
                raise TokenError("invalid_grant", "Доступ отозван")
            # Старые access-токены гранта больше не нужны.
            await s.execute(
                update(Token).where(Token.grant_id == grant.id, Token.kind == "access").values(expires_at=0)
            )
            return self._mint(s, grant.id)

    # ------------------------------------------------------------ access

    async def load_access_token(self, token: str) -> GatewayAccessToken | None:
        async with self.db.session() as s:
            tok = await s.get(Token, hash_secret(token))
            if tok is None or tok.kind != "access" or tok.expires_at < time.time():
                return None
            grant = await s.get(Grant, tok.grant_id)
            if grant is None or grant.revoked:
                return None
            if not await self._user_active(s, grant.user_id):
                return None
            return GatewayAccessToken(
                token=token,
                client_id=grant.client_id,
                scopes=list(grant.scopes),
                expires_at=int(tok.expires_at),
                resource=grant.resource,
                subject=str(grant.user_id),
                grant_id=grant.id,
                user_id=grant.user_id,
            )

    async def revoke_token(self, token: GatewayAccessToken | GatewayRefreshToken) -> None:
        async with self.db.session() as s:
            await s.execute(update(Grant).where(Grant.id == token.grant_id).values(revoked=True))

    # ------------------------------------------------------------ helpers

    def _mint(self, s, grant_id: int) -> OAuthToken:
        access, refresh = new_secret(), new_secret()
        t = time.time()
        s.add(
            Token(
                token_hash=hash_secret(access),
                kind="access",
                grant_id=grant_id,
                expires_at=t + self.s.access_token_ttl_seconds,
            )
        )
        s.add(
            Token(
                token_hash=hash_secret(refresh),
                kind="refresh",
                grant_id=grant_id,
                expires_at=t + self.s.refresh_token_ttl_seconds,
            )
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",  # noqa: S106 — это тип токена, не пароль
            expires_in=self.s.access_token_ttl_seconds,
            refresh_token=refresh,
            scope=GATEWAY_SCOPE,
        )

    @staticmethod
    async def _user_active(s, user_id: int) -> bool:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        return user is not None and not user.disabled
