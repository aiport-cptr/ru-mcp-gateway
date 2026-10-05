"""Возврат из Яндекса и экран согласия.

Экран согласия обязателен: без него любой, кто зарегистрировал клиента через
открытую регистрацию (DCR) со своим redirect_uri, мог бы прислать сотруднику
ссылку и молча получить токен (Яндекс не спрашивает повторно у залогиненного).
"""

from __future__ import annotations

import html
import logging
import time
from urllib.parse import urlparse

from mcp.server.auth.provider import construct_redirect_uri
from sqlalchemy import select, update
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from rugw.audit import Auditor
from rugw.auth.provider import GatewayOAuthProvider
from rugw.auth.yandex import YandexAuthError, YandexOAuth
from rugw.config import Settings
from rugw.db import Database, PendingLogin, User
from rugw.policy import admission_role
from rugw.security import hash_secret, new_secret, same

log = logging.getLogger(__name__)

CSRF_COOKIE = "rugw_consent"
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    # form-action не задаём: браузеры применяют его и к редиректу после POST,
    # а он ведёт на redirect_uri клиента (часто http://localhost:порт).
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;color:#1d1d1f}}
.box{{border:1px solid #ddd;border-radius:10px;padding:20px}}
code{{background:#f3f3f3;padding:1px 4px;border-radius:4px}}
button{{font:inherit;padding:8px 18px;border-radius:8px;border:1px solid #888;cursor:pointer;margin-right:8px}}
.ok{{background:#1d1d1f;color:#fff;border-color:#1d1d1f}}</style></head>
<body><div class="box"><h2>{html.escape(title)}</h2>{body}</div></body></html>"""
    return HTMLResponse(doc, status_code=status, headers=SECURITY_HEADERS)


def _error(msg: str, status: int = 400) -> HTMLResponse:
    return _page("Вход не выполнен", f"<p>{html.escape(msg)}</p>", status)


class AuthRoutes:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        yandex: YandexOAuth,
        provider: GatewayOAuthProvider,
        auditor: Auditor,
    ) -> None:
        self.s = settings
        self.db = db
        self.yandex = yandex
        self.provider = provider
        self.audit = auditor

    async def _load_pending(self, state: str) -> PendingLogin | None:
        async with self.db.session() as s:
            row = await s.get(PendingLogin, hash_secret(state))
            if row is None or row.consumed or row.expires_at < time.time():
                return None
            return row

    # ---------------------------------------------------------------- callback

    async def yandex_callback(self, request: Request) -> Response:
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        if request.query_params.get("error"):
            return _error("Вход через Яндекс отменён.")
        if not state or not code:
            return _error("Некорректный ответ Яндекса.")
        pending = await self._load_pending(state)
        if pending is None:
            return _error("Ссылка входа устарела. Начните подключение заново из клиента.")

        try:
            ident = await self.yandex.identify(code, pending.params_json["_yandex_verifier"])
        except YandexAuthError as exc:
            log.warning("yandex auth failed: %s", exc)
            return _error(str(exc), 502)

        role = admission_role(self.s, ident.email)
        if role is None:
            await self.audit.log(
                event="login_denied", outcome="denied", target=ident.email, client_id=pending.client_id
            )
            return _error("Этому аккаунту вход в шлюз не разрешён. Обратитесь к администратору.", 403)

        async with self.db.session() as s:
            user = (await s.execute(select(User).where(User.yandex_id == ident.yandex_id))).scalar_one_or_none()
            if user is None:
                user = User(yandex_id=ident.yandex_id, login=ident.login, email=ident.email, role=role)
                s.add(user)
            else:
                if user.disabled:
                    await self.audit.log(event="login_denied", outcome="denied", target=ident.email, user_id=user.id)
                    return _error("Учётная запись заблокирована.", 403)
                user.email, user.login = ident.email, ident.login
                if role == "admin":  # bootstrap-список может только повысить, не понизить
                    user.role = "admin"
            user.last_login_at = time.time()
            await s.flush()
            csrf = new_secret()
            await s.execute(
                update(PendingLogin)
                .where(PendingLogin.state_hash == hash_secret(state))
                .values(user_id=user.id, consent_csrf_hash=hash_secret(csrf))
            )
            user_id, email = user.id, user.email

        await self.audit.log(event="login_ok", outcome="ok", user_id=user_id, client_id=pending.client_id)

        client = await self.provider.get_client(pending.client_id)
        client_name = (client.client_name if client else None) or pending.client_id
        redirect_host = urlparse(pending.params_json["redirect_uri"]).netloc or "?"
        body = f"""
<p>Вы вошли как <b>{html.escape(email)}</b>.</p>
<p>Приложение <b>{html.escape(client_name)}</b> просит доступ к шлюзу от вашего имени.</p>
<p>После разрешения вы вернётесь на <code>{html.escape(redirect_host)}</code>.
Если вы не начинали подключение сами — нажмите «Отказать».</p>
<form method="post" action="/auth/consent">
<input type="hidden" name="state" value="{html.escape(state)}">
<input type="hidden" name="csrf" value="{html.escape(csrf)}">
<button class="ok" name="decision" value="allow">Разрешить</button>
<button name="decision" value="deny">Отказать</button>
</form>"""
        resp = _page("Подключение к шлюзу", body)
        resp.set_cookie(
            CSRF_COOKIE,
            csrf,
            max_age=self.s.pending_login_ttl_seconds,
            httponly=True,
            secure=not self.s.dev_mode,
            samesite="strict",
            path="/auth/consent",
        )
        return resp

    # ---------------------------------------------------------------- consent

    async def consent(self, request: Request) -> Response:
        form = await request.form()
        state = str(form.get("state", ""))
        csrf = str(form.get("csrf", ""))
        decision = str(form.get("decision", ""))
        cookie = request.cookies.get(CSRF_COOKIE, "")
        if not state or not csrf or not cookie or not same(csrf, cookie):
            return _error("Проверка формы не прошла. Начните подключение заново.", 403)

        async with self.db.session() as s:
            # Атомарно «съедаем» запрос: повторная отправка формы ничего не даст.
            res = await s.execute(
                update(PendingLogin)
                .where(
                    PendingLogin.state_hash == hash_secret(state),
                    PendingLogin.consumed.is_(False),
                    PendingLogin.consent_csrf_hash == hash_secret(csrf),
                    PendingLogin.user_id.is_not(None),
                    PendingLogin.expires_at >= time.time(),
                )
                .values(consumed=True)
            )
            if res.rowcount != 1:
                return _error("Запрос устарел или уже обработан.", 403)
            pending = await s.get(PendingLogin, hash_secret(state))

        params = pending.params_json
        if decision != "allow":
            await self.audit.log(
                event="consent_denied", outcome="denied", user_id=pending.user_id, client_id=pending.client_id
            )
            url = construct_redirect_uri(params["redirect_uri"], error="access_denied", state=params.get("state"))
        else:
            code, params = await self.provider.issue_auth_code(pending)
            await self.audit.log(
                event="consent_granted", outcome="ok", user_id=pending.user_id, client_id=pending.client_id
            )
            url = construct_redirect_uri(params["redirect_uri"], code=code, state=params.get("state"))
        resp = RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})
        resp.delete_cookie(CSRF_COOKIE, path="/auth/consent")
        return resp
