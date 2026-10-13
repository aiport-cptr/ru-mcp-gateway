#!/usr/bin/env bash
# Подключить поддомен шлюза к Caddy, уже работающему на сервере (способ caddy-host).
#   sudo deploy/apply-caddy.sh
#
# Безопасно для других сайтов этого Caddy:
#   1) копия /etc/caddy/Caddyfile → /etc/caddy/Caddyfile.bak-<время>;
#   2) блок шлюза дописывается в конец (если его там ещё нет);
#   3) проверка `caddy validate` от имени пользователя caddy (как работает служба);
#   4) только при успешной проверке — мягкая перезагрузка (сайты не прерываются),
#      иначе файл возвращается из копии и ничего не меняется.
set -euo pipefail
# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"

CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
DOMAIN="$(env_get GATEWAY_DOMAIN)"
[[ -n "$DOMAIN" ]] || die "в .env нет GATEWAY_DOMAIN — сначала deploy/install.sh"
BLOCK="$ROOT/deploy/generated/Caddyfile-$DOMAIN"
[[ -f "$BLOCK" ]] || die "нет $BLOCK — запустите deploy/install.sh --proxy caddy-host"
[[ -f "$CADDYFILE" ]] || die "нет $CADDYFILE"
command -v caddy >/dev/null || die "caddy не найден"

if grep -qE "^[[:space:]]*${DOMAIN//./\\.}[[:space:]]*\{" "$CADDYFILE"; then
	ok "блок $DOMAIN уже есть в $CADDYFILE — ничего не меняю"
	exit 0
fi

backup="$CADDYFILE.bak-$(date +%Y%m%d-%H%M%S)"
cp -p "$CADDYFILE" "$backup"
ok "копия: $backup"
{
	printf '\n'
	cat "$BLOCK"
} >>"$CADDYFILE"

validate() {
	if id caddy >/dev/null 2>&1; then
		runuser -u caddy -- caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1
	else
		caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1
	fi
}

if validate; then
	systemctl reload caddy
	ok "блок $DOMAIN добавлен, Caddy перезагружен (сертификат получится за ~30 секунд)"
	say "Проверка: sudo deploy/check.sh"
else
	cp -p "$backup" "$CADDYFILE"
	die "проверка Caddy не прошла — $CADDYFILE возвращён как был. Подробности: caddy validate --config $CADDYFILE"
fi
