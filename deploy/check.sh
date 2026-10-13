#!/usr/bin/env bash
# Проверка установленного шлюза. Ничего не меняет и не печатает секреты.
#   sudo deploy/check.sh            — всё, включая проверку снаружи по https
#   sudo deploy/check.sh --local    — только сервер (до настройки DNS и прокси)
set -uo pipefail
# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT" || exit 1

LOCAL_ONLY=0
[[ "${1:-}" == "--local" ]] && LOCAL_ONLY=1
failed=0
fail() {
	printf '  ✗ %s\n' "$*" >&2
	failed=1
}

require_docker
[[ -f "$ENV_FILE" ]] || die "нет .env — сначала deploy/install.sh"
DOMAIN="$(env_get GATEWAY_DOMAIN)"
PORT="$(env_get GATEWAY_HOST_PORT)"
PORT="${PORT:-8000}"

say "Контейнеры"
for svc in postgres gateway; do
	id="$(docker compose ps -q "$svc" 2>/dev/null)"
	if [[ -z "$id" ]]; then
		fail "$svc не запущен (docker compose up -d)"
		continue
	fi
	state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")"
	case "$state" in
	"running healthy" | "running ") ok "$svc: работает" ;;
	"running starting") warn "$svc: запускается — повторите проверку через минуту" ;;
	*) fail "$svc: $state (журнал: docker compose logs --tail 50 $svc)" ;;
	esac
done
if [[ "$(env_get COMPOSE_PROFILES)" == *caddy* ]]; then
	if [[ -n "$(docker compose ps -q caddy 2>/dev/null)" ]]; then ok "caddy: работает"; else fail "caddy не запущен"; fi
fi

say "Сеть"
binding="$(docker compose port gateway 8000 2>/dev/null)"
if [[ "$binding" == "127.0.0.1:$PORT" ]]; then
	ok "шлюз слушает только 127.0.0.1:$PORT"
else
	fail "порт шлюза опубликован как '${binding:-нет}', ожидалось 127.0.0.1:$PORT"
fi
health="$(curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" 2>/dev/null)"
if [[ "$health" == *'"auth_enabled":true'* ]]; then
	ok "локально отвечает: $health"
else
	fail "локально не отвечает /healthz"
fi

say "Настройки"
if docker compose exec -T gateway python -m rugw check | sed 's/^/  /'; then :; else fail "rugw check"; fi

if [[ $LOCAL_ONLY -eq 1 ]]; then
	say "Проверка снаружи пропущена (--local)."
elif [[ -z "$DOMAIN" ]]; then
	fail "в .env нет GATEWAY_DOMAIN"
else
	say "Снаружи (https://$DOMAIN)"
	base="https://$DOMAIN"
	if curl -fsS --max-time 10 "$base/healthz" 2>/dev/null | grep -q '"auth_enabled":true'; then
		ok "HTTPS работает, сертификат принят"
	else
		fail "https://$DOMAIN/healthz не открывается: проверьте A-запись, открытые порты 80/443 и прокси"
	fi
	meta="$(curl -fsS --max-time 10 "$base/.well-known/oauth-authorization-server" 2>/dev/null)"
	if [[ "$meta" == *"\"issuer\":\"$base"* ]]; then
		ok "OAuth-метаданные на месте (issuer = $base)"
	else
		fail "OAuth-метаданные не найдены или issuer не совпадает с $base"
	fi
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' \
		-H 'Accept: application/json, text/event-stream' -d '{}' "$base/mcp")"
	if [[ "$code" == 401 ]]; then
		ok "/mcp без входа отвечает 401 — доступ закрыт"
	else
		fail "/mcp без входа ответил $code, ожидался 401"
	fi
fi

say ""
if [[ $failed -eq 0 && $LOCAL_ONLY -eq 1 ]]; then
	say "На сервере всё в порядке. Осталось открыть доступ снаружи, затем: sudo deploy/check.sh"
elif [[ $failed -eq 0 ]]; then
	say "Всё в порядке. Адрес для подключения: https://${DOMAIN:-<домен>}/mcp"
else
	say "Есть ошибки (✗) — см. выше."
fi
exit $failed
