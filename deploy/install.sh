#!/usr/bin/env bash
# Установка и донастройка ru-mcp-gateway. Повторный запуск безопасен: заполненное не меняется.
#
#   sudo deploy/install.sh --domain mcp.company.ru --admin you@company.ru --allowed-domains company.ru
#
# Что делает:
#   - создаёт .env (права 600) и сам генерирует пароль базы и ключ шифрования токенов;
#   - выбирает свободный локальный порт шлюза (по умолчанию 8000, только 127.0.0.1);
#   - определяет, кто занимает порты 80/443, и выбирает способ HTTPS:
#       caddy      — порты свободны: встроенный Caddy в Docker (Let's Encrypt);
#       nginx      — на сервере nginx: готовит файл сайта в deploy/generated/, ничего не меняя в nginx;
#       caddy-host — на сервере Caddy: готовит блок для его Caddyfile;
#       external   — порты заняты чем-то другим (например, контейнером): настраиваете прокси сами;
#   - проверяет настройки и запускает шлюз, затем deploy/check.sh.
#
# Чего НЕ делает: не печатает секреты, не трогает чужие контейнеры, тома и настройки других сайтов,
# не открывает порты в файрволе, не выполняет `docker compose down`.
#
# Параметры:
#   --domain D            поддомен шлюза (A-запись должна указывать на этот сервер)
#   --admin EMAIL         кто станет администратором при первом входе
#   --allowed-domains D   почтовые домены сотрудников, которых пускать (через запятую)
#   --allowed-emails E    отдельные адреса (через запятую)
#   --proxy MODE          auto (по умолчанию) | caddy | nginx | caddy-host | external
#   --port N              локальный порт шлюза (по умолчанию — первый свободный от 8000)
#   --no-start            только подготовить .env и файлы прокси
#   --non-interactive     ничего не спрашивать (для автоматической установки)
set -euo pipefail

# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"
GEN_DIR="$ROOT/deploy/generated"

DOMAIN="" ADMIN="" ALLOWED_DOMAINS="" ALLOWED_EMAILS="" PROXY="auto" PORT="" START=1
INTERACTIVE=1
[[ -t 0 ]] || INTERACTIVE=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--domain) DOMAIN="${2:-}" && shift ;;
	--admin) ADMIN="${2:-}" && shift ;;
	--allowed-domains) ALLOWED_DOMAINS="${2:-}" && shift ;;
	--allowed-emails) ALLOWED_EMAILS="${2:-}" && shift ;;
	--proxy) PROXY="${2:-}" && shift ;;
	--port) PORT="${2:-}" && shift ;;
	--no-start) START=0 ;;
	--non-interactive) INTERACTIVE=0 ;;
	-h | --help)
		sed -n '2,32p' "$0"
		exit 0
		;;
	*) die "неизвестный параметр: $1 (см. --help)" ;;
	esac
	shift
done

check_list() { # check_list "значение" "что это" — список email/доменов через запятую, без пробелов и переводов строк.
	# Вызывать напрямую, не внутри $(…): там die завершил бы только подоболочку.
	[[ -z "$1" || "$1" =~ ^[a-z0-9@._+,-]+$ ]] || die "$2: только латиница, цифры, @ . _ + - и запятые"
}

is_placeholder() { [[ -z "$1" || "$1" == *your-company* || "$1" == *example* ]]; }

ask() { # ask "вопрос" — ответ в stdout; в неинтерактивном режиме пусто
	local answer=""
	if [[ $INTERACTIVE -eq 1 ]]; then
		read -r -p "$1: " answer
	fi
	printf '%s' "$answer"
}

# ------------------------------------------------------------------ 1. окружение

say "1. Проверка окружения"
require_docker
command -v openssl >/dev/null || die "нужен openssl"
command -v ss >/dev/null || die "нужна утилита ss (пакет iproute2)"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), Compose $(docker compose version --short)"
mem_mb=$(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || echo 0)
disk_mb=$(df -Pm "$ROOT" | awk 'NR == 2 { print $4 }')
if [[ "$mem_mb" -ge 700 ]]; then ok "свободно памяти: ${mem_mb} МБ"; else warn "свободно памяти ${mem_mb} МБ — шлюзу и базе нужно около 700 МБ"; fi
if [[ "$disk_mb" -ge 3000 ]]; then ok "свободно на диске: ${disk_mb} МБ"; else warn "свободно на диске ${disk_mb} МБ — нужно от 3 ГБ (образы и база)"; fi

# ------------------------------------------------------------------ 2. .env и секреты

say "2. Настройки (.env)"
umask 077
if [[ ! -f "$ENV_FILE" ]]; then
	cp .env.example "$ENV_FILE"
	ok "создан .env из .env.example"
fi
chmod 600 "$ENV_FILE"

if [[ -z "$(env_get POSTGRES_PASSWORD)" ]]; then
	# Пароль действует только при первом создании базы: если база уже есть, новый пароль не подойдёт.
	if docker volume inspect rugw_pgdata >/dev/null 2>&1; then
		die "в .env пустой POSTGRES_PASSWORD, но база (том rugw_pgdata) уже создана. Верните прежний пароль в .env"
	fi
	env_set POSTGRES_PASSWORD "$(openssl rand -hex 32)"
	ok "сгенерирован пароль базы"
else
	ok "пароль базы уже задан"
fi

if [[ -z "$(env_get RUGW_TOKEN_ENCRYPTION_KEYS)" ]]; then
	# Ключ Fernet: 32 случайных байта в base64url
	env_set RUGW_TOKEN_ENCRYPTION_KEYS "$(openssl rand -base64 32 | tr '+/' '-_')"
	ok "сгенерирован ключ шифрования токенов — .env нужно хранить в резервной копии: без ключа токены не прочитать"
else
	ok "ключ шифрования уже задан"
fi

# Домен
[[ -n "$DOMAIN" ]] || DOMAIN="$(env_get GATEWAY_DOMAIN)"
if is_placeholder "$DOMAIN"; then
	DOMAIN="$(ask 'Поддомен шлюза (например mcp.company.ru)')"
fi
DOMAIN="${DOMAIN,,}"
[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]] || die "укажите поддомен: --domain mcp.company.ru"
env_set GATEWAY_DOMAIN "$DOMAIN"
env_set RUGW_PUBLIC_URL "https://$DOMAIN"
ok "адрес шлюза: https://$DOMAIN"

# Кого пускать
cur_domains="$(env_get RUGW_ALLOWED_EMAIL_DOMAINS)"
if [[ -n "$ALLOWED_DOMAINS" ]]; then
	check_list "${ALLOWED_DOMAINS,,}" --allowed-domains
	env_set RUGW_ALLOWED_EMAIL_DOMAINS "${ALLOWED_DOMAINS,,}"
elif is_placeholder "$cur_domains"; then
	answer="$(ask 'Почтовые домены сотрудников через запятую (Enter — пропустить)' | tr '[:upper:]' '[:lower:]')"
	check_list "$answer" 'домены'
	env_set RUGW_ALLOWED_EMAIL_DOMAINS "$answer"
fi
if [[ -n "$ALLOWED_EMAILS" ]]; then
	check_list "${ALLOWED_EMAILS,,}" --allowed-emails
	env_set RUGW_ALLOWED_EMAILS "${ALLOWED_EMAILS,,}"
fi
if [[ -n "$ADMIN" ]]; then
	check_list "${ADMIN,,}" --admin
	env_set RUGW_BOOTSTRAP_ADMIN_EMAILS "${ADMIN,,}"
elif [[ -z "$(env_get RUGW_BOOTSTRAP_ADMIN_EMAILS)" ]]; then
	answer="$(ask 'Email администратора (станет админом при первом входе)' | tr '[:upper:]' '[:lower:]')"
	check_list "$answer" 'email администратора'
	env_set RUGW_BOOTSTRAP_ADMIN_EMAILS "$answer"
fi
if [[ -z "$(env_get RUGW_ALLOWED_EMAIL_DOMAINS)$(env_get RUGW_ALLOWED_EMAILS)$(env_get RUGW_BOOTSTRAP_ADMIN_EMAILS)" ]]; then
	warn "не задано, кого пускать: --admin и/или --allowed-domains"
fi

# OAuth-приложение Яндекса: ID можно спросить, секрет — только скрытым вводом и только у человека
if [[ -z "$(env_get RUGW_YANDEX_CLIENT_ID)" ]]; then
	answer="$(ask 'ClientID OAuth-приложения Яндекса (Enter — заполнить позже)')"
	[[ -z "$answer" || "$answer" =~ ^[A-Za-z0-9]+$ ]] || die "ClientID: только латиница и цифры"
	env_set RUGW_YANDEX_CLIENT_ID "$answer"
fi
if [[ -z "$(env_get RUGW_YANDEX_CLIENT_SECRET)" && $INTERACTIVE -eq 1 ]]; then
	read -r -s -p "Client secret OAuth-приложения Яндекса (ввод скрыт; Enter — заполнить позже): " secret
	echo
	[[ -z "$secret" || "$secret" =~ ^[A-Za-z0-9]+$ ]] || die "Client secret: только латиница и цифры (проверьте, что скопировали целиком)"
	[[ -n "$secret" ]] && env_set RUGW_YANDEX_CLIENT_SECRET "$secret"
	unset secret
fi

# ------------------------------------------------------------------ 3. порт шлюза

say "3. Локальный порт шлюза"
port_busy() { ss -ltnH "sport = :$1" | grep -q .; }
running="$(docker compose ps -q gateway 2>/dev/null || true)"
[[ -n "$PORT" ]] || PORT="$(env_get GATEWAY_HOST_PORT)"
if [[ -n "$PORT" ]] && ! [[ "$PORT" =~ ^[0-9]{4,5}$ && "$PORT" -ge 1024 && "$PORT" -le 65535 ]]; then
	die "порт — число от 1024 до 65535"
fi
if [[ -z "$PORT" ]]; then
	PORT=8000
	while port_busy "$PORT"; do
		PORT=$((PORT + 1))
		[[ $PORT -le 8099 ]] || die "нет свободного порта 8000–8099: укажите --port"
	done
elif [[ -z "$running" ]] && port_busy "$PORT"; then
	die "порт $PORT занят другой программой: укажите другой --port"
fi
env_set GATEWAY_HOST_PORT "$PORT"
ok "шлюз будет слушать 127.0.0.1:$PORT (снаружи недоступен)"

# ------------------------------------------------------------------ 4. HTTPS

say "4. HTTPS"
owner_of() { # имя программы на порту (нужен root, чтобы видеть чужие процессы)
	{ ss -ltnpH "sport = :$1" 2>/dev/null || true; } | grep -o 'users:(("[^"]*' | head -1 | sed 's/users:(("//' || true
}
describe() { # describe PORT — кто занимает порт
	local who
	who="$(owner_of "$1")"
	if [[ -n "$who" ]]; then
		printf '%s' "$who"
	elif port_busy "$1"; then
		printf 'занят'
	else
		printf 'свободен'
	fi
}
d80="$(describe 80)" d443="$(describe 443)"
ours_caddy="$(docker compose ps -q caddy 2>/dev/null || true)"
if [[ "$PROXY" == auto && -n "$(env_get GATEWAY_PROXY)" ]]; then
	PROXY="$(env_get GATEWAY_PROXY)" # выбран при прошлом запуске; сменить — --proxy
fi
if [[ "$PROXY" == auto ]]; then
	if [[ -n "$ours_caddy" ]]; then
		PROXY=caddy # порты занимает наш же встроенный Caddy (повторный запуск)
	elif [[ "$d80$d443" == свободенсвободен ]]; then
		PROXY=caddy
	elif [[ "$d80$d443" == *nginx* ]]; then
		PROXY=nginx
	elif [[ "$d80$d443" == *caddy* ]]; then
		PROXY=caddy-host
	else
		PROXY=external
	fi
fi
ok "порт 80: $d80; порт 443: $d443 → способ HTTPS: $PROXY"
if [[ "$PROXY" == caddy && -z "$ours_caddy" && "$d80$d443" != свободенсвободен ]]; then
	die "порты 80/443 заняты ($d80/$d443): встроенный Caddy не запустится. Уберите --proxy caddy"
fi

case "$PROXY" in
caddy | nginx | caddy-host | external) ;;
*) die "--proxy: auto | caddy | nginx | caddy-host | external" ;;
esac
mkdir -p "$GEN_DIR"
env_set GATEWAY_PROXY "$PROXY"
case "$PROXY" in
caddy)
	env_set COMPOSE_PROFILES caddy
	ok "встроенный Caddy получит сертификат Let's Encrypt (нужны A-запись и открытые порты 80, 443)"
	;;
nginx)
	env_set COMPOSE_PROFILES ""
	sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__PORT__/$PORT/g" deploy/nginx-site.conf.template >"$GEN_DIR/rugw-$DOMAIN.conf"
	chmod 644 "$GEN_DIR/rugw-$DOMAIN.conf"
	ok "готов файл сайта nginx: deploy/generated/rugw-$DOMAIN.conf (инструкция — в начале файла)"
	;;
caddy-host)
	env_set COMPOSE_PROFILES ""
	sed -e "s/{\$GATEWAY_DOMAIN}/$DOMAIN/" -e "s/{\$GATEWAY_HOST_PORT:8000}/$PORT/" \
		-e 's#output stdout#output file /var/log/caddy/rugw.log#' deploy/Caddyfile >"$GEN_DIR/Caddyfile-$DOMAIN"
	chmod 644 "$GEN_DIR/Caddyfile-$DOMAIN"
	ok "готов блок для Caddy сервера: deploy/generated/Caddyfile-$DOMAIN — добавьте в /etc/caddy/Caddyfile и: sudo systemctl reload caddy"
	;;
external)
	env_set COMPOSE_PROFILES ""
	warn "порты 80/443 заняты ($d80/$d443): направьте https://$DOMAIN на http://127.0.0.1:$PORT в вашем прокси"
	warn "требования к прокси: передавать Host, не буферизовать ответ, таймаут чтения от 1 часа"
	;;
esac

# DNS — только предупреждение: запись могла ещё не разойтись
resolved="$( (getent ahostsv4 "$DOMAIN" 2>/dev/null || true) | awk 'NR == 1 { print $1 }')"
if [[ -z "$resolved" ]]; then
	warn "DNS: $DOMAIN пока не разрешается — создайте A-запись на IP этого сервера"
elif hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$resolved"; then
	ok "DNS: $DOMAIN → $resolved (это этот сервер)"
else
	warn "DNS: $DOMAIN → $resolved; среди адресов сервера его нет (за NAT это нормально — проверьте IP в панели)"
fi

# ------------------------------------------------------------------ 5. проверка настроек и запуск

say "5. Проверка настроек"
missing=()
for key in RUGW_YANDEX_CLIENT_ID RUGW_YANDEX_CLIENT_SECRET; do
	[[ -n "$(env_get "$key")" ]] || missing+=("$key")
done
say "  Redirect URI для OAuth-приложения Яндекса: https://$DOMAIN/auth/yandex/callback"
if [[ ${#missing[@]} -gt 0 ]]; then
	say ""
	say "Осталось заполнить в .env (откройте: sudo nano $ENV_FILE):"
	printf '  - %s\n' "${missing[@]}"
	say "Создайте приложение на https://oauth.yandex.ru/client/new (права: адрес почты; логин, имя и фамилия)."
	say "Затем запустите deploy/install.sh ещё раз."
	exit 3
fi

if [[ $START -eq 0 ]]; then
	say "Готово (без запуска, --no-start)."
	exit 0
fi

docker compose build --quiet gateway
docker compose up -d --wait postgres
if ! docker compose run --rm -T gateway python -m rugw check; then
	say ""
	say "Исправьте настройки в .env по списку выше и запустите deploy/install.sh ещё раз."
	exit 4
fi

say "6. Запуск"
docker compose up -d --wait
ok "контейнеры запущены"

say "7. Проверка"
if [[ "$PROXY" == caddy ]]; then
	exec "$ROOT/deploy/check.sh"
fi
"$ROOT/deploy/check.sh" --local
say ""
say "Осталось подключить поддомен в прокси сервера (см. шаг 4), затем полная проверка: sudo deploy/check.sh"
