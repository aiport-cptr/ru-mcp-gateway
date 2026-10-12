# Общие функции скриптов deploy/. Подключается через source; сам не запускается.
# shellcheck shell=bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

say() { printf '%s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
die() {
	printf 'ОШИБКА: %s\n' "$*" >&2
	exit 1
}

env_get() { # значение ключа из .env (пусто, если нет). Значения секретов не выводите.
	[[ -f "$ENV_FILE" ]] || return 0
	awk -v k="$1" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' "$ENV_FILE"
}

env_set() { # env_set KEY VALUE — заменить строку KEY=… или дописать. Значение передаётся через
	# окружение, а не аргументом awk, чтобы не попасть в список процессов.
	local tmp
	tmp="$(mktemp "$ENV_FILE.XXXXXX")"
	KEY="$1" VAL="$2" awk '
		BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VAL"]; done = 0 }
		index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 }; next }
		{ print }
		END { if (!done) print k "=" v }
	' "$ENV_FILE" >"$tmp"
	chmod 600 "$tmp"
	mv "$tmp" "$ENV_FILE"
}

require_docker() {
	command -v docker >/dev/null || die "нужен Docker (Ubuntu: sudo apt-get install -y docker.io docker-compose-v2)"
	docker compose version >/dev/null 2>&1 || die "нужен Docker Compose v2 (sudo apt-get install -y docker-compose-v2)"
	docker info >/dev/null 2>&1 || die "нет доступа к Docker: запустите через sudo"
}
