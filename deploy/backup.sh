#!/usr/bin/env bash
# Резервная копия базы шлюза в backups/ (права 600). Хранит последние KEEP копий (по умолчанию 14).
#   sudo deploy/backup.sh
# Для cron (ежедневно в 03:15):
#   15 3 * * * cd /opt/rugw && deploy/backup.sh >/dev/null
#
# Файл .env в копию НЕ входит: в нём ключ шифрования токенов. Храните .env отдельно и надёжно —
# без ключа сохранённые токены сотрудников и Диадока не прочитать (придётся войти заново).
#
# Существующие копии не перезаписываются и не удаляются при ошибке: dump пишется во временный
# файл, проверяется и только потом получает окончательное имя (без перезаписи). Одновременные
# запуски выполняются по очереди (flock). Старые копии удаляются только после успешной.
set -euo pipefail
# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"
require_docker

KEEP="${KEEP:-14}"
[[ "$KEEP" =~ ^[0-9]+$ && "$KEEP" -ge 1 ]] || die "KEEP — число от 1"
umask 077
mkdir -p backups
chmod 700 backups

# Очередь: второй запуск ждёт первый (до 30 минут), а не пишет параллельно
exec 9>backups/.lock
flock -w 1800 9 || die "другая резервная копия выполняется слишком долго"

tmp="$(mktemp backups/.rugw-XXXXXXXX.part)"
trap 'rm -f -- "$tmp"' EXIT

if ! docker compose exec -T postgres pg_dump -U rugw -d rugw -Fc >"$tmp"; then
	die "pg_dump не удался (база запущена? docker compose ps); прежние копии не тронуты"
fi
[[ -s "$tmp" ]] || die "копия пустая; прежние копии не тронуты"
if ! docker compose exec -T postgres pg_restore -l <"$tmp" >/dev/null; then
	die "копия не читается pg_restore; прежние копии не тронуты"
fi

# Окончательное имя без перезаписи: ln не заменяет существующий файл
stamp="$(date +%Y%m%d-%H%M%S)"
file="backups/rugw-$stamp.dump"
n=1
until ln -- "$tmp" "$file" 2>/dev/null; do
	n=$((n + 1))
	[[ $n -le 100 ]] || die "не удалось выбрать свободное имя для копии"
	file="backups/rugw-$stamp-$n.dump"
done
rm -f -- "$tmp"
ok "копия: $file ($(du -h "$file" | cut -f1))"

# Ротация — только после успешной копии и только наши файлы rugw-*.dump
mapfile -t old < <(find backups -maxdepth 1 -name 'rugw-*.dump' -type f -printf '%T@ %p\n' | sort -rn |
	tail -n +"$((KEEP + 1))" | cut -d' ' -f2-)
for f in "${old[@]}"; do
	rm -f -- "$f"
done
[[ ${#old[@]} -eq 0 ]] || ok "удалено старых копий: ${#old[@]}"
