#!/usr/bin/env bash
# Резервная копия базы шлюза в backups/ (права 600). Хранит последние KEEP копий (по умолчанию 14).
#   sudo deploy/backup.sh
# Для cron (ежедневно в 03:15):
#   15 3 * * * cd /opt/rugw && deploy/backup.sh >/dev/null
#
# Файл .env в копию НЕ входит: в нём ключ шифрования токенов. Храните .env отдельно и надёжно —
# без ключа сохранённые токены сотрудников и Диадока не прочитать (придётся войти заново).
set -euo pipefail
# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"
require_docker

KEEP="${KEEP:-14}"
umask 077
mkdir -p backups
chmod 700 backups
file="backups/rugw-$(date +%Y%m%d-%H%M%S).dump"
if ! docker compose exec -T postgres pg_dump -U rugw -d rugw -Fc >"$file"; then
	rm -f "$file"
	die "pg_dump не удался (база запущена? docker compose ps)"
fi
[[ -s "$file" ]] || die "копия пустая: $file"
ok "копия: $file ($(du -h "$file" | cut -f1))"

# Старые копии — только наши файлы в backups/
mapfile -t old < <(find backups -maxdepth 1 -name 'rugw-*.dump' -type f | sort -r | tail -n +"$((KEEP + 1))")
for f in "${old[@]}"; do
	rm -f -- "$f"
done
[[ ${#old[@]} -eq 0 ]] || ok "удалено старых копий: ${#old[@]}"
