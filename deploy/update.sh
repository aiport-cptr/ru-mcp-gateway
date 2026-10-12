#!/usr/bin/env bash
# Обновление шлюза: резервная копия → новая версия из git → пересборка → проверка.
#   sudo deploy/update.sh
# Миграции базы применяются автоматически при запуске. Данные и .env не затрагиваются.
set -euo pipefail
# shellcheck source=deploy/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"
require_docker

before="$(git rev-parse --short HEAD)"
say "1. Резервная копия"
"$ROOT/deploy/backup.sh"
say "2. Новая версия"
git pull --ff-only
after="$(git rev-parse --short HEAD)"
if [[ "$before" == "$after" ]]; then
	ok "уже последняя версия ($after)"
else
	ok "$before → $after (что изменилось — CHANGELOG.md)"
fi
say "3. Пересборка и запуск"
docker compose up -d --build --wait
say "4. Проверка"
exec "$ROOT/deploy/check.sh"
