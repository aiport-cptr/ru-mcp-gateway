# ru-mcp-gateway

Корпоративный MCP-шлюз: один защищённый адрес, через который ИИ-ассистенты
(Claude Code, Cursor, Codex и другие MCP-клиенты) работают с системами компании —
Яндекс Трекером, Битрикс24, 1С.

- **Вход через Яндекс ID** с экраном согласия; пускаются только разрешённые домены и адреса.
- **MCP OAuth** для клиентов: никаких токенов вручную в конфиге клиента.
- **Роли** `readonly` / `member` / `admin`, проверяются на каждом вызове.
- **Журнал аудита** каждого вызова инструмента, входа и отказа.
- **Секреты коннекторов** остаются на сервере и не попадают ни к модели, ни к клиенту.
- **Авторизацию нельзя выключить.** Небезопасная конфигурация не даёт процессу стартовать.

Статус: **MVP 0.1**, не прошёл внешний аудит безопасности. Не подключайте рабочие
системы с правами на запись, пока не прочитаны [SECURITY.md](SECURITY.md) и не проведена проверка.

## Коннекторы

| Коннектор | Инструменты | Уровень |
|---|---|---|
| Шлюз | `gateway_whoami` | read |
| Яндекс Трекер | `tracker_search_issues`, `tracker_get_issue`, `tracker_get_comments` | read |
| | `tracker_add_comment` | write |
| Битрикс24 (CRM) | `bitrix_crm_list`, `bitrix_crm_get` | read |
| | `bitrix_crm_add_comment` | write |
| 1С (OData) | `onec_list_entities`, `onec_query` | read |

Коннектор включается, только если в `.env` заданы его учётные данные.
Пользователь видит в списке только инструменты, разрешённые его роли.

## Установка

Нужны: VM с Ubuntu 24.04, домен с A-записью на неё, Docker, Caddy.

```bash
sudo apt-get update && sudo apt-get install -y git docker.io docker-compose-v2 caddy
sudo git clone https://github.com/aiport-cptr/ru-mcp-gateway.git /opt/rugw
cd /opt/rugw
sudo install -m 0600 .env.example .env
sudo editor .env          # заполнить; секреты не отправлять в чаты
sudo docker compose up -d --build
curl -fsS http://127.0.0.1:8000/healthz      # {"ok":true,"auth_enabled":true,...}
```

HTTPS: скопируйте `deploy/Caddyfile` в `/etc/caddy/Caddyfile`, замените домен,
`sudo systemctl reload caddy`. Порт 8000 в облаке **не открывайте** — он слушает только 127.0.0.1.

OAuth-приложение Яндекса (https://oauth.yandex.ru/client/new):
права «Доступ к адресу электронной почты» и «Доступ к логину, имени и фамилии»,
Redirect URI — `https://<домен>/auth/yandex/callback`.

## Подключение клиента

Claude Code:

```bash
claude mcp add --transport http company https://<домен>/mcp
```

Клиент сам откроет браузер: вход через Яндекс → экран «Разрешить» → готово.

## Управление пользователями

Только из консоли сервера (у шлюза нет веб-админки — меньше поверхность атаки):

```bash
sudo docker compose exec gateway python -m rugw users list
sudo docker compose exec gateway python -m rugw users set-role ivan@company.ru member
sudo docker compose exec gateway python -m rugw users disable ivan@company.ru   # гасит все его токены
```

## Разработка

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
```

Тесты проходят полный цикл входа (с подменой Яндекса), выдачу и ротацию токенов,
проверку прав и аудита, валидацию ввода коннекторов.

Устройство — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), модель угроз — [SECURITY.md](SECURITY.md),
инструкция для проверяющих — [REVIEW.md](REVIEW.md), планы — [docs/ROADMAP.md](docs/ROADMAP.md).

## Лицензия

Apache-2.0
