# cf_worker — Cloudflare Worker fallback для passthrough-трафика

## Зачем

`web.telegram.org` (`149.154.167.99`) заблокирован на границе сети
Server A целиком на уровне SYN (null-route) — подтверждено живым тестом
(`curl` без REDIRECT: полный таймаут даже с активным zapret2, манглить
нечего, пакет наружу не уходит). У этого IP, в отличие от MTProto-DC,
нет известного рабочего аналога — заменить не на что (см. основной
`README.md`, раздел "Что требует внимания при эксплуатации").

Идея: открыть TCP до настоящего IP Telegram не с самого Server A, а из
сети Cloudflare — у неё свой исходящий маршрут, и с Telegram у неё,
вероятно, чистая связность (то же допущение, на котором уже держится
`cfproxy_worker_domains`-fallback у оригинального `tg-ws-proxy` для
MTProto-пути — `worker.js` использует ту же идею, только для сырого
passthrough вместо MTProto-фреймов). Server A достаёт до Worker'а обычным
WebSocket через Cloudflare edge (не заблокирован — обычный
`*.workers.dev`), Worker сам открывает `cloudflare:sockets`-соединение
до настоящего IP Telegram и гоняет байты в обе стороны без разбора
содержимого — TLS остаётся end-to-end клиент↔Telegram, Worker его не
видит и не терминирует.

**Подтверждено живым трафиком 2026-09-01** — задеплоено на Server A,
`web.telegram.org` открылся полностью через VLESS-туннель. В логе
`tg-transparent-relay` видно, что прямой TCP к `149.154.167.99` по-прежнему
падает по таймауту (SYN null-route никуда не делся), а fallback через
Worker проходит без единой ошибки — значит у Cloudflare действительно
чистая связность до этого IP, допущение выше подтвердилось не только
для голой страницы, но и для реальных WS-эндпоинтов данных
(`zws2.web.telegram.org`, `kws2.web.telegram.org`,
`venus.web.telegram.org` — то есть не просто статика, а живые
сообщения). Первый прогон деплоя споткнулся на человеческой ошибке, не
на архитектуре — в `tgrelay.env` буквально вписали плейсхолдер
`<тот же секрет...>` вместо настоящего значения из `wrangler secret put`,
из-за чего Worker отвечал 403 всем запросам; после исправления секрета
заработало сразу.

## Деплой

Нужен Cloudflare-аккаунт с включённым Workers (бесплатного плана
достаточно) и `wrangler` (Cloudflare CLI):

```bash
npm install -g wrangler
cd relay/cf_worker
wrangler login          # откроет браузер для авторизации

wrangler deploy          # первый деплой -- создаст воркер по имени
                          # из wrangler.toml (zenith-tg-relay), выведет
                          # его адрес вида
                          # https://zenith-tg-relay.<subdomain>.workers.dev

wrangler secret put RELAY_SECRET
# запросит значение интерактивно -- ввести длинную случайную строку,
# например: openssl rand -hex 32
# ЭТО НЕ MTProxy-секрет и не связано с ним -- отдельный секрет,
# защищающий сам Worker от использования кем угодно, кто угадает URL.
```

После деплоя у вас будет:
- домен воркера (например, `zenith-tg-relay.<subdomain>.workers.dev`)
- секрет, который вы сами задали через `wrangler secret put`

## Подключение к relay

Прописать в `/etc/z2r_autobench/tgrelay.env` на Server A (создать, если
нет — `tg-transparent-relay.service` уже подключает его как
`EnvironmentFile=-`, см. сам unit-файл):

```
ZTG_CF_WORKER_HOST=zenith-tg-relay.<subdomain>.workers.dev
ZTG_CF_WORKER_SECRET=<тот же секрет, что задали через wrangler secret put>
```

```bash
systemctl restart tg-transparent-relay
journalctl -u tg-transparent-relay -f
# при старте должна появиться строка:
#   "Cloudflare Worker fallback включён: zenith-tg-relay.<subdomain>.workers.dev"
```

Можно также передать через флаги CLI напрямую (`--cf-worker-host`,
`--cf-worker-secret`) — например, при ручном запуске для отладки
(`transparent_relay.py -v`), но на проде удобнее env-файл, чтобы не
светить секрет в `ps`/systemd unit.

Если переменные не заданы (файл отсутствует или пустой) — поведение
как раньше, passthrough к заблокированным IP просто не удаётся и
разрывается, без ошибок и без деградации остального (MTProto-путь
Worker'а вообще не касается).

## Проверка

С любого устройства, ходящего через VLESS-туннель до Server A:

```
https://web.telegram.org/
```

В логе relay при успешном fallback должна появиться строка вида:

```
[<клиент>] прямой TCP к 149.154.167.99:443 не удался -- ушли через Cloudflare Worker zenith-tg-relay.<subdomain>.workers.dev
```

Если вместо этого видно `Cloudflare Worker fallback к ... тоже не
удался` — либо неверный секрет/домен в `tgrelay.env`, либо у самого
Cloudflare тоже нет связности до этого IP Telegram (в этом случае
подход не решает задачу, см. предупреждение выше).

## Безопасность / почему не открытый релей

`worker.js` сознательно ограничен:
- `dst` разрешён **только** из официальных подсетей Telegram
  (`ALLOWED_CIDRS`, тот же список, что `cidr/telegram_ipv4.txt` —
  обновлять оба списка вместе, если Telegram изменит подсети);
- обязателен `RELAY_SECRET` — без него 403, чтобы Worker не мог стать
  открытым TCP-релеем для кого угодно, кто угадает его URL.

Тем не менее это дополнительная сущность с доступом в интернет от
имени вашего Cloudflare-аккаунта — считайте секрет из
`wrangler secret put` таким же чувствительным, как любой другой
production-секрет.
