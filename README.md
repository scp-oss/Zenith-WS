# Zenith-WS

Прозрачный модуль доступа к Telegram для инфраструктуры z2r_autobench —
без ручной настройки MTProto-прокси в приложении, без модифицированных
клиентов, без десинка пакетов (не сработал в этом случае — см. ниже).

## Происхождение

Основан на [`Flowseal/tg-ws-proxy`](https://github.com/Flowseal/tg-ws-proxy)
(MIT). `relay/vendor/` — прямая копия его релейного слоя (пул
WebSocket-соединений к Telegram, Cloudflare-фронтинг/worker fallback,
балансировка доменов) без изменений, см.
`relay/vendor/LICENSE.tg-ws-proxy`. Не оформлено как формальный GitHub
fork (создавался независимо, не через кнопку Fork — задним числом эта
связь на GitHub не переключается) — вместо оригинального клиентского
"коннектора" `tg-ws-proxy` (требует MTProxy-секрет от клиента, см.
ниже) здесь используется собственный `relay/transparent_relay.py`,
плюс весь остальной модуль (`prober/`, `cidr/`, `zapret2/`, тесты) —
код этого репозитория, не из `tg-ws-proxy`.

## Итог расследования (коротко)

На реальном сервере (Server A) прямой доступ к Telegram оказался
заблокирован не по протоколу/сигнатуре (значит, `zapret2`/`nfqws2`
десинк не поможет в принципе — испробовано, подтверждено), а по
IP-блэклисту: несколько конкретных, широко известных IP Telegram-DC
(`149.154.175.50`, `149.154.167.51`, `149.154.175.100`, `149.154.167.91`,
`149.154.171.5`, `149.154.167.99`) заблокированы целиком на уровне
аплинка, а другой, менее известный IP той же подсети —
**`149.154.167.220`** — работает штатно. Голый TCP до него отвечает за
~0.2с.

[`Flowseal/tg-ws-proxy`](https://github.com/Flowseal/tg-ws-proxy) как
раз по умолчанию использует именно этот IP (плюс запасной путь через
Cloudflare-домены на случай, если и он окажется заблокирован) — поэтому
он и "просто работал", когда его протестировали как обычный
MTProto-прокси.

Проблема с исходным `tg-ws-proxy` — не связность, а то, что MTProxy как
протокол **обязывает клиента знать секрет** (секрет вшит в формулу
вывода ключа шифрования, `SHA256(prekey + secret)` — это не галочка
доступа, которую можно выключить, а часть математики). Значит ручная
настройка прокси в каждом приложении неизбежна, если использовать
`tg-ws-proxy` "как есть".

## Решение: `relay/transparent_relay.py`

Взяли у `tg-ws-proxy` (MIT, см. `relay/vendor/LICENSE.tg-ws-proxy`)
рабочую **релейную** часть как есть (пул WebSocket-соединений к
`.220`, Cloudflare-фронтинг/worker fallback — всё, что реально умеет
достучаться до Telegram) и заменили только **коннектор** — приёмный
слой, декодирующий входящий пакет клиента. Вместо
`SHA256(prekey + secret)` используется формула **настоящего прямого
клиента Telegram** (сырой ключ без секрета, тот же код, что и в
`prober/proto.py`). Результат: клиенту (обычному, немодифицированному
Telegram Desktop/mobile) вообще не нужно ничего настраивать — реле
принимает его как будто оно и есть Telegram, декодирует DC из
init-пакета и уже само решает, как реально до Telegram достучаться.

Прозрачность достигается `iptables REDIRECT`: исходящий TCP:443-трафик
к официальным подсетям Telegram молча заворачивается на локальный порт
релея — работает как для процессов на самом сервере, так и для
клиентов, туннелирующих трафик через этот сервер (Xray/VLESS-outbound
делает обычный локальный `connect()`, значит подпадает под ту же
`OUTPUT`-цепочку — проверено вживую).

Подтверждено сквозным тестом (`tests/test_transparent_relay_e2e.py`):
симулированный "прямой" клиент получает настоящий `resPQ` от Telegram
через релей — не только для DC, на которые указывает дефолтный
`.220`-редирект (DC2/DC4), но и для любого другого DC — релейная часть
сама подхватывает недостающие через Cloudflare-fallback.

## Альтернатива: `relay/mtproxy_relay.py` (настоящий MTProxy с секретом)

Живой случай (2026-08-22, полный разбор — `CLAUDE.md`, "Android MTProto
investigation"): прозрачный no-secret `transparent_relay.py` работает на
iPhone, но не на Android — байтовый захват показал, что Android-клиент
без явно настроенного прокси шлёт настоящий TLS ClientHello к реальным
IP датацентров вместо ожидаемого сырого obfuscated2-формата. Причина не
установлена (открытый вопрос в `CLAUDE.md`), но факт в том, что
"прозрачная" идея не универсальна для всех платформ/сборок клиента.

`relay/mtproxy_relay.py` — прямой запуск оригинального
`vendor/tg_ws_proxy.py` (тот же апстрим, СОВСЕМ не изменён, только
импортирован как модуль) как отдельного сервиса: настоящий MTProxy-
протокол с секретом, клиент настраивается явной `tg://proxy?...`
ссылкой/QR — тот же принцип, что и у любого обычного MTProxy, без
всякого REDIRECT/угадывания. Раньше (до адаптации под транспарентный
режим) этот же код в исходном виде работал одинаково на обеих
платформах, так что это не эксперимент, а откат к подтверждённо рабочему
пути для случаев, когда транспарентный режим не заводится.

```bash
cd relay
# первый ручной запуск -- получить секрет и готовую ссылку из лога
python3 mtproxy_relay.py --host 0.0.0.0 --port 9443
# дальше зафиксировать тот же секрет в /etc/z2r_autobench/wsrelay.env
# (ZWS_MTPROXY_SECRET=..., ZWS_MTPROXY_PORT=9443) и поставить как
# systemd-сервис, см. ws-mtproxy-relay.service
```

Слушает на публичном интерфейсе (не `127.0.0.1`, в отличие от
`transparent_relay.py`) — это ожидаемо и безопасно: контроль доступа тут
сам секрет, а не сетевая изоляция (у прозрачного релея контроля доступа
вообще нет, поэтому ОН обязан сидеть только на loopback).

## Состав

```
prober/
  proto.py            -- независимая реализация init-пакета
                          obfuscated-транспорта MTProto
  mtproto_probe.py     -- CLI-зонд DPI/IP-блокировки (baseline-диагностика)
cidr/
  fetch_telegram_cidr.sh  -- официальный список подсетей Telegram
  telegram_ipv4.txt       -- снапшот
relay/
  transparent_relay.py    -- прозрачный коннектор (без секрета)
  vendor/                 -- вендоренная relay-машинерия tg-ws-proxy (MIT)
  ws-transparent-relay.service -- systemd unit
  setup_redirect.sh        -- iptables REDIRECT apply/remove/status
  redirect_watchdog.sh     -- проверяет и восстанавливает REDIRECT-правила,
                             если их смахнёт посторонний сервис
  ws-redirect-watchdog.service/.timer -- systemd unit + таймер (каждые 5 мин)
  mtproxy_relay.py         -- настоящий MTProxy с секретом (альтернатива)
  ws-mtproxy-relay.service -- systemd unit для mtproxy_relay.py
  cf_worker/               -- опциональный fallback для passthrough
                             (web.telegram.org и т.п.) через Cloudflare
                             Worker -- см. cf_worker/README.md
zapret2/
  TG_MTPROTO.block.conf   -- ЧЕРНОВИК десинк-профиля -- НЕ СРАБОТАЛ на
                             реальном IP-блэклисте (см. strategies.md),
                             оставлен для случаев, когда блокировка
                             именно сигнатурная, а не по IP
  strategies.md
tests/
  test_proto.py                  -- юнит-тесты пакета (без сети)
  test_transparent_relay_e2e.py  -- сквозной тест (нужна сеть)
```

## Быстрый старт

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Обновить список подсетей Telegram
bash cidr/fetch_telegram_cidr.sh

# Тесты
.venv/bin/python3 tests/test_proto.py
.venv/bin/python3 tests/test_transparent_relay_e2e.py   # нужна сеть

# Запуск релея вручную (для проверки перед systemd)
.venv/bin/python3 relay/transparent_relay.py --host 127.0.0.1 --port 8447 -v
```

## Развёртывание на сервере

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin wsrelay
chown -R wsrelay:wsrelay /opt/Zenith-WS

cp relay/ws-transparent-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ws-transparent-relay

# Прозрачный REDIRECT (нужен root, меняет iptables)
sudo bash relay/setup_redirect.sh apply
sudo bash relay/setup_redirect.sh status   # проверить, что правила встали

# Watchdog: правила REDIRECT живут в nat OUTPUT независимо от самого
# relay-сервиса, и их может смахнуть побочным эффектом какой-то другой,
# формально не связанный процесс (живой случай 2026-08-23 — см. CLAUDE.md,
# краш-луп zapret2.service из z2r_autobench задел их своим собственным
# "Clearing iptables"). Сам relay при этом продолжает работать штатно и
# не может это заметить — таймер раз в 5 минут проверяет и молча
# восстанавливает, если правила пропали целиком.
cp relay/ws-redirect-watchdog.service relay/ws-redirect-watchdog.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ws-redirect-watchdog.timer
```

Откат: `sudo bash relay/setup_redirect.sh remove` + `systemctl disable --now ws-transparent-relay ws-redirect-watchdog.timer`.

**Слушать `transparent_relay.py` ТОЛЬКО на `127.0.0.1`** — без секрета
нет контроля доступа, трафик должен приходить исключительно через
локальный `REDIRECT`, не выставлять порт наружу напрямую.

## Что требует внимания при эксплуатации

- **REDIRECT-правила в `nat OUTPUT` может смахнуть побочным эффектом
  совершенно посторонний сервис** — живой случай 2026-08-23 на Server A:
  краш-луп `zapret2.service` (из отдельного репо `z2r_autobench`, три
  рестарта подряд за ~20с) стёр все правила Zenith-WS в `nat OUTPUT`,
  хотя формально разные таблицы/логика — `relay/transparent_relay.py`
  при этом продолжал работать штатно (слушает только `127.0.0.1:8447`,
  ему всё равно, заворачивает ли что-то трафик), просто трафик перестал
  доходить, и телеграм на iOS через VLESS сломался тихо на всю ночь,
  никто не заметил. Митигировано `relay/redirect_watchdog.sh` +
  `ws-redirect-watchdog.timer` (раз в 5 минут проверяет и молча
  восстанавливает, если правил REDIRECT не осталось вообще) — см.
  «Развёртывание на сервере» выше. Не решает первопричину (это не в
  нашей власти — сторонний сервис), только сокращает окно простоя.
- `149.154.167.220` (или найденный аналог) может сам попасть в
  блэклист в будущем — тогда `dc_redirects` в `transparent_relay.py`
  нужно будет обновить на новый рабочий IP; Cloudflare-fallback
  внутри `relay/vendor/` при этом продолжит работать как запасной путь.
- `cidr/telegram_ipv4.txt` устаревает — периодически перезапускать
  `fetch_telegram_cidr.sh` и переприменять `setup_redirect.sh apply`
  (идемпотентно добавит новые записи; для чистоты сначала `remove`,
  потом `apply`, если список сильно изменился).
- `zapret2/TG_MTPROTO.block.conf` — рабочий десинк-профиль ТАК И НЕ
  найден (блокировка на тестовом сервере оказалась IP-based, не
  сигнатурной) — черновик оставлен на случай, если у другого
  провайдера/сервера блокировка будет именно DPI-сигнатурной, тогда он
  может пригодиться после живой проверки синтаксиса операторов.
- **`setup_redirect.sh` ОБЯЗАН исключать собственный исходящий трафик
  relay** (`-m owner --uid-owner wsrelay -j RETURN` перед REDIRECT-
  правилами, уже в скрипте) — без этого relay заворачивает СВОИ ЖЕ
  попытки достучаться до Telegram сам на себя (self-loop через
  localhost). Живой случай на Server A: это давало ложное впечатление
  "IP доступен" (loopback всегда быстрый/надёжный), маскируя реальный
  таймаут — несколько часов отладки ушло, пока не сравнили `curl` с
  REDIRECT и без него напрямую. Если меняете `--user`/переименовываете
  системного пользователя relay — обязательно обновите и это правило.
- **`web.telegram.org` (браузерная версия) на Server A по умолчанию не
  работает** — его реальный IP (`149.154.167.99`, тот же, что у
  `kws2.web.telegram.org` из `dc_redirects`) заблокирован так же, как
  исходные "боевые" IP Telegram-DC, и, в отличие от MTProto-пути,
  эквивалента `.220` для него не нашли (это не MTProto-релей с гибким
  выбором сервера, а прямой сайт — заменить не на что). Приложение
  Telegram (Desktop/mobile) при этом работает нормально — проблема
  затрагивает только браузерную версию.
  Опциональный обходной путь: `_passthrough_plain_tcp` умеет уходить
  через Cloudflare Worker (`relay/cf_worker/`, `cloudflare:sockets`),
  если он задеплоен и настроен через `ZWS_CF_WORKER_HOST`/
  `ZWS_CF_WORKER_SECRET` — см. `relay/cf_worker/README.md`. Не
  гарантированное решение (зависит от связности самого Cloudflare с
  этим IP Telegram, не проверено на реальном трафике на момент
  написания) и требует отдельного Cloudflare-аккаунта — без настройки
  ничего не меняется, relay ведёт себя как раньше.

## Лицензия

MIT. `relay/vendor/` содержит код Flowseal/tg-ws-proxy (тоже MIT, см.
`relay/vendor/LICENSE.tg-ws-proxy`), использован по условиям лицензии.
