#!/usr/bin/env bash
# deploy.sh -- одна команда вместо ручной пляски с wrangler/секретом,
# описанной в README.md ниже. Живой повод: первый ручной прогон на
# Server A (2026-09-01) споткнулся именно на копипасте -- в wsrelay.env
# буквально попал плейсхолдер "<тот же секрет...>" вместо настоящего
# значения, и "Cloudflare Worker fallback включён" в логе всё равно
# печаталось (проверка там -- просто непустая строка, не валидность),
# так что баг молчал, пока не проверили живым трафиком.
#
# ЭТОТ СКРИПТ НЕ "ЗАШИВАЕТ" СЕКРЕТ В РЕПОЗИТОРИЙ -- см. README.md
# "Почему нельзя просто закоммитить готовый секрет": воркер висит на
# ЛИЧНОМ Cloudflare-аккаунте того, кто деплоит, RELAY_SECRET защищает
# именно ЕГО квоту/аккаунт от чужого использования, если кто-то угадает
# URL воркера. Секрет генерируется ЗАНОВО при каждом запуске этого
# скрипта -- свой на каждый сервер, никогда не переиспользуется и
# никогда никуда не коммитится.
#
# Единственный обязательный ручной ввод -- Cloudflare API-токен (без
# учётки Cloudflare развернуть воркер физически негде, это не наш
# секрет, а чужого сервиса):
#   export CLOUDFLARE_API_TOKEN=...   # шаблон "Edit Cloudflare Workers"
#   sudo -E ./deploy.sh
#
# ...но только В ПЕРВЫЙ раз на конкретном сервере. После успешного
# деплоя токен кэшируется в САМ $ENV_FILE (chmod 600, тот же файл, что
# уже хранит ZWS_MTPROXY_SECRET/ZWS_CF_WORKER_SECRET -- секреты этого
# проекта и так живут только там, ничего нового не открываем) -- любой
# следующий запуск deploy.sh на ЭТОМ ЖЕ сервере подхватывает его сам,
# без единого вопроса. Разворачиваешь на ДРУГОМ сервере -- там своего
# кэша ещё нет, там ввод один раз повторится, это неизбежно (без
# учётки Cloudflare там в принципе некуда деплоить).
#
# НЕ храним токен где-либо ЕЩЁ (напр. в облаке типа Google Drive, даже
# приватно) -- см. README.md "Почему нельзя просто закоммитить готовый
# секрет": единственный способ деплою прочитать секрет откуда-либо
# автоматически -- это дать ЕМУ доступ к тому хранилищу, а это просто
# переносит тот же самый вопрос секретности на СЛЕДУЮЩИЙ уровень (теперь
# нужен ещё и секрет для доступа к хранилищу) и добавляет менее
# контролируемую поверхность (публичная ссылка = скачать может кто
# угодно, у кого есть URL, без журналирования доступа и отзыва, которые
# у самого Cloudflare для его токенов есть). Локальный файл с правами
# 600 на конкретной машине, куда токен реально нужен -- меньшая и более
# понятная поверхность, чем что-либо в облаке.
# Использование: deploy.sh [--env-file PATH] [--skip-redirect]
#   --env-file PATH   -- куда писать ZWS_CF_WORKER_HOST/SECRET
#                        (по умолчанию /etc/z2r_autobench/wsrelay.env,
#                        тот же файл, что ws-transparent-relay.service
#                        уже подключает через EnvironmentFile=-).
#   --skip-redirect   -- не трогать iptables (только задеплоить воркер
#                        и прописать env) -- на случай, если REDIRECT
#                        уже применён отдельно или сервис ещё не
#                        поставлен вообще.

set -euo pipefail

# На самом первом в жизни машины запуске wrangler может спросить
# интерактивное согласие на анонимную телеметрию -- этот скрипт читает
# `wrangler deploy` через `$(...)`, так что сам вопрос ушёл бы в
# захваченный вывод незамеченным, а stdin никуда не делся, так что со
# стороны это выглядело бы как зависший без причины деплой. Отключаем
# явно вместо того чтобы на это надеяться.
export WRANGLER_SEND_METRICS=false

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RELAY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ENV_FILE=/etc/z2r_autobench/wsrelay.env
SKIP_REDIRECT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --skip-redirect) SKIP_REDIRECT=1; shift ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

command -v wrangler >/dev/null 2>&1 || {
  echo "wrangler не найден. Установка (нужен Node >=22 -- Debian's apt даёт" >&2
  echo "только v20, wrangler с ним не стартует):" >&2
  echo "  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash" >&2
  echo "  export NVM_DIR=\"\$HOME/.nvm\"; . \"\$NVM_DIR/nvm.sh\"" >&2
  echo "  nvm install 22 && npm install -g wrangler" >&2
  exit 1
}

# Если не передан явно -- пробуем взять из кэша (см. комментарий выше
# про запись в конце скрипта). grep|cut вместо `source "$ENV_FILE"` --
# файл может содержать чужие для этого скрипта переменные, не хотим
# случайно исполнить что-то неожиданное из него.
if [ -z "${CLOUDFLARE_API_TOKEN:-}" ] && [ -f "$ENV_FILE" ]; then
  # `|| true` -- живой баг 2026-09-09: под `set -o pipefail` пустой grep
  # (переменная ещё ни разу не была записана в файл) отдаёт код ошибки,
  # который ПРОТАСКИВАЕТСЯ через весь пайплайн даже когда tail/cut после
  # него успешны -- под `set -e` это тихо убивает скрипт РОВНО на этой
  # строке, без единого сообщения об ошибке (см. остальные три таких же
  # места ниже -- тот же паттерн, тот же фикс).
  CLOUDFLARE_API_TOKEN="$(grep '^CLOUDFLARE_API_TOKEN=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
  [ -n "$CLOUDFLARE_API_TOKEN" ] && echo "==> Использую CLOUDFLARE_API_TOKEN из кэша ($ENV_FILE)." >&2
fi

[ -n "${CLOUDFLARE_API_TOKEN:-}" ] || {
  echo "CLOUDFLARE_API_TOKEN не задан и не найден в $ENV_FILE. Создай токен на" >&2
  echo "https://dash.cloudflare.com/profile/api-tokens (шаблон \"Edit Cloudflare" >&2
  echo "Workers\" достаточен), затем: export CLOUDFLARE_API_TOKEN=..." >&2
  exit 1
}
# Живой баг 2026-09-09: чтение из кэша выше (grep|tail|cut) заводит
# ОБЫЧНУЮ, неэкспортированную переменную -- `wrangler` ниже видит только
# унаследованное окружение дочернего процесса, не переменные родительского
# шелла. Кэш-путь из-за этого ни разу реально не доносил токен до
# wrangler: он либо падал раньше (см. `|| true` фикс чуть выше того же
# дня), либо, как выяснилось при первом реальном прогоне после того
# фикса, доходил до `wrangler deploy`, но тот отвечал "необходимо
# установить переменную окружения CLOUDFLARE_API_TOKEN", хотя сам скрипт
# видел непустую $CLOUDFLARE_API_TOKEN (проверка чуть выше уже прошла) --
# путаница именно exported vs unexported. Безопасно ставить здесь
# безусловно: до этой строки код уже гарантированно вышел бы, если бы
# токена не было вообще.
export CLOUDFLARE_API_TOKEN

cd "$SCRIPT_DIR"

# ALLOW_TELEGRAM/ALLOW_WHATSAPP в wrangler.toml -- независимое
# включение/выключение доступа к web.telegram.org/web.WhatsApp через
# ЭТОТ воркер (добавлено 2026-09-04, см. CLAUDE.md "Независимое
# включение/выключение Telegram и WhatsApp"). Читаем сохранённое
# состояние из ENV_FILE (ZWS_TELEGRAM_WORKER/ZWS_WHATSAPP_WORKER,
# записывается z0r'ом при переключении) -- по умолчанию "enabled" для
# обоих, чтобы сервер, ни разу не трогавший новый тумблер, продолжал
# работать как раньше (оба всегда были разрешены безусловно). Правим
# wrangler.toml через sed, а не `wrangler deploy --var` -- текущее
# состояние тогда видно прямо в файле, а не только в истории вызовов
# этого скрипта.
tg_worker_state="enabled"; wa_worker_state="enabled"
if [ -f "$ENV_FILE" ]; then
  # `|| true` на обеих -- см. комментарий у первого такого места выше.
  tg_worker_state="$(grep '^ZWS_TELEGRAM_WORKER=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
  wa_worker_state="$(grep '^ZWS_WHATSAPP_WORKER=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
  [ -n "$tg_worker_state" ] || tg_worker_state="enabled"
  [ -n "$wa_worker_state" ] || wa_worker_state="enabled"
fi
tg_var="true"; [ "$tg_worker_state" = "disabled" ] && tg_var="false"
wa_var="true"; [ "$wa_worker_state" = "disabled" ] && wa_var="false"
sed -i "s/^ALLOW_TELEGRAM = .*/ALLOW_TELEGRAM = \"$tg_var\"/" wrangler.toml
sed -i "s/^ALLOW_WHATSAPP = .*/ALLOW_WHATSAPP = \"$wa_var\"/" wrangler.toml
echo "==> Воркер: web.telegram.org=$tg_worker_state, web.WhatsApp=$wa_worker_state" >&2

echo "==> Деплой воркера (wrangler deploy)..." >&2
DEPLOY_OUT="$(wrangler deploy 2>&1)" || { echo "$DEPLOY_OUT" >&2; exit 1; }
echo "$DEPLOY_OUT" >&2

WORKER_HOST="$(printf '%s\n' "$DEPLOY_OUT" | grep -oE 'https://[a-zA-Z0-9.-]+\.workers\.dev' | head -1 | sed 's#^https://##')"
[ -n "$WORKER_HOST" ] || {
  echo "Не удалось найти адрес воркера в выводе wrangler deploy выше -- деплой" >&2
  echo "мог пройти, но домен придётся прописать в $ENV_FILE вручную." >&2
  exit 1
}
echo "==> Воркер: https://$WORKER_HOST" >&2

echo "==> Генерирую новый RELAY_SECRET (свой на этот сервер, не переиспользуется)..." >&2
SECRET="$(openssl rand -hex 32)"
printf '%s' "$SECRET" | wrangler secret put RELAY_SECRET >&2

# Идемпотентная запись в env-файл -- та же sed-или-append схема, что
# z0r уже использует для ZENITH_PROFILES и т.п. (см. z2r_autobench/z0r).
# Не трогает остальные строки файла (ZWS_MTPROXY_SECRET и т.п.).
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
# CLOUDFLARE_API_TOKEN кэшируется тут же ТОЛЬКО после успешного
# деплоя+secret put выше -- если что-то из этого упало (see errexit),
# до сюда исполнение не доходит, кэш не запишется с непроверенным
# значением.
for kv in "ZWS_CF_WORKER_HOST=$WORKER_HOST" "ZWS_CF_WORKER_SECRET=$SECRET" "CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN"; do
  key="${kv%%=*}"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s#^${key}=.*#${kv}#" "$ENV_FILE"
  else
    echo "$kv" >> "$ENV_FILE"
  fi
done
echo "==> Записано в $ENV_FILE (права 600 — там же теперь и CLOUDFLARE_API_TOKEN, для следующего запуска без вопросов)." >&2

# Telegram и WhatsApp REDIRECT теперь независимо включаются/выключаются
# (z0r пункт 14 -> 3 -> "Telegram/WhatsApp по отдельности", был пункт 22,
# потом 31, см. z2r_autobench/CLAUDE.md для полной истории перенумерации
# "Независимое включение/выключение Telegram и WhatsApp") -- этот скрипт
# может быть вызван повторно просто чтобы обновить/задеплоить воркер
# заново (напр. ротация секрета), и НЕ должен молча включать обратно
# список, который человек осознанно выключил (напр. WhatsApp сломал
# Instagram на том же ASN, живой случай, послуживший поводом для самого
# разделения). Дефолт -- "enabled" для ОБОИХ, чтобы поведение на первом
# в жизни сервера деплое не изменилось (раньше эти два apply были
# безусловными).
if [ "$SKIP_REDIRECT" = "0" ]; then
  tg_state="enabled"; wa_state="enabled"
  if [ -f "$ENV_FILE" ]; then
    # `|| true` на обеих -- см. комментарий у первого такого места выше.
    tg_state="$(grep '^ZWS_TELEGRAM_REDIRECT=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
    wa_state="$(grep '^ZWS_WHATSAPP_REDIRECT=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
    [ -n "$tg_state" ] || tg_state="enabled"
    [ -n "$wa_state" ] || wa_state="enabled"
  fi
  if [ "$tg_state" = "disabled" ]; then
    echo "==> Telegram REDIRECT пропущен (отмечен как выключенный в $ENV_FILE)." >&2
  else
    echo "==> Применяю REDIRECT (Telegram)..." >&2
    "$RELAY_DIR/setup_redirect.sh" apply
  fi
  if [ "$wa_state" = "disabled" ]; then
    echo "==> WhatsApp REDIRECT пропущен (отмечен как выключенный в $ENV_FILE)." >&2
  else
    echo "==> Применяю REDIRECT (WhatsApp, порты 443+5222 -- см. CLAUDE.md 2026-09-09)..." >&2
    "$RELAY_DIR/setup_redirect.sh" apply --cidr-file "$RELAY_DIR/../cidr/whatsapp_ipv4.txt" --dports 443,5222
  fi
fi

if systemctl list-unit-files ws-transparent-relay.service >/dev/null 2>&1; then
  echo "==> Перезапускаю ws-transparent-relay..." >&2
  systemctl restart ws-transparent-relay
  echo "==> Готово. Проверь: journalctl -u ws-transparent-relay -f" >&2
else
  echo "==> ws-transparent-relay.service не установлен -- воркер задеплоен и" >&2
  echo "    env прописан, но сам релей нужно поставить отдельно (см. README.md" >&2
  echo "    основного репозитория, 'Развёртывание на сервере')." >&2
fi
