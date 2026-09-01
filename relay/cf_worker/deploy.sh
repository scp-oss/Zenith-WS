#!/usr/bin/env bash
# deploy.sh -- одна команда вместо ручной пляски с wrangler/секретом,
# описанной в README.md ниже. Живой повод: первый ручной прогон на
# Server A (2026-09-01) споткнулся именно на копипасте -- в tgrelay.env
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
# Использование: deploy.sh [--env-file PATH] [--skip-redirect]
#   --env-file PATH   -- куда писать ZTG_CF_WORKER_HOST/SECRET
#                        (по умолчанию /etc/z2r_autobench/tgrelay.env,
#                        тот же файл, что tg-transparent-relay.service
#                        уже подключает через EnvironmentFile=-).
#   --skip-redirect   -- не трогать iptables (только задеплоить воркер
#                        и прописать env) -- на случай, если REDIRECT
#                        уже применён отдельно или сервис ещё не
#                        поставлен вообще.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RELAY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ENV_FILE=/etc/z2r_autobench/tgrelay.env
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

[ -n "${CLOUDFLARE_API_TOKEN:-}" ] || {
  echo "CLOUDFLARE_API_TOKEN не задан. Создай токен на" >&2
  echo "https://dash.cloudflare.com/profile/api-tokens (шаблон \"Edit Cloudflare" >&2
  echo "Workers\" достаточен), затем: export CLOUDFLARE_API_TOKEN=..." >&2
  exit 1
}

cd "$SCRIPT_DIR"

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
# Не трогает остальные строки файла (ZTG_MTPROXY_SECRET и т.п.).
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
for kv in "ZTG_CF_WORKER_HOST=$WORKER_HOST" "ZTG_CF_WORKER_SECRET=$SECRET"; do
  key="${kv%%=*}"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s#^${key}=.*#${kv}#" "$ENV_FILE"
  else
    echo "$kv" >> "$ENV_FILE"
  fi
done
echo "==> Записано в $ENV_FILE" >&2

if [ "$SKIP_REDIRECT" = "0" ]; then
  echo "==> Применяю REDIRECT (Telegram + WhatsApp)..." >&2
  "$RELAY_DIR/setup_redirect.sh" apply
  "$RELAY_DIR/setup_redirect.sh" apply --cidr-file "$RELAY_DIR/../cidr/whatsapp_ipv4.txt"
fi

if systemctl list-unit-files tg-transparent-relay.service >/dev/null 2>&1; then
  echo "==> Перезапускаю tg-transparent-relay..." >&2
  systemctl restart tg-transparent-relay
  echo "==> Готово. Проверь: journalctl -u tg-transparent-relay -f" >&2
else
  echo "==> tg-transparent-relay.service не установлен -- воркер задеплоен и" >&2
  echo "    env прописан, но сам релей нужно поставить отдельно (см. README.md" >&2
  echo "    основного репозитория, 'Развёртывание на сервере')." >&2
fi
