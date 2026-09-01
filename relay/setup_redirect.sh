#!/usr/bin/env bash
# setup_redirect.sh -- прозрачно перенаправляет исходящий TCP:443 трафик
# к официальным подсетям Telegram (см. ../cidr/telegram_ipv4.txt) на
# локальный transparent_relay.py (127.0.0.1:8447 по умолчанию).
#
# ПОЧЕМУ REDIRECT в OUTPUT-цепочку, а не PREROUTING/FORWARD: трафик,
# который реально нужно перехватывать здесь -- это то, что ЛОКАЛЬНО
# порождает сам сервер (в т.ч. Xray/VLESS "freedom"-outbound делает для
# туннелированных клиентов ОБЫЧНЫЙ локальный socket.connect(), это и
# есть OUTPUT, не FORWARD, проверено вживую на Server A при разборе
# DNAT-варианта этого же профиля).
#
# КРИТИЧНО: REDIRECT в OUTPUT матчит ЛЮБОЕ локально исходящее
# соединение к подсетям Telegram -- включая исходящие соединения
# САМОГО relay (relay/transparent_relay.py), когда он в passthrough
# пытается сам подключиться к настоящему IP! Без исключения это
# self-loop: relay думает, что говорит с Telegram, а на самом деле
# снова попадает сам на себя через REDIRECT. Живой случай на Server A:
# это давало ложное впечатление, что TCP до 149.154.167.99 "работает"
# (loopback всегда быстрый и надёжный), хотя реальный IP в этот момент
# был недоступен -- нашли только сравнив с curl БЕЗ REDIRECT вообще.
# Исправлено через -m owner --uid-owner (сервис работает под отдельным
# системным пользователем wsrelay, см. ws-transparent-relay.service) --
# трафик ОТ этого пользователя пропускается мимо REDIRECT (RETURN),
# должно стоять ПЕРЕД правилами REDIRECT.
#
# Использование:
#   setup_redirect.sh apply [--port N] [--user NAME] [--cidr-file PATH]
#   setup_redirect.sh remove [--port N] [--user NAME] [--cidr-file PATH]
#   setup_redirect.sh status
#
# --cidr-file добавлен 2026-09-01 для WhatsApp (см.
# ../cidr/whatsapp_ipv4.txt) -- та же схема, что уже работает для
# Telegram (SYN-блэкхол -> REDIRECT на transparent_relay.py -> passthrough
# -> Cloudflare Worker fallback), другой список подсетей. Вызывается
# ВТОРЫМ разом, отдельно от Telegram-списка, с тем же портом --
# transparent_relay.py уже общий (классифицирует по содержимому
# пакета, не по тому, из-за какого REDIRECT-правила трафик сюда попал).
#
# ВАЖНО про несколько CIDR-файлов сразу: exclusion self-loop'а (см. ниже)
# общий на ВСЕ REDIRECT-правила, не привязан к конкретному файлу.
# `remove` для ОДНОГО файла всё равно попытается убрать этот exclusion --
# если активны оба файла (Telegram + WhatsApp), убирать/переприменять их
# нужно ВМЕСТЕ, а не по одному, иначе на секунду останутся REDIRECT-правила
# без self-loop-защиты для оставшегося файла. `apply` теперь полностью
# идемпотентен -- и exclusion, и каждое REDIRECT-правило проверяются через
# `-C` перед добавлением (2026-09-01: раньше только exclusion был
# идемпотентен, а сами REDIRECT-правила дублировались при каждом повторном
# apply -- живой риск, т.к. cf_worker/deploy.sh вызывает apply безусловно
# на каждом запуске, в т.ч. на сервере, где REDIRECT уже стоит с первой
# установки) -- можно вызывать apply сколько угодно раз подряд, с любым
# --cidr-file, без накопления дублей.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CIDR_FILE="$SCRIPT_DIR/../cidr/telegram_ipv4.txt"
PORT=8447
RELAY_USER=wsrelay
ACTION="${1:-}"
shift || true

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --user) RELAY_USER="$2"; shift 2 ;;
    --cidr-file) CIDR_FILE="$2"; shift 2 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

[ -f "$CIDR_FILE" ] || { echo "Не найден $CIDR_FILE -- сначала запустите cidr/fetch_telegram_cidr.sh" >&2; exit 1; }

mapfile -t CIDRS < <(grep -vE '^\s*#|^\s*$' "$CIDR_FILE")
[ "${#CIDRS[@]}" -gt 0 ] || { echo "$CIDR_FILE пуст -- нечего перенаправлять" >&2; exit 1; }

case "$ACTION" in
  apply)
    # Исключение ПЕРВЫМ -- собственный исходящий трафик relay (см.
    # предупреждение о self-loop выше) не должен попадать под REDIRECT
    # ниже. -I вставляет в начало цепочки -- порядок относительно
    # других правил, добавленных этим же скриптом, не важен (все они
    # ниже, через -A), но эта строка обязана оказаться ПЕРЕД ними.
    if id "$RELAY_USER" >/dev/null 2>&1; then
      # -C проверяет существование правила без побочных эффектов -- без
      # этой проверки повторный apply (напр. второй раз для другого
      # --cidr-file) дублировал бы exclusion при каждом вызове.
      if ! iptables -t nat -C OUTPUT -p tcp -m owner --uid-owner "$RELAY_USER" -j RETURN 2>/dev/null; then
        iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner "$RELAY_USER" -j RETURN
      fi
    else
      echo "Пользователь $RELAY_USER не найден -- исключение self-loop НЕ применено, добавьте вручную после создания пользователя." >&2
    fi

    # -C перед -A по той же причине, что и у exclusion выше -- без неё
    # повторный apply того же файла (напр. cf_worker/deploy.sh вызывает
    # apply безусловно на каждом запуске, в т.ч. на сервере, где Telegram
    # REDIRECT уже стоит с первой установки) дублирует каждое правило.
    # Дубли не ломают маршрутизацию (iptables матчит первое совпавшее),
    # но бесконтрольно раздувают таблицу NAT с каждым повторным apply.
    for cidr in "${CIDRS[@]}"; do
      if ! iptables -t nat -C OUTPUT -p tcp -d "$cidr" --dport 443 \
          -j REDIRECT --to-port "$PORT" 2>/dev/null; then
        iptables -t nat -A OUTPUT -p tcp -d "$cidr" --dport 443 \
          -j REDIRECT --to-port "$PORT"
      fi
    done
    echo "Применено: ${#CIDRS[@]} подсетей -> 127.0.0.1:$PORT (плюс исключение для $RELAY_USER)" >&2
    ;;
  remove)
    for cidr in "${CIDRS[@]}"; do
      iptables -t nat -D OUTPUT -p tcp -d "$cidr" --dport 443 \
        -j REDIRECT --to-port "$PORT" 2>/dev/null || true
    done
    iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner "$RELAY_USER" -j RETURN 2>/dev/null || true
    echo "Правила для порта $PORT (и исключение для $RELAY_USER) удалены (если были)" >&2
    ;;
  status)
    iptables -t nat -L OUTPUT -n -v --line-numbers | grep -E "REDIRECT|Chain OUTPUT"
    ;;
  *)
    echo "Использование: $0 apply|remove|status [--port N]" >&2
    exit 1
    ;;
esac
