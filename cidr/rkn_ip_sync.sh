#!/usr/bin/env bash
# rkn_ip_sync.sh -- синхронизирует внешний список IP-адресов (не доменов)
# из community-реестра блокировок РФ и ЖИВЬЁМ проверяет каждый НОВЫЙ
# кандидат на реальную недоступность с этого сервера, прежде чем считать
# его кандидатом на REDIRECT+Cloudflare Worker (см. relay/setup_redirect.sh,
# cidr/whatsapp_ipv4.txt/telegram_ipv4.txt -- тот же механизм, здесь просто
# источник списка внешний и обновляемый, а не вручную накопленный).
#
# ПОЧЕМУ IP, а не домены: domain-уровня блокировки уже покрывает
# z2r_autobench (RKN_TLS хостлист + --lua-desync=, см. rkn_external_sync.sh
# в том репо) -- десинк там реально работает, потому что блокировка на
# уровне DPI-сигнатуры. Этот скрипт -- для другого класса: IP-level
# SYN-null-route (пакет вообще не уходит, манглить нечего), тот же класс,
# что уже подтверждён живьём для Telegram DC-адресов и
# 31.13.72.48/157.240.200.61 (WhatsApp) -- см. CLAUDE.md. Единственное, что
# помогает против ЭТОГО класса -- сменить исходящий IP целиком (relay ->
# Cloudflare Worker), не поможет никакой --lua-desync=.
#
# ПОЧЕМУ ПРОВЕРЯЕМ ЖИВЬЁМ, А НЕ ДОВЕРЯЕМ СПИСКУ: источник (community-
# реестр) неизбежно устаревает и не разделяет "IP реально недоступен" от
# "IP просто когда-то упоминался в блокировке" -- ровно то же самое "не
# гадаем, проверяем" правило, что уже применялось в этом проекте для
# clone-стратегий/тестовых доменов (см. z2r_autobench/CLAUDE.md). Тест —
# тот же приём, что уже использован для 31.13.72.48 и других: сырой
# `/dev/tcp` от имени пользователя wsrelay (см. relay/setup_redirect.sh --
# именно этот пользователь исключён из REDIRECT правилом `-m owner
# --uid-owner wsrelay -j RETURN`, так что тест идёт НАПРЯМУЮ в реальный
# интернет, а не заворачивается сам на себя).
#
# ПОЧЕМУ ТОЛЬКО /32: источник (проверено живьём 2026-09-10, см. CLAUDE.md)
# смешивает одиночные IP (78% списка) с огромными провайдерскими блоками
# (напр. 104.16.0.0/12 -- это ВЕСЬ основной диапазон Cloudflare, больше
# миллиона адресов; несколько блоков Google/GCP). Проверить "заблокирован
# ли" такой блок одним коннектом бессмысленно (он используется и
# заблокированными, и совершенно не связанными сайтами одновременно) --
# `/28` и шире отбрасываются на этапе фильтрации, даже не доходя до теста.
# `/31` (пара соседних адресов) тоже отбрасывается для простоты первой
# версии -- почти вся полезная часть источника (21130 из 27135 записей на
# момент проверки) и так /32.
#
# Использование:
#   rkn_ip_sync.sh [--source-url URL] [--port N] [--timeout N] [--concurrency N] [--recheck-existing]
#
# Фоновый ночной запуск -- см. relay/rkn-ip-sync.service +
# relay/rkn-ip-sync.timer (по умолчанию 03:00, +- 30 мин джиттер) --
# прямой запрос "пусть это будет в фоне ночью", один прогон на большом
# источнике не рассчитан на интерактивное ожидание (полчаса-пара часов).
#
# --recheck-existing -- по умолчанию уже подтверждённые в OUTPUT_FILE IP
# повторно НЕ тестируются (экономия времени на большом источнике) -- этот
# флаг заставляет перепроверить и их тоже (напр. раз в несколько недель,
# вручную, не по расписанию -- IP мог перестать быть заблокированным).
#
# --timeout/--concurrency также читаются из окружения (ZWS_RKN_SYNC_TIMEOUT/
# ZWS_RKN_SYNC_CONCURRENCY) ДО разбора аргументов -- CLI-флаг всё равно
# главнее, если передан явно. Смысл: rkn-ip-sync.service (см. ниже) тянет
# те же переменные из /etc/z2r_autobench/wsrelay.env через
# EnvironmentFile=, так что таймаут/параллелизм ночного запуска настраивается
# правкой ОДНОГО общего файла, без правки самого юнита или скрипта.
#
# Результат: cidr/rkn_ip_blocked.txt -- живой, накопленный список
# подтверждённых IP (формат "1.2.3.4/32" на строку, тот же, что
# telegram_ipv4.txt/whatsapp_ipv4.txt). Скрипт НИКОГДА не трогает
# iptables/REDIRECT сам -- это отдельный, осознанный шаг человека
# (`setup_redirect.sh apply --cidr-file cidr/rkn_ip_blocked.txt ...`,
# см. предупреждение в конце вывода) -- та же дисциплина, что и everywhere
# else в этом репо (preview/данные отдельно от применения).
#
# ОТКРЫТЫЙ РИСК, не решённый этим скриптом: много параллельных SYN к
# тысячам разных внешних адресов за короткое окно -- по форме похоже на
# сканирование порта, с точки зрения провайдера/аплинка Server A. Не тот
# же риск, что уже задокументированное "эскалация DPI против ОДНОЙ цели"
# (z2r_autobench/CLAUDE.md "Ban / rate-limit avoidance") -- здесь цели все
# разные, риск скорее в паттерне трафика как таковом. Не проверено, что
# это безопасно на любом провайдере -- умеренный --concurrency (дефолт 20)
# осознанный компромисс, не гарантия.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SOURCE_URL="https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst"
SOURCE_URL="$DEFAULT_SOURCE_URL"
OUTPUT_FILE="$SCRIPT_DIR/rkn_ip_blocked.txt"
TELEGRAM_FILE="$SCRIPT_DIR/telegram_ipv4.txt"
WHATSAPP_FILE="$SCRIPT_DIR/whatsapp_ipv4.txt"
TEST_PORT=443
TEST_TIMEOUT="${ZWS_RKN_SYNC_TIMEOUT:-3}"
CONCURRENCY="${ZWS_RKN_SYNC_CONCURRENCY:-20}"
RECHECK_EXISTING=0
WSRELAY_USER=wsrelay

while [ $# -gt 0 ]; do
  case "$1" in
    --source-url) SOURCE_URL="$2"; shift 2 ;;
    --port) TEST_PORT="$2"; shift 2 ;;
    --timeout) TEST_TIMEOUT="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --recheck-existing) RECHECK_EXISTING=1; shift ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Нужен root (тест идёт через sudo -u $WSRELAY_USER, в обход REDIRECT)." >&2
  exit 1
fi
id "$WSRELAY_USER" >/dev/null 2>&1 || {
  echo "Пользователь $WSRELAY_USER не найден -- без него тест не сможет" >&2
  echo "обойти собственный self-loop REDIRECT (см. relay/setup_redirect.sh)." >&2
  exit 1
}
command -v curl >/dev/null 2>&1 || { echo "curl не найден" >&2; exit 1; }
# Нужен для корректного CIDR-исключения ниже (telegram_ipv4.txt содержит
# широкие диапазоны, не только /32 -- точное совпадение строки, которое
# было тут раньше, их не покрывало, см. коммит, который это исправил).
command -v python3 >/dev/null 2>&1 || { echo "python3 не найден" >&2; exit 1; }

TMP_RAW="$(mktemp)"
TMP_CANDIDATES="$(mktemp)"
TMP_NEW="$(mktemp)"
TMP_RESULTS="$(mktemp)"
trap 'rm -f "$TMP_RAW" "$TMP_CANDIDATES" "$TMP_NEW" "$TMP_RESULTS"' EXIT

echo "Скачиваю $SOURCE_URL..." >&2
if ! curl -fsS --max-time 30 -o "$TMP_RAW" "$SOURCE_URL"; then
  echo "Не удалось скачать $SOURCE_URL" >&2
  exit 1
fi
[ -s "$TMP_RAW" ] || { echo "Скачанный список пуст, прерываю" >&2; exit 1; }

# Оставляем только /32 (см. докстринг выше про широкие диапазоны) и
# приводим к голому IP без суффикса для дальнейшего теста.
total_lines="$(wc -l < "$TMP_RAW" | tr -d ' ')"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32$' "$TMP_RAW" \
  | sed 's#/32$##' | sort -u > "$TMP_CANDIDATES"
candidates_total="$(wc -l < "$TMP_CANDIDATES" | tr -d ' ')"
echo "Источник: $total_lines строк всего, $candidates_total из них -- одиночные /32 (остальное отброшено, см. докстринг)." >&2

# Уже известные (Telegram/WhatsApp кураторские списки + уже подтверждённые
# этим же скриптом ранее) -- не тестируем их снова здесь без необходимости.
#
# Живой баг 2026-09-16, найден при ручной проверке пересечений с
# telegram_ipv4.txt/whatsapp_ipv4.txt: раньше это исключение делалось
# через `grep -oE` (вытаскивал только голый адрес сети из каждой строки)
# + `comm -23` (точное совпадение строки). Для whatsapp_ipv4.txt (там
# только /32) это работало, но telegram_ipv4.txt по-прежнему хранит
# широкие диапазоны (`149.154.160.0/20` и т.п.) -- точное совпадение
# ловило только сам адрес сети (`149.154.160.0`), а не остальные ~4000
# адресов внутри того же /20. Кандидат из внешнего RKN-источника,
# попадающий ВНУТРЬ такого диапазона, но не совпадающий с ним побайтово,
# проходил бы мимо исключения и тестировался/добавлялся бы заново --
# безобидно с точки зрения REDIRECT (то же самое место назначения всё
# равно накрывается диапазоном Telegram), но бессмысленно дублирует
# работу и раздувает rkn_ip_blocked.txt повторами. Теперь настоящее
# CIDR-вхождение через python3's ipaddress -- через переменные окружения,
# не подстановку путей прямо в текст python-скрипта (не хотим, чтобы
# путь с спецсимволом сломал синтаксис или что-то похуже).
RKN_KNOWN_RECHECK="$RECHECK_EXISTING" \
RKN_TELEGRAM_FILE="$TELEGRAM_FILE" \
RKN_WHATSAPP_FILE="$WHATSAPP_FILE" \
RKN_OUTPUT_FILE="$OUTPUT_FILE" \
RKN_CANDIDATES_FILE="$TMP_CANDIDATES" \
python3 <<'PYEOF' > "$TMP_NEW"
import ipaddress
import os

def load_networks(paths):
    nets = []
    for path in paths:
        if not path or not os.path.isfile(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
    return nets

known_paths = [os.environ['RKN_TELEGRAM_FILE'], os.environ['RKN_WHATSAPP_FILE']]
if os.environ['RKN_KNOWN_RECHECK'] == '0':
    known_paths.append(os.environ['RKN_OUTPUT_FILE'])
known = load_networks(known_paths)

with open(os.environ['RKN_CANDIDATES_FILE']) as f:
    for line in f:
        ip_str = line.strip()
        if not ip_str:
            continue
        ip = ipaddress.ip_address(ip_str)
        if not any(ip in net for net in known):
            print(ip_str)
PYEOF
new_count="$(wc -l < "$TMP_NEW" | tr -d ' ')"
if [ "$RECHECK_EXISTING" -eq 1 ]; then
  echo "Кандидатов на (пере)проверку: $new_count -- включая уже подтверждённые ранее (--recheck-existing), порт $TEST_PORT, таймаут ${TEST_TIMEOUT}с, параллельно $CONCURRENCY." >&2
else
  echo "Новых кандидатов для живой проверки: $new_count (порт $TEST_PORT, таймаут ${TEST_TIMEOUT}с, параллельно $CONCURRENCY)." >&2
fi

if [ "$new_count" -eq 0 ]; then
  echo "Нечего проверять -- либо источник не изменился, либо всё уже покрыто." >&2
  exit 0
fi

# Один коннект = одна запись, atomic append (короткая строка укладывается
# в PIPE_BUF, конкурентные >> не рвут друг друга построчно) -- без flock,
# как и остальные однострочные append'ы в этом репо (rkn_list_cli.sh и
# т.п. делают то же самое для одиночных операций).
test_one_ip() {
  local ip="$1"
  if ! sudo -u "$WSRELAY_USER" timeout "$TEST_TIMEOUT" bash -c "echo > /dev/tcp/$ip/$TEST_PORT" 2>/dev/null; then
    echo "${ip}/32" >> "$TMP_RESULTS"
  fi
}

job_count=0
checked=0
while IFS= read -r ip; do
  test_one_ip "$ip" &
  job_count=$((job_count + 1))
  checked=$((checked + 1))
  if [ "$job_count" -ge "$CONCURRENCY" ]; then
    wait -n
    job_count=$((job_count - 1))
  fi
  if [ $((checked % 500)) -eq 0 ]; then
    echo "...проверено $checked/$new_count" >&2
  fi
done < "$TMP_NEW"
wait

blocked_count="$(wc -l < "$TMP_RESULTS" | tr -d ' ')"
if [ "$RECHECK_EXISTING" -eq 1 ]; then
  echo "Проверка завершена: $blocked_count из $new_count (пере)проверенных подтверждённо недоступны (SYN-таймаут на порт $TEST_PORT)." >&2
else
  echo "Проверка завершена: $blocked_count из $new_count новых кандидатов подтверждённо недоступны (SYN-таймаут на порт $TEST_PORT)." >&2
fi

# Живой баг 2026-09-16: раньше при blocked_count=0 скрипт выходил тут же,
# НЕ трогая OUTPUT_FILE вообще -- под --recheck-existing это означало, что
# полная перепроверка, честно не подтвердившая НИ ОДНОГО кандидата
# (например, все старые записи оказались ложными срабатываниями), не
# могла очистить файл -- тот же баг класса "может только расти", что и
# сам merge-режим ниже. Теперь ранний выход -- только для обычного
# инкрементального режима (там действительно нечего менять, IPс просто
# нет новых подтверждений поверх уже накопленного).
if [ "$blocked_count" -eq 0 ] && [ "$RECHECK_EXISTING" -eq 0 ]; then
  echo "Ни один новый кандидат не подтвердился как заблокированный -- $OUTPUT_FILE не менялся." >&2
  exit 0
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"
# Два отдельных последовательных шага, не один awk-пайп с двумя
# процессами, пишущими в один файл -- та первая версия не гарантировала
# порядок (шапка могла перемешаться с sort'нутым телом в зависимости от
# буферизации). Так строго детерминировано: шапка целиком, потом тело.
{
  echo "# rkn_ip_blocked.txt -- накоплено rkn_ip_sync.sh, каждая запись живьём"
  echo "# подтверждена как SYN-timeout с этого сервера (не просто взята из"
  echo "# источника без проверки). Источник кандидатов: $SOURCE_URL"
  echo "# Последнее обновление: $(date -u '+%Y-%m-%d %H:%M UTC')"
} > "$OUTPUT_FILE.new"
if [ "$RECHECK_EXISTING" -eq 1 ]; then
  # Живой баг 2026-09-16: --recheck-existing тестирует ВСЕ кандидаты
  # (включая уже подтверждённые ранее -- под этим флагом OUTPUT_FILE не
  # идёт в список исключений известных IP выше), но старая версия этого
  # блока всё
  # равно ОБЪЕДИНЯЛА новый результат со старым содержимым файла вместо
  # того, чтобы заменить его -- то есть IP, переставший отвечать
  # SYN-таймаутом при перепроверке, никогда бы не пропал из файла.
  # Перепроверка, которая может только расти, а не сжиматься -- не
  # перепроверка. Теперь при --recheck-existing файл ПОЛНОСТЬЮ
  # перезаписывается тем, что подтвердилось именно в этом прогоне --
  # никакого merge со старым содержимым.
  sort -u "$TMP_RESULTS" 2>/dev/null >> "$OUTPUT_FILE.new"
else
  {
    [ -f "$OUTPUT_FILE" ] && grep -vE '^\s*#|^\s*$' "$OUTPUT_FILE"
    cat "$TMP_RESULTS"
  } 2>/dev/null | sort -u >> "$OUTPUT_FILE.new"
fi
mv "$OUTPUT_FILE.new" "$OUTPUT_FILE"

if [ "$RECHECK_EXISTING" -eq 1 ]; then
  echo "$OUTPUT_FILE полностью пересобран по результатам этой перепроверки: $blocked_count подтверждённых IP (было -- смотри предыдущую версию в git/бэкапе, если нужно сравнить)." >&2
else
  echo "Дописано $blocked_count новых подтверждённых IP в $OUTPUT_FILE." >&2
fi
echo "Это НЕ применяет REDIRECT само по себе -- следующий шаг вручную:" >&2
echo "  relay/setup_redirect.sh apply --cidr-file $OUTPUT_FILE --dports $TEST_PORT" >&2
echo "(при большом количестве записей это может быть медленно/раздувать" >&2
echo "таблицу NAT -- см. открытый вопрос про ipset в CLAUDE.md, если" >&2
echo "$OUTPUT_FILE вырос за несколько десятков строк)." >&2
