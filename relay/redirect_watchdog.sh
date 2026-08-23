#!/usr/bin/env bash
# redirect_watchdog.sh -- проверяет, что REDIRECT-правила Zenith-TG в
# nat OUTPUT ещё на месте, и молча восстанавливает их, если пропали.
#
# Живой инцидент 2026-08-23 на NETH-4: краш-луп zapret2.service (три
# рестарта подряд за ~20с из-за отдельного бага в z2r_autobench, см. его
# CLAUDE.md) смахнул ВСЕ REDIRECT-правила Zenith-TG в nat OUTPUT побочным
# эффектом своего init.d-скрипта -- сам relay (transparent_relay.py) при
# этом продолжал работать штатно и даже не заметил проблему (слушает
# только 127.0.0.1:8447, ему всё равно, заворачивает ли что-то трафик на
# его порт) -- просто трафик к нему больше не заворачивался. Телеграм на
# iOS через VLESS сломался тихо где-то ночью, обнаружили только утром,
# отдельно от несвязанного на первый взгляд инцидента с YouTube в
# z2r_autobench, который на самом деле и был первопричиной по цепочке.
#
# setup_redirect.sh remove -- идемпотентен (2>/dev/null || true на каждое
# правило), поэтому remove+apply безопасно гонять даже когда правил и так
# нет. Голый повторный apply был бы НЕ идемпотентен -- он использует
# iptables -A без проверки существования, каждый лишний запуск плодил бы
# дубликаты REDIRECT-правил. Поэтому здесь всегда remove, затем apply,
# никогда просто apply поверх уже применённого.
#
# Срабатывает только на явный "правил вообще нет" (actual=0, ожидалось
# больше) -- не пытается угадывать частичную порчу правил (другой набор
# CIDR, другой порт и т.п.), чтобы не переприменять раз в 5 минут вхолостую
# из-за ложных срабатываний парсинга; такой класс порчи в этом инциденте
# не наблюдался -- либо все правила на месте, либо ни одного.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CIDR_FILE="$SCRIPT_DIR/../cidr/telegram_ipv4.txt"

expected=0
if [ -f "$CIDR_FILE" ]; then
  expected="$(grep -vcE '^\s*#|^\s*$' "$CIDR_FILE" || true)"
fi

actual="$(iptables -t nat -S OUTPUT 2>/dev/null | grep -c -- '-j REDIRECT' || true)"

if [ "$expected" -gt 0 ] && [ "$actual" -eq 0 ]; then
  echo "$(date -Iseconds) WATCHDOG: REDIRECT-правил в nat OUTPUT нет (ожидалось $expected по $CIDR_FILE) -- переприменяю setup_redirect.sh" >&2
  bash "$SCRIPT_DIR/setup_redirect.sh" remove >/dev/null 2>&1 || true
  bash "$SCRIPT_DIR/setup_redirect.sh" apply
  echo "$(date -Iseconds) WATCHDOG: восстановлено." >&2
fi
