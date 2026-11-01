#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# Сравнивает исполненный census с планом, выведенным из скомпилированной сетки.
# Исторические журналы и отчёты не меняет; старый формат не принимает.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo 'usage: collect-strength.sh REPORT RAW_LOG ACTUAL_GO_RC' >&2
  exit 64
fi
report=$1
raw_log=$2
[ "$3" = 0 ] || { echo 'strength: Go не завершился успешно' >&2; exit 1; }
[ -s "$report" ] && [ -s "$raw_log" ] || { echo 'strength: отсутствует непустой вход' >&2; exit 1; }
plan=$(sed -n 's/^  STRENGTH_PLAN //p' "$report")
census=$(sed -n 's/^  STRENGTH_CENSUS //p' "$report")
[[ "$plan" =~ ^axes=[1-9][0-9]*\ plannedAxes=[1-9][0-9]*\ points=[1-9][0-9]*\ scenarios=[1-9][0-9]*\ askScenarios=[1-9][0-9]*\ listScenarios=[1-9][0-9]*\ apiInvocations=[1-9][0-9]*\ askRepeats=[1-9][0-9]*\ listRepeats=1$ ]] || { echo 'strength: план отсутствует, неоднозначен или имеет неизвестный формат' >&2; exit 1; }
[ "$plan" = "$census" ] || { echo 'strength: исполненный census отличается от плана' >&2; exit 1; }
grep -Eq '^--- PASS: TestStrengthGrid_Report ' "$raw_log" || { echo 'strength: нет итогового PASS' >&2; exit 1; }
grep -q 'отчёт записан:' "$raw_log" || { echo 'strength: нет итоговой записи отчёта' >&2; exit 1; }
if grep -Eq 'ПРОМЕЖУТОЧНЫЙ СРЕЗ|ПРОГОН НЕ ОКОНЧЕН' "$report"; then
  echo 'strength: отчёт промежуточный' >&2
  exit 1
fi
printf 'strength: complete %s\n' "$census"
