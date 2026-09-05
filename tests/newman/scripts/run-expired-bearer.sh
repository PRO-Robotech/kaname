#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# run-expired-bearer.sh — ВОЛНА ИСТЁКШЕГО ПРЕДЪЯВИТЕЛЯ: создаёт условие «срок токена
# УЖЕ прошёл», гоняет коллекцию, которой это условие нужно, и выносит вердикт ЧИСЛАМИ.
#
# ЗАЧЕМ ОТДЕЛЬНАЯ ВОЛНА, А НЕ МАСКА И НЕ ОСЛАБЛЕННЫЙ КЕЙС.
# Кейс `AUTHZ-APITOK-EXPIRED-GT-A1` спрашивает, отвергает ли край СВОЙ СОБСТВЕННЫЙ,
# корректно подписанный предъявитель, у которого прошёл срок. Подделать такого
# предъявителя нельзя не по принципиальным соображениям, а по устройству: подписывает
# выдающий, своим ключом, и срок назначает тоже он. Скованный харнессом «просроченный»
# токен проверял бы отказ по ЧУЖОЙ подписи — другое утверждение, не то, ради которого
# кейс написан. Отходных путей ровно два, и маска в них не входит: либо волна, которая
# условие СОЗДАЁТ, либо открытый долг с числом. Эталон формы — scripts/run-ceremony.sh.
#
# СКОЛЬКО ЭТО ИДЁТ — ДЕСЯТКИ СЕКУНД. Волна идёт столько, сколько живёт предъявитель, —
# а живёт он ровно столько, сколько заказано КЛЮЧУ ЭТОЙ ПРОБЫ (`EXPIRED_BEARER_TTL_S`,
# по умолчанию 20 с) плюс запас `SKEW_S`.
#
# СРОК ЗАКАЗЫВАЕТСЯ ПРИ ВЫПУСКЕ КЛЮЧА, И ЭТО РУЧКА НАША (задача #1120). Ключ служебной
# учётки обменивается только у нашего издателя, а наш выпуск не отдаёт токен,
# переживающий свой ключ: срок токена — минимум из объявленного посадкой и остатка
# жизни ключа. Здесь стояла правка срока административным вызовом ПРЕЖНЕМУ издателю —
# его клиенту; клиента у него больше не заводится вовсе, поэтому править нечего.
# Общая настройка (`authn.client-token.token-ttl`) НЕ трогается — менять её значило бы
# менять посадку стенда всем остальным, и этот запрет остаётся в силе.
#
# ПОЭТОМУ СОБСТВЕННОГО РАСПИСАНИЯ БОЛЬШЕ НЕ ТРЕБУЕТСЯ: условие создаёт волна церемонии
# (стадия 10 её посева делегирует сюда же), и открытого долга по этому кейсу в общем
# прогоне нет. Этот скрипт остаётся отдельной точкой входа — прогнать пробу одну.
#
# ЧЕГО НЕ ДЕЛАЕТ: не прощает. Посев не прошёл, коллекции нет, набор пуст — скрипт
# ПАДАЕТ и отчётов не оставляет, поэтому авторитетный гейт докладывает `(no-report)`.
# «Не смогли создать условие» — открытый долг, а не зелёная суита.
#
# Запуск: cwd = services/iam/tests/newman
#   [SETUP_NS=kacho] [SKEW_S=30] [EXPIRED_BEARER_TTL_S=20] [DELAY=…] ./scripts/run-expired-bearer.sh
#   DRY_PROBE=1 ./scripts/run-expired-bearer.sh   — самопроверка пути БЕЗ ожидания:
#       доказывает, что выпуск и проба края живые и что проба читает настоящий вердикт;
#       инвариант при этом НЕ объявляется проверенным и коллекции НЕ гоняются.

set -uo pipefail
cd "$(dirname "$0")/.."

SUITE_DIR="$PWD"
ROOT="$(cd "$SUITE_DIR/../../../.." && pwd)"
SEED="$ROOT/tests/authz-fixtures/prodseed_expired_bearer.py"
ENV_FILE="environments/local.postman_environment.json"
DELAY="${DELAY:-100}"
STEM="authz-sa-apitoken"

for tool in newman jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: '$tool' не найден в PATH" >&2; exit 2; }
done
[ -f "$SEED" ]     || { echo "FATAL: нет посева $SEED" >&2; exit 2; }
[ -f "$ENV_FILE" ] || { echo "FATAL: нет env $ENV_FILE — его пишет посев фикстур" >&2; exit 2; }

# ─── 1. условие: выпустить и ПЕРЕЖДАТЬ срок ──────────────────────────────────
echo "[expired] посев: $SEED"
if ! SETUP_NS="${SETUP_NS:-kacho}" python3 "$SEED"; then
  echo "===== ВОЛНА ИСТЁКШЕГО ПРЕДЪЯВИТЕЛЯ: ПОСЕВ УПАЛ =====" >&2
  echo "Условие не создано. Коллекция НЕ запускалась: прогон против непосеянного" >&2
  echo "условия — это не красный результат и не зелёный, результата нет." >&2
  exit 2
fi

if [ "${DRY_PROBE:-}" != "" ] && [ "${DRY_PROBE:-0}" != "0" ]; then
  echo "[expired] САМОПРОВЕРКА завершена: коллекции НЕ гонялись, вердикт НЕ выносится."
  exit 0
fi

# ─── 2. прогон ───────────────────────────────────────────────────────────────
COL="collections/${STEM}.postman_collection.json"
[ -f "$COL" ] || { echo "FATAL: нет коллекции $COL (scripts/gen.py)" >&2; exit 2; }
mkdir -p out
# Код возврата берётся у NEWMAN (`PIPESTATUS[0]`), не у `tee` и не через `|| true`:
# проглоченный код возврата — то, из-за чего суита в этом дереве однажды напечатала
# GREEN с 94 упавшими утверждениями.
newman run "$COL" \
  -e "$ENV_FILE" \
  --delay-request "$DELAY" \
  --reporters cli,json \
  --reporter-json-export "out/${STEM}.json" \
  ${EXTRA_NEWMAN_ARGS:-} 2>&1 | tee "out/${STEM}.cli"
echo "${PIPESTATUS[0]}" > "out/${STEM}.rc"

# ─── 3. вердикт — ЧИСЛАМИ ────────────────────────────────────────────────────
# Форма и сигнатура те же, что у суитных агрегаторов дерева
# (`aggregate_verdict <out_dir> <stem…>` → 0/1), поэтому эта функция попадает под
# tree-wide инъекцию deploy/scripts/assert-verdict-aggregators-honest.sh: чистый отчёт
# обязан дать 0, а упавшее утверждение / запрос без ответа / немой отчёт / отсутствующий
# отчёт / ненулевой код newman — ненуль. Ни одно из четырёх непрошедших состояний не
# вычитается и не объясняется.
aggregate_verdict() {
  local out_dir="$1"; shift
  local bad=0 stem json rcfile rc total failed requests unanswered note
  local reported=0 expected=$# s_req=0 s_unans=0 s_ass=0 s_fail=0 s_mute=0
  printf "%-38s %10s %10s %10s %12s %8s  %s\n" \
    "COLLECTION" "ASSERT" "FAILED" "REQUESTS" "UNANSWERED" "RC" "NOTE"
  for stem in "$@"; do
    json="${out_dir}/${stem}.json"
    rcfile="${out_dir}/${stem}.rc"
    rc="n/a"
    [[ -f "$rcfile" ]] && rc="$(cat "$rcfile")"
    if [[ ! -f "$json" ]]; then
      printf "%-38s %10s %10s %10s %12s %8s  %s\n" "$stem" "-" "-" "-" "-" "MISSING" \
        "отчёта нет — коллекция волны не отработала"
      bad=1
      continue
    fi
    reported=$((reported + 1))
    total=0; failed=0; requests=0; unanswered=0
    read -r total failed requests unanswered < <(
      jq -r '"\(.run.stats.assertions.total) \(.run.stats.assertions.failed) \(.run.stats.requests.total) \(.run.stats.requests.failed // 0)"' \
        "$json" 2>/dev/null || echo "0 0 0 0"
    )
    [[ "$total" =~ ^[0-9]+$ ]]      || total=0
    [[ "$failed" =~ ^[0-9]+$ ]]     || failed=0
    [[ "$requests" =~ ^[0-9]+$ ]]   || requests=0
    [[ "$unanswered" =~ ^[0-9]+$ ]] || unanswered=0
    note=""
    if [[ "$total" -eq 0 ]]; then
      note="NOTHING RAN — 0 утверждений; коллекция, ничего не спросившая, не проходит"
      s_mute=$((s_mute + 1)); bad=1
    fi
    if [[ "$unanswered" -gt 0 ]]; then
      note="${note:+$note; }UNANSWERED — запросы без ответа НЕ вычитаются"
      bad=1
    fi
    printf "%-38s %10s %10s %10s %12s %8s  %s\n" \
      "$stem" "$total" "$failed" "$requests" "$unanswered" "$rc" "$note"
    s_req=$((s_req + requests)); s_unans=$((s_unans + unanswered))
    s_ass=$((s_ass + total));    s_fail=$((s_fail + failed))
    if [[ "$failed" -gt 0 ]]; then bad=1; fi
    if [[ "$rc" != "0" ]];    then bad=1; fi
  done
  printf "TOTAL: %d/%d коллекций отчиталось — %d запрос(ов), %d без ответа, %d утверждени(й), %d упавших, %d немых отчёт(ов)\n" \
    "$reported" "$expected" "$s_req" "$s_unans" "$s_ass" "$s_fail" "$s_mute"
  return "$bad"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo
  echo "===== ВОЛНА ИСТЁКШЕГО ПРЕДЪЯВИТЕЛЯ: вердикт ====="
  if aggregate_verdict "out" "$STEM" | tee out/expired-bearer-summary.txt; then
    echo "OK: волна истёкшего предъявителя зелёная."
    exit 0
  fi
  echo "FAIL: волна истёкшего предъявителя красная / неполная (см. таблицу выше)." >&2
  exit 1
fi
