#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# run-ceremony.sh — ВОЛНА ЦЕРЕМОНИИ: создаёт условие «предъявитель принадлежит
# человеку», гоняет коллекции, которым это условие нужно, и выносит вердикт
# ЧИСЛАМИ.
#
# ЗАЧЕМ ОТДЕЛЬНАЯ ВОЛНА, А НЕ МАСКА.
# Часть набора описывает поведение, у которого вызывающий — человек: аккаунт
# принадлежит пользователю by construction, а уровень аутентификации поднимается
# только церемонией входа. Машинный посев такого предъявителя не производит.
# Пока условие не создано, эти шаги идут ПОД ЧУЖИМ ПРИНЦИПАЛОМ: часть падает,
# часть — что хуже — зеленеет, потому что отказ пришёл, только по другой причине.
# Отходных путей здесь ровно два, и маска в них не входит: либо волна, которая
# условие СОЗДАЁТ, либо открытый долг с числом. Эталон формы —
# scripts/run-failclosed.sh (волна для суиты, которой нужен выключенный store прав).
#
# ЧТО ЗДЕСЬ ВЫВОДИТСЯ, А ЧТО ОБЪЯВЛЕНО.
# Перечень коллекций волны НЕ выписан: он ВЫВОДИТСЯ на каждом запуске из дерева
# (tests/authz-fixtures/ceremony_credentials.py) по двум основаниям —
# предъявитель шага берётся из переменной, которую посев не куёт, ЛИБО форма
# запроса требует человека структурно. Выписанный перечень в этом репозитории уже
# расходился с деревом; выведенный разойтись не может.
#
# ПОЧЕМУ ЭТО ВОЛНА, А НЕ ШАГ ПОСЕВА ПЕРЕД ВСЕМИ. Три причины, все из дерева:
#   1. предъявитель человека живёт ограниченный срок (prodrun.sh уже документирует
#      этот класс: матрица старше ~10 минут чеканит токены, истекающие посреди
#      прогона) — церемония идёт непосредственно перед своими коллекциями;
#   2. неудавшаяся церемония не должна обнулять машинные суиты: это ОТДЕЛЬНАЯ
#      находка, и она обязана быть отличима;
#   3. iam-материализация прав идёт полным путём под EXCLUSIVE-локом и голодает
#      под конкурентной нагрузкой — та же причина, по которой iam уже вынесен в
#      отдельную волну.
#
# ЧЕГО НЕ ДЕЛАЕТ: не прощает. Нет посева церемонии, церемония не прошла, набор
# вывелся пустым — скрипт ПАДАЕТ и отчётов не оставляет, поэтому авторитетный
# гейт (scripts/assert-suites-green.sh) докладывает `<stem>(no-report)` и роняет
# прогон. «Не смогли создать условие» — открытый долг, а не зелёная суита.
#
# Запуск: cwd = services/iam/tests/newman
#   [SETUP_NS=kacho] [DELAY=…] ./scripts/run-ceremony.sh

set -uo pipefail
cd "$(dirname "$0")/.."

SUITE_DIR="$PWD"
ROOT="$(cd "$SUITE_DIR/../../../.." && pwd)"
DECL="$ROOT/tests/authz-fixtures/ceremony_credentials.py"
ENV_FILE="environments/local.postman_environment.json"
DELAY="${DELAY:-100}"

for tool in newman jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: '$tool' не найден в PATH" >&2; exit 2; }
done
[ -f "$DECL" ] || { echo "FATAL: нет объявления церемонии $DECL" >&2; exit 2; }
[ -f "$ENV_FILE" ] || { echo "FATAL: нет env $ENV_FILE — его пишет посев фикстур" >&2; exit 2; }

# ─── 1. условие: посев церемонии ─────────────────────────────────────────────
# Путь посева читается из ОБЪЯВЛЕНИЯ, а не пишется здесь: иначе у одного факта
# стало бы два места, и они разошлись бы (ровно этот класс волна и закрывает).
SEED="$(python3 "$DECL" --root "$ROOT" --seed-path)"
if [ ! -f "$SEED" ]; then
  echo "===== ВОЛНА ЦЕРЕМОНИИ НЕ МОЖЕТ СОЗДАТЬ СВОЁ УСЛОВИЕ =====" >&2
  python3 "$DECL" --root "$ROOT" --debt >&2
  echo >&2
  echo "Отчётов не оставлено НАМЕРЕННО: гейт scripts/assert-suites-green.sh обязан" >&2
  echo "доложить по каждой из этих коллекций '(no-report)'. Зелёной эта волна быть" >&2
  echo "не может ни при каком коде возврата." >&2
  exit 3
fi

echo "[ceremony] посев церемонии: $SEED"
if ! SETUP_NS="${SETUP_NS:-kacho}" python3 "$SEED"; then
  echo "===== ВОЛНА ЦЕРЕМОНИИ: ПОСЕВ УПАЛ =====" >&2
  echo "Церемония не довела предъявителя. Коллекции НЕ запускались: прогон против" >&2
  echo "непосеянного условия — это не красный результат и не зелёный, результата нет." >&2
  exit 2
fi

# ─── 2. набор волны — ВЫВОДИТСЯ из дерева ────────────────────────────────────
mapfile -t STEMS < <(python3 "$DECL" --root "$ROOT" --suite "services/iam/tests/newman" --stems)
if [ "${#STEMS[@]}" -eq 0 ]; then
  echo "FATAL: набор волны вывелся ПУСТЫМ." >&2
  echo "  Это не 'церемония больше не нужна' — это 'ничего не прочитано': коллекции" >&2
  echo "  ещё не сгенерированы (scripts/gen.py) либо объявление разошлось с деревом." >&2
  echo "  Проверить: python3 $DECL --root $ROOT --verify" >&2
  exit 2
fi
echo "[ceremony] коллекций в волне: ${#STEMS[@]} (выведены из дерева, не выписаны): ${STEMS[*]}"

# ─── 3. прогон ───────────────────────────────────────────────────────────────
mkdir -p out
run_one() { # <stem>
  local stem="$1" col="collections/${stem}.postman_collection.json"
  if [ ! -f "$col" ]; then
    echo "[ceremony] НЕТ КОЛЛЕКЦИИ $col — отчёта не будет, и гейт это назовёт" >&2
    return 1
  fi
  local rc
  # Код возврата берётся у NEWMAN (`PIPESTATUS[0]`), не у `tee` и не через
  # `|| true`: проглоченный код возврата — то, из-за чего суита в этом дереве
  # однажды напечатала GREEN с 94 упавшими утверждениями.
  #
  # `errexit` здесь НЕ снимается и НЕ ставится: он у этого скрипта выключен
  # изначально (`set -uo pipefail` в шапке). Пара `set +e` … `set -e`, скопированная
  # из соседнего прогонщика, ВКЛЮЧИЛА бы его на весь остаток файла — и первый же
  # `run_one`, вернувший 1 на отсутствующей коллекции, оборвал бы прогон до
  # вердикта. Отсутствие коллекции обязано доехать до таблицы как MISSING, а не
  # оборвать волну.
  newman run "$col" \
    -e "$ENV_FILE" \
    --delay-request "$DELAY" \
    --reporters cli,json \
    --reporter-json-export "out/${stem}.json" \
    ${EXTRA_NEWMAN_ARGS:-} 2>&1 | tee "out/${stem}.cli"
  rc=${PIPESTATUS[0]}
  echo "$rc" > "out/${stem}.rc"
  return 0
}

for stem in "${STEMS[@]}"; do
  echo
  echo "[ceremony] ---- $stem ----"
  run_one "$stem"
done

# ─── 4. вердикт — ЧИСЛАМИ ────────────────────────────────────────────────────
# Форма и сигнатура те же, что у восьми суитных агрегаторов дерева
# (`aggregate_verdict <out_dir> <stem…>` → 0/1), поэтому эта функция попадает под
# tree-wide инъекцию deploy/scripts/assert-verdict-aggregators-honest.sh: чистый
# отчёт обязан дать 0, а упавшее утверждение / запрос без ответа / немой отчёт /
# отсутствующий отчёт / ненулевой код newman — ненуль. Ни одно из четырёх
# непрошедших состояний не вычитается и не объясняется.
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
    if [[ "$unanswered" -gt 0 ]]; then
      jq -r '[.run.failures[]? | select((.error.name? // "") != "AssertionError")
              | "    NOT EXECUTED: \(.source.name? // "?") <- \(.error.message? // "нет ответа")"]
             | unique | .[]' "$json" 2>/dev/null || true
    fi
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
  echo "===== ВОЛНА ЦЕРЕМОНИИ: вердикт ====="
  if aggregate_verdict "out" "${STEMS[@]}" | tee out/ceremony-summary.txt; then
    echo "OK: все коллекции волны церемонии зелёные."
    exit 0
  fi
  echo "FAIL: волна церемонии красная / неполная (см. таблицу выше)." >&2
  exit 1
fi
