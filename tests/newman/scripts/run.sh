#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# tests/newman/scripts/run.sh — прогон newman коллекций kacho-iam.
#
# Usage:
#   ./scripts/run.sh                       # все коллекции, сводный отчет
#   ./scripts/run.sh --service disk        # одна коллекция
#   ./scripts/run.sh --service disk --bail # прерывать после первого fail
#   ./scripts/run.sh --delay 100           # задержка между запросами (ms)
#
# Exit-код: 0 ТОЛЬКО если каждая ожидаемая коллекция произвела отчёт И в нём
# assertions.failed==0 И собственный exit-код newman==0 (плюс coverage-гейт ниже).
# Вердикт выводится из СОДЕРЖИМОГО отчётов (out/<stem>.json + out/<stem>.rc), а не
# из факта запуска. Сводка печатается ВСЕГДА, в том числе на красном — её потеря и
# породила прежний `| tee … || true`, который глотал код возврата newman.
#
# Ожидаемый набор для вердикта НЕ дублируется списком: это объединение
#   (a) реально сгенерированных collections/*.json — ровно то, что грейдит
#       scripts/assert-suites-green.sh (каждый комментарий ниже требует «MUST run
#       here, else the gate reports <x>(no-report)»); коллекция, которую run.sh
#       забыл прогнать, становится MISSING → красный, а не молчаливый пропуск;
#   (b) stem'ов, для которых run_one написал out/<stem>.rc — так «run.sh зовёт
#       коллекцию, которой gen.py не сгенерировал» тоже ловится как MISSING.
#
# Outputs:
#   out/<resource>.json — newman JSON reporter (для агрегации)
#   out/<resource>.cli  — newman cli-вывод
#   out/<resource>.rc   — exit-код newman конкретной коллекции
#   out/summary.txt     — итоговая сводка
#
# Требует: api-gateway доступен по baseUrl из env (локально — port-forward на 18080);
#          newman установлен (`npm install -g newman`); jq для сводки.

set -euo pipefail
cd "$(dirname "$0")/.."
NEWMAN_DIR="$PWD"

# ОТБОР КОЛЛЕКЦИЙ — ИЗ ОБЩЕГО СЛОЯ, А НЕ СВОИМ ОБХОДОМ.
#
# Здесь набор обходил `collections/` СВОИМ циклом — в двух местах, остатком и
# вердиктом. Перечень коллекций объявлен деревом, и каждый свой обход есть ещё
# одно место об одном предмете: правило отбора уже расходилось между копиями
# (`__init__`/`__main__` против ЛЮБОГО ведущего подчёркивания), и расходилось
# оно молча.
#
# ПОРЯДОК вызовов у этого набора остаётся рукописным ОСОЗНАННО (посев и
# зависимость между коллекциями), и правило этого не запрещает: предмет общего
# отбора — МНОЖЕСТВО, а не порядок.
#
# Общий слой ищется ВВЕРХ ОТ ЭТОГО ФАЙЛА, а не от cwd: прогонщик зовут из
# каталога набора, и путь, выведенный из текущего каталога, был бы свойством
# того, ОТКУДА позвали. Поиск — тот же бутстрап, что у `_kacholib_dir()` в
# gen.py, и по той же причине неустраним: общий слой нельзя найти его же
# средствами.
_stems_lib() {
  local d="$NEWMAN_DIR"
  while [[ "$d" != "/" ]]; do
    if [[ -f "$d/tests/newman/kacholib/stems.sh" ]]; then
      printf '%s\n' "$d/tests/newman/kacholib/stems.sh"
      return 0
    fi
    d="$(dirname "$d")"
  done
  echo "общий слой отбора не найден: ожидается <корень>/tests/newman/kacholib/stems.sh" >&2
  echo "Это ОТКАЗ, а не пропуск: без него прогонщик выбрал бы коллекции молча и не те." >&2
  return 1
}
_STEMS_LIB="$(_stems_lib)"
# shellcheck source=/dev/null
. "$_STEMS_LIB"

SERVICE=""
BAIL=""
DELAY="100"
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) SERVICE="$2"; shift 2 ;;
    --bail)    BAIL="--bail"; shift ;;
    --delay)   DELAY="$2"; shift 2 ;;
    # --jobs: принят для паритета с vpc/nlb/compute run.sh + newman-parallel.sh
    # (директива #1). iam-суиты гоняются СЕРИЙНО намеренно (jit-pending reseed +
    # порядковые зависимости между матрицами) — флаг consume-and-ignore, а НЕ
    # пробрасывается в `newman run` (иначе `unknown option '--jobs'` → 0 отчётов
    # → ложный no-report RED всей iam-суиты). Cross-service параллелизм (4 суиты
    # разом) даёт основной выигрыш; internal-iam-serial — приемлемо.
    --jobs)    shift 2 ;;
    *)         EXTRA+=("$1"); shift ;;
  esac
done

ENV="environments/local.postman_environment.json"
# Env-файл gitignore-ится (fixture-seed пишет в него живые токены), но НИКТО его
# не создаёт: patch-env.py/setup.sh только ПАТЧАТ уже существующий и молча
# пропускают отсутствующий. На свежем клоне суита падала здесь ещё до вызова
# newman. Материализация — часть пути прогона, а не ручной шаг: копируем
# закоммиченный шаблон, креды/id допишет fixture-seed. Существующий файл НЕ
# перетираем — в нём может лежать живая сессия текущего прогона.
if [[ ! -f "$ENV" && -f "${ENV%.json}.template.json" ]]; then
  cp "${ENV%.json}.template.json" "$ENV"
  echo "создан $ENV из ${ENV%.json}.template.json (креды допишет fixture-seed)" >&2
fi
[[ -f "$ENV" ]] || { echo "missing env: $ENV"; exit 1; }

# RAN_STEMS — что этот прогон УЖЕ рассматривал. Не для вердикта (его набор
# выводится из дерева ниже), а для остаточного прохода: он подбирает коллекции,
# которых рукописный перечень вызовов не назвал.
RAN_STEMS=()
_was_run() {
  local s
  for s in ${RAN_STEMS[@]+"${RAN_STEMS[@]}"}; do [[ "$1" == "$s" ]] && return 0; done
  return 1
}

# run_one — прогон одной коллекции. Пишет out/<res>.json|.cli|.rc.
run_one() {
  RAN_STEMS+=("$1")
  local res="$1"
  # Второй аргумент `explicit` — прямая просьба человека (`--service <stem>`), и она
  # ВЫИГРЫВАЕТ: отлаживать делегированную коллекцию отсюда по-прежнему можно, просто
  # с предупреждением, что условие её волны здесь не создано.
  #
  # Без второго аргумента делегированная коллекция не запускается: её гоняет своя
  # волна. Проверка стоит ЗДЕСЬ, а не у каждого из двадцати пяти вызовов, потому что
  # список вызовов рукописный — и следующий добавленный вызов иначе снова обошёл бы
  # вычитание молча.
  if [[ "${2:-}" != "explicit" ]] && _is_delegated "$res"; then
    echo "[delegated] ${res} — условие создаёт своя волна (run-failclosed.sh / run-ceremony.sh); здесь НЕ гоняется, вердикт по нему выносит assert-suites-green.sh"
    return 0
  fi
  if [[ "${2:-}" == "explicit" ]] && _is_delegated "$res"; then
    echo "[delegated] ${res} запрошен ЯВНО — гоню, хотя условие его волны здесь не создано; часть шагов ответит не тем принципалом" >&2
  fi
  local col="collections/${res}.postman_collection.json"
  if [[ ! -f "$col" ]]; then
    # Ожидаемая коллекция не сгенерирована = молчаливая потеря покрытия, не skip:
    # .rc-маркер вводит stem в набор вердикта → MISSING → красный.
    echo "[missing] ${res} — нет коллекции ${col}"
    echo "missing" > "out/${res}.rc"
    return 0
  fi
  echo "===== ${res} ====="
  # Берём PIPESTATUS[0] (newman), а НЕ статус tee и НЕ `|| true`: проглоченный код
  # возврата newman = ложный GREEN при красных проверках.
  set +e
  newman run "$col" \
    -e "$ENV" \
    --delay-request "$DELAY" \
    $BAIL \
    --reporters cli,json \
    --reporter-json-export "out/${res}.json" \
    ${EXTRA[@]+"${EXTRA[@]}"} 2>&1 | tee "out/${res}.cli"
  local rc=${PIPESTATUS[0]}
  set -e
  echo "$rc" > "out/${res}.rc"
  return 0
}

# aggregate_verdict — чистый вердикт ПО ОТЧЁТАМ. Печатает таблицу и возвращает 1,
# если у любого stem: нет out/<stem>.json (MISSING), assertions.failed>0 или rc!=0.
aggregate_verdict() {
  local out_dir="$1"; shift
  local bad=0 stem json rcfile rc total failed requests unanswered note
  local reported=0 expected=$# s_req=0 s_unans=0 s_ass=0 s_fail=0 s_mute=0
  printf "%-38s %10s %10s %10s %12s %8s  %s\n" \
    "RESOURCE" "ASSERT" "FAILED" "REQUESTS" "UNANSWERED" "RC" "NOTE"
  for stem in "$@"; do
    json="${out_dir}/${stem}.json"
    rcfile="${out_dir}/${stem}.rc"
    rc="n/a"
    [[ -f "$rcfile" ]] && rc="$(cat "$rcfile")"
    if [[ ! -f "$json" ]]; then
      printf "%-38s %10s %10s %10s %12s %8s  %s\n" "$stem" "-" "-" "-" "-" "MISSING" \
        "нет отчёта — коллекция не отработала"
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

    # Два измерения, которых у этого вердикта не было — единственного из восьми
    # агрегаторов дерева (у vpc, compute, geo, storage, registry, nlb и gateway они
    # есть). Оба читаются как безупречный прогон, если смотреть только на число
    # упавших утверждений: провалов ноль, потому что проверять было нечего.
    note=""
    if [[ "$total" -eq 0 ]]; then
      note="NOTHING RAN — 0 утверждений; суита, которая ничего не спросила, не проходит"
      s_mute=$((s_mute + 1))
      bad=1
    fi
    if [[ "$unanswered" -gt 0 ]]; then
      note="${note:+$note; }UNANSWERED — запросы без ответа НЕ вычитаются"
      bad=1
    fi

    printf "%-38s %10s %10s %10s %12s %8s  %s\n" \
      "$stem" "$total" "$failed" "$requests" "$unanswered" "$rc" "$note"

    # Назвать то, что не ответило: счётчик сам по себе не действие.
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
  # Вердикт в числах. Первая пара читается ПЕРВОЙ: при оборванном прогоне все
  # остальные счётчики выглядят здоровыми.
  printf "TOTAL: %d/%d коллекций отчиталось — %d запрос(ов), %d без ответа, %d утверждени(й), %d упавших, %d немых отчёт(ов)\n" \
    "$reported" "$expected" "$s_req" "$s_unans" "$s_ass" "$s_fail" "$s_mute"
  return "$bad"
}


# Start from a clean out/ — a stale reporter JSON from an earlier run (or one
# accidentally committed to git) would otherwise be picked up by the summary
# below and resurface as a phantom suite with frozen pass/fail numbers (this is
# exactly how `authz-deny-rerun` — a 511-failure ghost — leaked into the
# newman-e2e gate). out/ is .gitignore'd; this rm is the belt to that suspenders.
# Targeted rm (not `rm -rf out`) so an out/suite.log already opened by
# deploy/scripts/newman-parallel.sh is not unlinked from under it.
mkdir -p out
rm -f out/*.json out/*.cli out/*.rc out/summary.txt out/coverage.txt 2>/dev/null || true

# ─── Кого этот прогон НЕ гоняет ─────────────────────────────────────────────
# Набор считается ЗДЕСЬ, ДО единственного места, где коллекции запускаются, — и
# это не оформление. Раньше он считался ниже, между последним `run_one` и
# сводкой, поэтому вычитание доставалось ТОЛЬКО вердикту: коллекции волны
# успевали отработать под машинным принципалом, а строка «делегировано
# коллекций: 5» печаталась после того, как все пять уже прошли. Со стороны
# механизм выглядел исполненным, и он даже называл верное число — просто ничего
# из названного не делал.
#
# Цена была двойной: пять коллекций гонялись ДВАЖДЫ за прогон (здесь под чужим
# предъявителем, где их человеческие шаги честно падают на своём страже, и потом
# в своей волне), а сводка этой суиты краснела на шагах, условие которых на этом
# этапе ещё не создано, — то есть вердикт прогонщика и вердикт гейта расходились
# по построению.
DELEGATED=(authz-failclosed)
_CEREMONY_ROOT="$(cd ../../../.. && pwd)"
_CEREMONY_DECL="$_CEREMONY_ROOT/tests/authz-fixtures/ceremony_credentials.py"
if [[ -f "$_CEREMONY_DECL" ]] && command -v python3 >/dev/null 2>&1 \
   && python3 "$_CEREMONY_DECL" --root "$_CEREMONY_ROOT" --seed-exists 2>/dev/null; then
  _n_before="${#DELEGATED[@]}"
  while IFS= read -r _cs; do
    [[ -n "$_cs" ]] && DELEGATED+=("$_cs")
  done < <(python3 "$_CEREMONY_DECL" --root "$_CEREMONY_ROOT" \
             --suite services/iam/tests/newman --stems 2>/dev/null)
  echo "[ceremony] волна церемонии активна — делегировано коллекций: $(( ${#DELEGATED[@]} - _n_before ))"
fi
_is_delegated() {
  local s
  for s in "${DELEGATED[@]}"; do [[ "$1" == "$s" ]] && return 0; done
  return 1
}

if [[ -n "$SERVICE" ]]; then
  # Pre-run reseed for jit-pending suite to ensure seed rows are PENDING.
  run_one "$SERVICE" explicit
else
  # authz matrices + the IAM resource suites (Case/Step format).
  # NB: the legacy iam-access-binding suite is RETIRED — superseded by
  # iam-access-binding-redesign (IAM-1 F7-F11, the new scope_type/target/revoke
  # contract). The legacy suite tested the tombstoned scope/scope_ref surface and
  # was only half-migrated; the redesign suite is the authoritative AccessBinding
  # coverage.
  for res in authz-deny authz-sa-apitoken iam-account iam-project iam-user iam-role iam-group iam-service-account iam-rbac-scope-grant iam-rbac-rules-labels iam-rbac-subjects iam-whoami; do
    run_one "$res"
  done
  # IAM-1 REDESIGN authz-core suites (Account/Project tenancy-tree, Role
  # definitionTier+catalog, AccessBinding scope+target+revoke) — tenant-facing
  # source-of-truth for the new contract (docs/specs/sub-phase-IAM-1-tenancy-
  # authz-core-acceptance.md, F1-F11). gen.py emits collections/iam-*-redesign.json,
  # and the CI `assert all suites green` step parses EVERY collections/*.json — so
  # these MUST run here, else the gate reports `iam-*-redesign(no-report)` as a
  # phantom failure. Env deps seeded by the shared authz-fixtures.
  run_one "iam-account-redesign"
  run_one "iam-role-redesign"
  run_one "iam-access-binding-redesign"
  # iam-access-binding-account-scope — поле `accountId` у канонического List:
  # «выдачи субъекта в названном аккаунте» одним вызовом (задача #1737, приёмка
  # docs/engineering/acceptance/subject-grants-within-an-account.md). Строка
  # обязательна: гейт `assert all suites green` разбирает КАЖДУЮ
  # collections/*.json, поэтому без неё коллекция не отработает, а гейт доложит
  # `iam-access-binding-account-scope(no-report)` — фантомный отказ, а не тишину.
  # Зависимости окружения (jwtAccountAdminA / jwtPureNoBindings / accountAId /
  # accountBId / projectA1Id / userNOBId) сеются общими authz-фикстурами.
  run_one "iam-access-binding-account-scope"
  # iam-access-binding-include-revoked — флаг `includeRevoked` на ДВУХ остальных
  # поверхностях, которые его принимают: `accounts/{id}/accessBindings`
  # (ListByAccount) и `accessBindings:listByRole` (ListByRole). Перечень
  # поверхностей выведен из контракта (`bool include_revoked` встречается в
  # трёх запросах), третью — канонический List — покрывает соседняя коллекция.
  # Порядок: сразу за ней, зависимости окружения те же самые.
  #
  # Остаточный проход ниже подобрал бы коллекцию и без этой строки (набор
  # вердикта выводится из дерева, а не из перечня вызовов), но подхват — сигнал
  # автору, а не норма: место в порядке у коллекции есть, и оно здесь.
  run_one "iam-access-binding-include-revoked"
  # geo-read — AUTHENTICATED kacho-geo public reads through the api-gateway
  # (gateway->geo "no children to pick from" 503 regression; api-gateway#83 +
  # deploy#99). kacho-geo has no own tests/newman/, so the authenticated geo
  # read lives in this harness (already wired to the authz-fixtures JWT +
  # api-gateway endpoint). The CI `assert all suites green` step parses EVERY
  # collections/*.json — so this MUST run here, else the gate reports
  # `geo-read(no-report)` as a phantom failure.
  run_one "geo-read"
  run_one "iam-internal-only-check"
  # iam-permission-catalog — PermissionCatalogService.ListPermissionCatalog
  # (sub-phase G): backend-driven grantable role-rule catalog on the PUBLIC mux
  # (GET /iam/v1/permissionCatalog). Authenticated read + anonymous-deny. The CI
  # `assert all suites green` step parses EVERY collections/*.json — so this MUST
  # run here, else the gate reports `iam-permission-catalog(no-report)` as a
  # phantom failure.
  run_one "iam-permission-catalog"
  # iam-membership-read — чтение принадлежности человека аккаунту на
  # аккаунт-скоупных путях (IAM-ID-2, стадия S1). Три полосы отрицаний
  # утверждаются СРАВНЕНИЕМ ТЕЛ, а не совпадением кодов: чужой аккаунт против
  # несуществующего, три положения человека против пустого перечня, чужое
  # членство против отсутствующего.
  #
  # Прогон объявляется ЗДЕСЬ, потому что шаг сводного вердикта разбирает КАЖДЫЙ
  # collections/*.json: без этой строки набор исполнялся бы нулём коллекций, а
  # гейт назвал бы `iam-membership-read(no-report)` — и это читалось бы как
  # призрачный отказ, а не как «набор не запускали».
  run_one "iam-membership-read"
  # iam-token-facade-conformance — #59 Phase C: iam is the SINGLE FACADE to the
  # token-signing provider (security.md §«Production-mode обязателен ВЕЗДЕ» п.4).
  # IBT-04/05/06/10 (the acceptance's e2e-conformance scenarios) + IBT-12/13/14/15
  # (the mirror / hook / docker-handle / provider-surface lanes the acceptance has no
  # scenario for). Needs FOUR extra base URLs beyond the gateway ones —
  # iamJwksBaseUrl / providerPublicBaseUrl / iamRegistryTokenBaseUrl /
  # registryDataPlaneBaseUrl — injected as --env-var by
  # deploy/scripts/newman-{e2e,parallel}.sh; a missing one turns the case RED naming
  # the variable (require_env_url), never a silent skip. The CI `assert all suites
  # green` step parses EVERY collections/*.json, so this MUST run here — otherwise the
  # gate reports `iam-token-facade-conformance(no-report)` as a phantom failure.
  run_one "iam-token-facade-conformance"
  # The atomic grant→FGA-Check propagation suite (AccessBinding/JIT/BG
  # paths). The CI `assert all suites green` step parses every
  # collections/*.postman_collection.json, so the report for this suite MUST
  # exist — otherwise the assertion-gate reports
  # `iam-authz-grant-check-propagation(no-report)` as a phantom failure even
  # though all cases would pass. Run it here.
  run_one "iam-authz-grant-check-propagation"
  # iam-invite-grant-fga: invite→activate→grant(anchor role on project)→invitee
  # SEES the granted project+account AND has its own personal default account+project
  # (RC-1/RC-2/RC-5). gen.py emits collections/iam-invite-grant-fga.json from
  # cases/iam-invite-grant-fga.py, and the CI `assert all suites green` step parses
  # EVERY collections/*.json — so without running it here the gate reports
  # `iam-invite-grant-fga(no-report)` as a phantom failure.
  run_one "iam-invite-grant-fga"
  # T3.1 cross-service ARM_LABELS revoke-on-label-change (workspace#113). These
  # suites grant an ARM_LABELS role on a vpc/compute/nlb resource (matchLabels)
  # and assert visibility (InternalIAMService.Check v_list) appears on Create and
  # is REVOKED when the matching label is removed/changed on the resource. They
  # are CROSS-SERVICE: they require kacho-vpc / kacho-compute / kacho-nlb deployed
  # alongside kacho-iam behind the gateway (the `*→iam` RegisterResource edge that
  # feeds resource_mirror with labels). The newman-e2e of EVERY repo (iam / vpc /
  # compute / nlb / deploy) brings up the FULL kacho-deploy umbrella (all services)
  # and runs this shared iam suite, so these run against a complete stack — GREEN
  # since the T3.1 fixes are in vpc/compute/nlb@main (47d707d / 4a0b010 / 3cf783e).
  # The CI `assert all suites green` step parses EVERY collections/*.json, so they
  # MUST run here to produce the report the gate expects.
  run_one "label-revoke-vpc"
  run_one "label-revoke-nlb"
  # label-revoke-storage — the OWNER-side carrier. label-revoke-compute is GONE: the
  # block-storage duplicate in kacho-compute it drove (Disk/Image/Snapshot) is retired,
  # and this suite was added ahead of that removal precisely so the evidence would not
  # leave with it. Same shape, storage FGA types (storage_volume / storage_snapshot /
  # storage_image). GREEN and deliberately NOT whitelisted — see docs/RESULTS.md
  # "Resolved — label-remove on storage revokes". It was red on the revoke half when
  # written and was fixed the same day; the note here claiming otherwise outlived the
  # fix. With the compute duplicate gone this is the ONLY carrier of the property, so
  # a red here is a product finding standing on its own, never a budget to widen.
  run_one "label-revoke-storage"
  # label-revoke-iam — the IAM-NATIVE analogue: a label clear via
  # ProjectService.Update(update_mask=labels, empty body) must CLEAR the labels
  # (not a silent no-op) and REVOKE the ARM_LABELS grant on iam.project (v_list
  # True->False). Unlike the cross-service suites above, the selectable resource is
  # iam-native (label-selectable iam-direct, same-DB), so it runs fully against the
  # IAM-only stack too. gen.py ALWAYS emits collections/label-revoke-iam.json, and
  # the CI `assert all suites green` step parses EVERY collections/*.json — so this
  # MUST run here, else the gate reports `label-revoke-iam(no-report)` as a phantom
  # failure. Env deps (jwtBootstrap / jwtAccountAdminA / accountAId) are seeded by
  # the shared authz-fixtures.
  run_one "label-revoke-iam"
  # iam-flat-authz-vbc — Design-B flat-authz verb-bearing iam-native suite (VBC-16
  # AccessBinding.Create lowercase-subject-type id-prefix derive: happy usr-prefix +
  # 400 bad-prefix negative). gen.py ALWAYS emits collections/iam-flat-authz-vbc.json,
  # and the CI `assert all suites green` step parses EVERY collections/*.json — so
  # without running it here the gate reports `iam-flat-authz-vbc(no-report)` as a
  # phantom failure (the integrated-umbrella NO-REPORT). Its env deps (jwtAccountAdminA
  # / accountAId / userNOBId) are all seeded by the shared authz-fixtures (patch-env.py
  # copies every fixture key into the env), so it runs against the same authenticated
  # env as the other authz suites — no extra fixture bootstrap needed.
  run_one "iam-flat-authz-vbc"
  # iam-read-authz-vget — read-authz v_get fix: a non-owner granted iam.account.get
  # (v_get on account:<id>) reads the account → 200 (was 404 owner-only use-case gate),
  # plus a no-grant negative (403 PERMISSION_DENIED). gen.py ALWAYS emits
  # collections/iam-read-authz-vget.json, and the CI `assert all suites green` step
  # parses EVERY collections/*.json — so without running it here the gate reports
  # `iam-read-authz-vget(no-report)` as a phantom failure. Env deps (jwtAccountAdminA /
  # accountAId / jwtInvitee / userINVId / jwtNoBindings) are seeded by the shared
  # crud / authz fixtures (patch-env.py copies every fixture key into the env).
  run_one "iam-read-authz-vget"
  # rbac-subject-channel-equivalence — INV-9 subject-channel equivalence (the SAME
  # ROLE_VIEW@ACCOUNT grant delivered via user-direct / group-member / SA-token yields
  # identical account v_get + project visible-set) + per-channel delta cases (membership
  # flip, revoke-binding, non-member deny, SA↔user principal isolation). gen.py ALWAYS
  # emits collections/rbac-subject-channel-equivalence.json, and the CI `assert all suites
  # green` step parses EVERY collections/*.json — so without running it here the gate
  # reports `rbac-subject-channel-equivalence(no-report)` as a phantom failure. Env deps
  # (jwtAccountAdminA / accountAId / projectA1Id / userINVId / jwtInvitee / jwtNoBindings /
  # svaAId / jwtSAA / jwtSANoGrant) are all seeded by the shared fixtures.
  run_one "rbac-subject-channel-equivalence"
  # rbac-visibility-set — exact-set visibility invariants on the live label-selectable iam
  # content types (project + serviceAccount + group + role): INV-2 (by-label grant → subject
  # sees EXACTLY the foo=runId M+ set; M− / other-label hidden) + INV-1 (v_list-only grant →
  # object visible in List but detail Get 404; v_list ≠ v_get). gen.py ALWAYS emits
  # collections/rbac-visibility-set.json, so it MUST run here or the gate reports
  # `rbac-visibility-set(no-report)`. Env deps (jwtAccountAdminA / accountAId / userINVId /
  # jwtInvitee) are seeded by the shared fixtures.
  run_one "rbac-visibility-set"
  # iam-interactive-client — CRUD/валидация клиента интерактивного входа на
  # cluster-internal листенере (ic-id, ровно один https-audience, grant
  # authorization_code; повтор имени → ALREADY_EXISTS; redirect_uris; malformed-id
  # → INVALID_ARGUMENT, а НЕ NOT_FOUND; immutable-vs-unknown в маске; повторное
  # удаление идемпотентно). Условия ЧЕЛОВЕКА не требует и в DELEGATED-набор
  # (authz-failclosed + волна церемонии) не входит — значит место ему здесь.
  # gen.py ВСЕГДА эмитит collections/iam-interactive-client.json, а авторитетный
  # гейт разбирает КАЖДУЮ collections/*.json, поэтому без этого вызова коллекция
  # не отрабатывает вовсе и докладывается `iam-interactive-client(no-report)`:
  # восемь кейсов, которые не могут упасть, потому что не исполняются.
  run_one "iam-interactive-client"
  # iam-limit — потолки на число ресурсов арендатора на cluster-internal листенере
  # (issue #291 S1): назначение предела и его форма (`lim-`-id, область видимости,
  # предмет, вид, величина, ревизия); отрицательная величина и вид вне закрытого
  # каталога отвергаются ПО ИМЕНИ и ничего не оставляют; повтор тройки →
  # ALREADY_EXISTS, а отозванный предел освобождает её снова; malformed-id →
  # INVALID_ARGUMENT, а НЕ NOT_FOUND; разрешение перекрытий и возврат к умолчанию;
  # узкое отношение на служебном чтении; дельта видит изменение и НЕ видит повтор
  # того же значения. Условия ЧЕЛОВЕКА не требует (вызывающий — машинный принципал
  # bootstrap), в DELEGATED-набор не входит — значит место ему здесь.
  # gen.py ВСЕГДА эмитит collections/iam-limit.json, а авторитетный гейт разбирает
  # КАЖДУЮ collections/*.json, поэтому без этого вызова коллекция не отрабатывает
  # вовсе и докладывается `iam-limit(no-report)`: одиннадцать кейсов, которые не
  # могут упасть, потому что не исполняются.
  run_one "iam-limit"
  # iam-list-visibility — страница списка есть страница ВИДИМОГО (задача #645):
  # свой объект лежит на ПЕРВОЙ маленькой странице, хотя перед ним по времени
  # создания лежат чужие, и ни одной чужой строки с ним не приходит. Порог
  # воспроизводится размером страницы, а не набивкой объектов, поэтому кейсам не
  # нужно ни одного создания — только фикстурные идентичности (jwtAccountAdminB /
  # accountAId / accountBId / projectA1Id / projectB1Id / userAAAId / userAABId),
  # которые сеют общие фикстуры. Условия ЧЕЛОВЕКА не требует и в DELEGATED-набор
  # не входит — значит место ему здесь.
  # gen.py ВСЕГДА эмитит collections/iam-list-visibility.json, а авторитетный гейт
  # разбирает КАЖДУЮ collections/*.json, поэтому без этого вызова коллекция не
  # отрабатывает вовсе и докладывается `iam-list-visibility(no-report)`: три кейса,
  # которые не могут упасть, потому что не исполняются.
  run_one "iam-list-visibility"

  # Встроенный доступ платформы виден на поверхности выдач — чёрным ящиком, тем
  # же публичным списком, которым пользуется администратор (#893/#895).
  # Условия ЧЕЛОВЕКА не требует и в DELEGATED-набор не входит: спрашивает
  # кластерный администратор (jwtBootstrap), а законного близнеца — обычную
  # выдачу с ролью — сеют общие фикстуры. Значит место ему здесь.
  # gen.py ВСЕГДА эмитит collections/iam-system-grant-visibility.json, а
  # авторитетный гейт разбирает КАЖДУЮ collections/*.json, поэтому без этого
  # вызова коллекция не отрабатывает вовсе и докладывается
  # `iam-system-grant-visibility(no-report)` — ровно так она и приехала в ствол
  # вместе со своей работой: сгенерирована, посчитана в 34, ни разу не исполнена.
  run_one "iam-system-grant-visibility"

  # iam-subject-privileges-read — перечень выдач НАЗВАННОГО субъекта чёрным
  # ящиком (задача #1438). Три полосы допуска: сам субъект (несужённо) ·
  # распорядитель домашнего аккаунта (страница СУЖЕНА его аккаунтом, #1354) ·
  # посторонний (отказ, и отказ не оракул существования). До неё обе полосы
  # держались пробами уровня кода, а поверхность, куда ходит арендатор, не
  # проверялась ничем.
  #
  # Условия ЧЕЛОВЕКА не требует и в DELEGATED-набор не входит: все вызывающие —
  # служебные учётки общих фикстур (jwtInvitee / jwtAccountAdminA /
  # jwtAccountAdminB / jwtPureNoBindings), своих записей набор не создаёт.
  # Значит место ему здесь.
  #
  # ВЫЗОВ ЗДЕСЬ — ради МЕСТА В ПОРЯДКЕ, а не ради самого факта прогона: блок
  # «остаток» ниже подобрал бы коллекцию и без него (`_was_run` только
  # исключает повтор), напечатав `[remainder] iam-subject-privileges-read …`.
  # Подхват остатком — сигнал автору, что коллекции, возможно, нужно место
  # среди соседей; здесь оно названо явно, потому что набор читает выдачи
  # общих фикстур и обязан идти ПОСЛЕ того, как соседи их завели.
  run_one "iam-subject-privileges-read"

  # ─── ОСТАТОК: коллекции, которых рукописный перечень выше не назвал ────────
  #
  # ПОЧЕМУ ОН ЕСТЬ. Перечень вызовов выше — рукописный, а набор коллекций
  # выводится из дерева (`gen.py` эмитит их из `cases/*.py`). Два перечня об
  # одном предмете расходятся молча, и расходятся они РОВНО в одну сторону:
  # новая коллекция генерируется, считается в ожидаемых и не исполняется ни
  # разу. Со стороны это выглядит как «суита отработала».
  #
  # КЛАСС ИЗМЕРЕН, А НЕ ПРЕДПОЛОЖЕН. Он уже случался: `iam-system-grant-visibility`
  # приехала в ствол сгенерированной, посчитанной и ни разу не исполненной — и
  # была починена ЭКЗЕМПЛЯРОМ (добавили один вызов), а не классом. Класс
  # повторился на следующей же волне: `basic-access-token` и
  # `docker-lane-credential-kind` доложились гейту как `(no-report)`, то есть
  # семь и шесть шагов не судил никто.
  #
  # ЧТО ДЕЛАЕТ. Гоняет всё сгенерированное, чего перечень не назвал и что не
  # делегировано своей волне, и НАЗЫВАЕТ подобранное поимённо: подхват — не
  # норма, а сигнал автору, что у коллекции, возможно, есть место в порядке
  # (посев, зависимость от соседа). Печатается перепись, поэтому «подобрано 0»
  # отличимо от «не смотрели».
  _rest_seen=0 _rest_taken=0
  while IFS= read -r _stem; do
    [[ -n "$_stem" ]] || continue
    _rest_seen=$((_rest_seen + 1))
    _was_run "$_stem" && continue
    _is_delegated "$_stem" && continue
    _rest_taken=$((_rest_taken + 1))
    echo "[remainder] ${_stem} — сгенерирована, но перечнем вызовов НЕ названа; гоню здесь"
    run_one "$_stem"
  done < <(newman_present_stems "$NEWMAN_DIR")
  echo "[remainder] коллекций сгенерировано ${_rest_seen} · подобрано остатком ${_rest_taken}"
fi

# ─── Verdict ──────────────────────────────────────────────────────────────
# Набор вердикта = сгенерированные коллекции ∪ stem'ы, для которых run_one оставил
# .rc. Дублировать здесь список прогона не нужно (и нечему разъезжаться): коллекция,
# которую этот скрипт забыл прогнать, не имеет отчёта → MISSING → красный.
#
# DELEGATED — коллекции, которым нужно условие, несовместимое с этим прогоном.
# Их гоняет ОТДЕЛЬНАЯ ВОЛНА (см. ниже), поэтому здесь они из набора вычитаются —
# но только из ЭТОГО набора. Авторитетный гейт (scripts/assert-suites-green.sh)
# по-прежнему требует отчёт для КАЖДОЙ collections/*.json и докладывает
# `<stem>(no-report)`, если волна не отработала. То есть вычитание здесь ничего
# спрятать не может: оно снимает ложный MISSING у прогонщика, а не проверку.
#
#   authz-failclosed — нужен ВЫКЛЮЧЕННЫЙ store прав; scripts/run-failclosed.sh
#     сворачивает его в ноль, гоняет коллекцию и поднимает обратно. Волну
#     запускает deploy/scripts/newman-parallel.sh (WAVE 3, после всех суит) либо
#     отдельный шаг CI — соседям выключенный store прав сломал бы всё.
#
#   волна ЦЕРЕМОНИИ — коллекции, часть шагов которых требует ЧЕЛОВЕЧЕСКОГО
#     вызывающего (аккаунт принадлежит пользователю by construction; уровень
#     аутентификации поднимается только церемонией входа). Машинный посев такого
#     предъявителя не производит, поэтому сейчас эти шаги идут под ЧУЖИМ
#     принципалом: часть падает, часть зеленеет по неверной причине. Их гоняет
#     scripts/run-ceremony.sh (WAVE 4 в deploy/scripts/newman-parallel.sh) — волна,
#     которая условие СОЗДАЁТ посевом церемонии.
#
#     Перечень НЕ выписан здесь и не будет: он ВЫВОДИТСЯ из дерева единственным
#     объявлением (tests/authz-fixtures/ceremony_credentials.py) на каждом запуске,
#     по двум основаниям сразу — переменная предъявителя, которую посев не куёт, и
#     форма запроса, требующая человека структурно. Выписанный перечень в этом
#     репозитории уже расходился с деревом.
#
#     Вычитание включается РОВНО ТОГДА, когда посев церемонии существует в дереве
#     (артефакт стадии S2). Пока его нет, условие создавать нечем — коллекции идут
#     здесь, как и раньше, а долг называется ЧИСЛОМ там, где планируются волны
#     (`ceremony_credentials.py --debt`). Предикат внешний: его выполняет чужая
#     стадия, а не эта правка, — поэтому он не может быть отменён ею же.
stems=()
if [[ -n "$SERVICE" ]]; then
  stems=("$SERVICE")
else
  while IFS= read -r s; do
    [[ -n "$s" ]] || continue
    if _is_delegated "$s"; then
      echo "[verdict-skip] ${s} — вне набора вердикта ЭТОГО прогонщика: отчёт по нему пишет своя волна, а грейдит assert-suites-green.sh"
      continue
    fi
    stems+=("$s")
  done < <(
    {
      newman_present_stems "$NEWMAN_DIR"
      for f in out/*.rc; do
        [[ -e "$f" ]] && basename "$f" .rc
      done
    } | sort -u
  )
fi

echo
echo "===== Summary ====="
SUITE_FAIL=0
# pipefail прокидывает ненулевой вердикт сквозь tee — печать сводки сохранена.
if aggregate_verdict "out" "${stems[@]}" | tee out/summary.txt; then
  echo "OK: все iam-коллекции зелёные."
else
  SUITE_FAIL=1
  echo "FAIL: одна или несколько iam-коллекций провалены / отсутствуют (см. таблицу выше)." >&2
fi

# ─── Coverage gate ───────────────────────────────────────────────────────
# After running all newman collections, summarise RPC→case-id coverage by
# parsing the iam .proto files vs ./collections/*.json. Exit-code is 0 unless
# COVERAGE_MIN is set AND coverage% drops below it (set this in CI to enforce a
# floor).
#
# The .proto live at the MONOREPO ROOT (<root>/proto/kacho/cloud/<domain>/v1) — this
# suite sits at <root>/services/iam/tests/newman, so the default glob is four levels
# up. The previous default (`../../../kacho-proto/proto/…`) addressed the polyrepo
# layout where kacho-proto was a sibling CHECKOUT; in the monorepo it resolves to
# services/kacho-proto/… which does not exist → coverage.py exits 2 ("no RPCs
# discovered") → the whole iam suite went red with zero failing assertions.
# Both layouts are supported: the first glob that actually matches .proto files wins,
# so a standalone/polyrepo checkout with a sibling kacho-proto still resolves.
# COVERAGE_PROTO_GLOB overrides both (CI may pass an absolute path).
if command -v python3 >/dev/null 2>&1 && [ -f scripts/coverage.py ]; then
  echo
  echo "===== coverage ====="
  COV_MIN="${COVERAGE_MIN:-0}"
  PROTO_GLOB="${COVERAGE_PROTO_GLOB:-}"
  if [ -z "$PROTO_GLOB" ]; then
    for _cand in \
      '../../../../proto/kacho/cloud/iam/v1/*.proto' \
      '../../../kacho-proto/proto/kacho/cloud/iam/v1/*.proto'; do
      # shellcheck disable=SC2086
      if compgen -G "$_cand" >/dev/null 2>&1; then PROTO_GLOB="$_cand"; break; fi
    done
    PROTO_GLOB="${PROTO_GLOB:-../../../../proto/kacho/cloud/iam/v1/*.proto}"
  fi
  echo "proto-glob: $PROTO_GLOB"
  if python3 scripts/coverage.py \
       --proto-glob "$PROTO_GLOB" \
       --collections-glob 'collections/*.postman_collection.json' \
       --min "$COV_MIN" | tee out/coverage.txt; then
    :
  else
    COVERAGE_FAIL=$?
  fi
fi

if [ "$SUITE_FAIL" -ne 0 ]; then exit 1; fi
exit "${COVERAGE_FAIL:-0}"
