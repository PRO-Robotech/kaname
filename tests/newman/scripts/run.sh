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
[[ -f "$ENV" ]] || { echo "missing env: $ENV"; exit 1; }

# run_one — прогон одной коллекции. Пишет out/<res>.json|.cli|.rc.
run_one() {
  local res="$1"
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
  local bad=0 stem json rcfile rc total failed requests
  printf "%-38s %10s %10s %10s %8s\n" "RESOURCE" "ASSERT" "FAILED" "REQUESTS" "RC"
  for stem in "$@"; do
    json="${out_dir}/${stem}.json"
    rcfile="${out_dir}/${stem}.rc"
    rc="n/a"
    [[ -f "$rcfile" ]] && rc="$(cat "$rcfile")"
    if [[ ! -f "$json" ]]; then
      printf "%-38s %10s %10s %10s %8s\n" "$stem" "-" "-" "-" "MISSING"
      bad=1
      continue
    fi
    total=0; failed=0; requests=0
    read -r total failed requests < <(
      jq -r '"\(.run.stats.assertions.total) \(.run.stats.assertions.failed) \(.run.stats.requests.total)"' \
        "$json" 2>/dev/null || echo "0 0 0"
    )
    [[ "$total" =~ ^[0-9]+$ ]]    || total=0
    [[ "$failed" =~ ^[0-9]+$ ]]   || failed=0
    [[ "$requests" =~ ^[0-9]+$ ]] || requests=0
    printf "%-38s %10s %10s %10s %8s\n" "$stem" "$total" "$failed" "$requests" "$rc"
    if [[ "$failed" -gt 0 ]]; then bad=1; fi
    if [[ "$rc" != "0" ]];    then bad=1; fi
  done
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

if [[ -n "$SERVICE" ]]; then
  # Pre-run reseed for jit-pending suite to ensure seed rows are PENDING.
  run_one "$SERVICE"
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
  # iam-condition — ConditionsService CRUD over the conventional projectId scope.
  # gen.py emits collections/iam-condition.json from cases/iam-condition.py, and the
  # CI `assert all suites green` step parses EVERY collections/*.json — so without
  # running it here the gate reports `iam-condition(no-report)` as a phantom failure.
  run_one "iam-condition"
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
fi

# ─── Verdict ──────────────────────────────────────────────────────────────
# Набор вердикта = сгенерированные коллекции ∪ stem'ы, для которых run_one оставил
# .rc. Дублировать здесь список прогона не нужно (и нечему разъезжаться): коллекция,
# которую этот скрипт забыл прогнать, не имеет отчёта → MISSING → красный.
stems=()
if [[ -n "$SERVICE" ]]; then
  stems=("$SERVICE")
else
  while IFS= read -r s; do
    [[ -n "$s" ]] && stems+=("$s")
  done < <(
    {
      for f in collections/*.postman_collection.json; do
        [[ -e "$f" ]] && basename "$f" .postman_collection.json
      done
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
