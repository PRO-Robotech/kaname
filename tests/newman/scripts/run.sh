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
# Outputs:
#   out/<resource>.json — newman JSON reporter (для агрегации)
#   out/<resource>.cli  — newman cli-вывод
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

run_one() {
  local res="$1"
  local col="collections/${res}.postman_collection.json"
  if [[ ! -f "$col" ]]; then
    echo "[skip] $res — нет коллекции"
    return 0
  fi
  echo "===== ${res} ====="
  newman run "$col" \
    -e "$ENV" \
    --delay-request "$DELAY" \
    $BAIL \
    --reporters cli,json \
    --reporter-json-export "out/${res}.json" \
    ${EXTRA[@]+"${EXTRA[@]}"} 2>&1 | tee "out/${res}.cli" || true
}


# Start from a clean out/ — a stale reporter JSON from an earlier run (or one
# accidentally committed to git) would otherwise be picked up by the summary
# loop below and resurface as a phantom suite with frozen pass/fail numbers
# (this is exactly how `authz-deny-rerun` — a 511-failure ghost — leaked into
# the newman-e2e gate). out/ is .gitignore'd; this rm is the belt to that
# suspenders.
rm -rf out
mkdir -p out

if [[ -n "$SERVICE" ]]; then
  # Pre-run reseed for jit-pending suite to ensure seed rows are PENDING.
  run_one "$SERVICE"
else
  # authz matrices + the IAM resource suites (Case/Step format).
  for res in authz-deny authz-sa-apitoken iam-account iam-project iam-user iam-role iam-group iam-service-account iam-access-binding iam-rbac-scope-grant iam-rbac-rules-labels iam-rbac-subjects iam-whoami; do
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
  # The atomic grant→FGA-Check propagation suite (AccessBinding/JIT/BG
  # paths). The CI `assert all suites green` step parses every
  # collections/*.postman_collection.json, so the report for this suite MUST
  # exist — otherwise the assertion-gate reports
  # `iam-authz-grant-check-propagation(no-report)` as a phantom failure even
  # though all cases would pass. Run it here.
  run_one "iam-authz-grant-check-propagation"
  # SEC-C FGA-proxy suite. gen.py emits collections/sec-c-fga-proxy.json from
  # cases/sec-c-fga-proxy.py, and the CI `assert all suites green` step parses
  # EVERY collections/*.json — so without running it here the gate reports
  # `sec-c-fga-proxy(no-report)` as a phantom failure. Its cases hit the
  # Internal FGA-proxy RPCs (RegisterResource/UnregisterResource) which are
  # cluster-internal :9091-only with NO google.api.http mapping (ban #6) — they
  # are NOT reachable as black-box REST through the api-gateway and are covered
  # at the integration level (internal/.../fgaproxy_test.go). The cases stay
  # whitelisted as known-RED in newman-e2e.yml; running the collection just
  # produces the report the gate expects.
  run_one "sec-c-fga-proxy"
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
  run_one "label-revoke-compute"
  run_one "label-revoke-nlb"
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

echo
echo "===== Summary ====="
{
  printf "%-22s %10s %10s %10s\n" "RESOURCE" "ASSERT" "FAILED" "REQUESTS"
  for f in out/*.json; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f" .json)
    stats=$(jq -r '"\(.run.stats.assertions.total) \(.run.stats.assertions.failed) \(.run.stats.requests.total)"' "$f" 2>/dev/null || echo "0 0 0")
    set -- $stats
    printf "%-22s %10s %10s %10s\n" "$name" "$1" "$2" "$3"
  done
} | tee out/summary.txt

# ─── Coverage gate ───────────────────────────────────────────────────────
# After running all newman collections, summarise RPC→case-id coverage by
# parsing the iam .proto files vs ./collections/*.json. Exit-code is 0 unless
# COVERAGE_MIN is set AND coverage% drops below it (set this in CI to enforce a
# floor).
#
# The .proto live ONLY in kacho-proto (proto is centralized; there is no in-repo
# proto/ dir). COVERAGE_PROTO_GLOB overrides the glob so CI can point it at the
# kacho-proto sibling checkout (absolute path); the default is kept as a local-dev
# convenience for a checkout that vendors a sibling kacho-proto alongside this repo.
if command -v python3 >/dev/null 2>&1 && [ -f scripts/coverage.py ]; then
  echo
  echo "===== coverage ====="
  COV_MIN="${COVERAGE_MIN:-0}"
  if python3 scripts/coverage.py \
       --proto-glob "${COVERAGE_PROTO_GLOB:-../../../kacho-proto/proto/kacho/cloud/iam/v1/*.proto}" \
       --collections-glob 'collections/*.postman_collection.json' \
       --min "$COV_MIN" | tee out/coverage.txt; then
    :
  else
    COVERAGE_FAIL=$?
  fi
fi

exit "${COVERAGE_FAIL:-0}"
