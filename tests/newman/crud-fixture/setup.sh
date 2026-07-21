#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# tests/newman/crud-fixture/setup.sh — lightweight CRUD fixture for the
# iam-account newman suite.
#
# Provides a single seeded owner user + JWT that AccountService CRUD cases need.
# This is a MINIMAL alternative to the full authz-fixtures/setup.sh.
# If the full authz fixture has already been run, skip this script — all env vars
# it exports are a strict subset of what authz-fixtures/setup.sh produces.
#
# Prerequisites:
#   - kacho-iam api-gateway reachable at BASE_URL
#   - kacho-iam InternalUserService reachable at IAM_INTERNAL_GRPC via grpcurl
#   - grpcurl installed (go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
#
# Env vars exported (written to OUT_DIR/crud-fixtures.json + patched into
# environments/local.postman_environment.json when PATCH_ENV=true):
#
#   jwtAccountAdminA  — HS256 JWT (sub=crud-owner@kacho.local, exp=24h)
#   userAAAId         — User.id of the seeded owner (usr<...>)
#   accountAId        — pre-seeded Account for Get/Update/Delete probes (acc<...>)
#   accountBId        — second Account for isolation probes (acc<...>)
#   jwtAccountAdminB  — JWT for accountBId owner
#   jwtNoBindings     — JWT for a user with no account membership
#   jwtInvitee        — JWT for a user with binding on accountB
#   userNOBId         — User.id for jwtNoBindings
#   userINVId         — User.id for jwtInvitee
#
# Note: if you need the full authz matrix (jwtProjectAdminA1, projectA1Id, etc.),
# run tests/authz-fixtures/setup.sh instead — it covers all of the above plus more.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEWMAN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
AUTHZ_FIXTURES_DIR="$WORKSPACE_DIR/tests/authz-fixtures"

BASE_URL="${BASE_URL:-http://localhost:18080}"
IAM_INTERNAL_GRPC="${IAM_INTERNAL_GRPC:-localhost:19091}"
DEV_SECRET="${DEV_SECRET:-kacho-dev-jwt-secret-2026}"
EXP_HOURS="${EXP_HOURS:-24}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
PATCH_ENV="${PATCH_ENV:-true}"
VERBOSE="${VERBOSE:-false}"

# If full authz-fixtures output exists, use it directly (superset of what we need).
if [ -f "$AUTHZ_FIXTURES_DIR/out/authz-fixtures.json" ]; then
  echo "[crud-fixture] Full authz-fixtures/out/authz-fixtures.json found — reusing it." >&2
  echo "[crud-fixture] Patching environments/local.postman_environment.json ..." >&2
  if [ "$PATCH_ENV" = "true" ]; then
    python3 "$AUTHZ_FIXTURES_DIR/patch-env.py" \
      "$AUTHZ_FIXTURES_DIR/out/authz-fixtures.json" \
      "$NEWMAN_DIR/environments/local.postman_environment.json"
  fi
  echo "[crud-fixture] DONE — using existing authz-fixtures output." >&2
  exit 0
fi

echo "[crud-fixture] Full authz-fixtures not found — seeding minimal CRUD fixture." >&2

if ! command -v grpcurl >/dev/null 2>&1; then
  echo "[crud-fixture] FATAL: grpcurl not found in PATH." >&2
  echo "               Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

log() { echo "[crud-fixture] $*" >&2; }
vrun() { if [ "$VERBOSE" = "true" ]; then echo "+ $*" >&2; fi; "$@"; }

api() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local hdrs=(-H "Content-Type: application/json" -H "Accept: application/json")
  if [ -n "$token" ]; then hdrs+=(-H "Authorization: Bearer $token"); fi
  if [ -n "$body" ]; then
    vrun curl -sS -X "$method" "${hdrs[@]}" --data "$body" "$BASE_URL$path"
  else
    vrun curl -sS -X "$method" "${hdrs[@]}" "$BASE_URL$path"
  fi
}

poll_op() {
  local op_id="$1" token="$2"
  for _ in $(seq 1 30); do
    local r
    r=$(api GET "/operations/${op_id}" "$token")
    if echo "$r" | grep -q '"done":true'; then echo "$r"; return 0; fi
    sleep 0.3
  done
  echo "$r"
  return 1
}

# Mint JWTs using the workspace setup-jwt.py minter.
log "1/4 minting JWTs (exp=${EXP_HOURS}h)"
EXP_SECONDS=$((EXP_HOURS * 3600))
MINTER="$AUTHZ_FIXTURES_DIR/setup-jwt.py"

JWT_AAA=$(python3 "$MINTER" --secret "$DEV_SECRET" --sub "auth-test-account-admin-a@example.com" --exp-hours "$EXP_HOURS")
JWT_AAB=$(python3 "$MINTER" --secret "$DEV_SECRET" --sub "auth-test-account-admin-b@example.com" --exp-hours "$EXP_HOURS")
JWT_NOB=$(python3 "$MINTER" --secret "$DEV_SECRET" --sub "auth-test-no-bindings@example.com" --exp-hours "$EXP_HOURS")
JWT_INV=$(python3 "$MINTER" --secret "$DEV_SECRET" --sub "auth-test-invitee@example.com" --exp-hours "$EXP_HOURS")
JWT_BOOT=$(python3 "$MINTER" --secret "$DEV_SECRET" --sub "admin@prorobotech.ru" --exp-hours "$EXP_HOURS")

# Upsert users via InternalUserService (grpcurl — no REST mapping).
log "2/4 upserting owner users via grpcurl → $IAM_INTERNAL_GRPC"

upsert_user_grpc() {
  local ext_id="$1" email="$2" display="${3:-$email}"
  local body resp op_id user_id
  body=$(printf '{"externalId":"%s","email":"%s","displayName":"%s"}' "$ext_id" "$email" "$display")
  resp=$(grpcurl -plaintext -d "$body" "$IAM_INTERNAL_GRPC" \
    kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity 2>&1)
  op_id=$(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)
  if [ -n "$op_id" ]; then poll_op "$op_id" "$JWT_BOOT" >/dev/null 2>&1 || true; fi
  user_id=$(echo "$resp" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(((d.get("metadata") or {}).get("userId","")))' 2>/dev/null || true)
  if [ -z "$user_id" ]; then
    user_id=$(grpcurl -plaintext -d "{\"email\":\"$email\"}" "$IAM_INTERNAL_GRPC" \
      kacho.cloud.iam.v1.InternalIAMService/LookupSubject 2>/dev/null \
      | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("subjectId",""))' 2>/dev/null || true)
  fi
  echo "$user_id"
}

USER_BOOT=$(upsert_user_grpc "admin@prorobotech.ru"                  "admin@prorobotech.ru"                  "Bootstrap Admin")
USER_AAA=$(upsert_user_grpc "auth-test-account-admin-a@example.com" "auth-test-account-admin-a@example.com" "CRUD Owner A")
USER_AAB=$(upsert_user_grpc "auth-test-account-admin-b@example.com" "auth-test-account-admin-b@example.com" "CRUD Owner B")
USER_NOB=$(upsert_user_grpc "auth-test-no-bindings@example.com"     "auth-test-no-bindings@example.com"     "No Bindings")
USER_INV=$(upsert_user_grpc "auth-test-invitee@example.com"         "auth-test-invitee@example.com"         "Invitee")
log "    users: AAA=$USER_AAA AAB=$USER_AAB NOB=$USER_NOB INV=$USER_INV"

for _pair in "AAA:$USER_AAA" "AAB:$USER_AAB" "NOB:$USER_NOB" "INV:$USER_INV"; do
  if [ -z "${_pair#*:}" ]; then
    echo "[crud-fixture] FATAL: user ${_pair%%:*} resolved to empty id." >&2; exit 1
  fi
done

# Ensure accounts (idempotent by name).
log "3/4 ensuring accounts"

find_account_by_name() {
  local name="$1" token="$2"
  api GET "/iam/v1/accounts" "$token" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); n=[x for x in (d.get('accounts') or []) if x.get('name')=='$name']; print(n[0].get('id','') if n else '')" 2>/dev/null || true
}

ensure_account() {
  local name="$1" owner="$2" owner_token="$3"
  local found
  found=$(find_account_by_name "$name" "$owner_token")
  if [ -n "$found" ]; then echo "$found"; return; fi
  local body op op_id
  body=$(printf '{"name":"%s","description":"crud-fixture seed account"}' "$name")
  op=$(api POST "/iam/v1/accounts" "$owner_token" "$body")
  op_id=$(echo "$op" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))' 2>/dev/null)
  if [ -z "$op_id" ]; then echo "[crud-fixture] FATAL: Account.Create no id: $op" >&2; return 1; fi
  poll_op "$op_id" "$owner_token" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("metadata") or {}).get("accountId",""))'
}

ACCOUNT_A=$(ensure_account "crud-test-a" "$USER_AAA" "$JWT_AAA")
ACCOUNT_B=$(ensure_account "crud-test-b" "$USER_AAB" "$JWT_AAB")
log "    accounts: A=$ACCOUNT_A B=$ACCOUNT_B"

# Create a project in account-A so IAM-ACC-DL-NEG-HAS-CHILDREN fires correctly.
log "4/4 ensuring project in account-A for delete-with-children test"
find_project() {
  local name="$1" acct="$2" token="$3"
  api GET "/iam/v1/projects?accountId=$acct" "$token" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); n=[x for x in (d.get('projects') or []) if x.get('name')=='$name']; print(n[0].get('id','') if n else '')" 2>/dev/null || true
}

PROJECT_A=$(find_project "crud-child-prj" "$ACCOUNT_A" "$JWT_AAA")
if [ -z "$PROJECT_A" ]; then
  body=$(printf '{"accountId":"%s","name":"crud-child-prj","description":"crud-fixture has-children guard"}' "$ACCOUNT_A")
  op=$(api POST "/iam/v1/projects" "$JWT_AAA" "$body")
  op_id=$(echo "$op" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)
  if [ -n "$op_id" ]; then
    PROJECT_A=$(poll_op "$op_id" "$JWT_AAA" \
      | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("metadata") or {}).get("projectId",""))')
  fi
fi
log "    project in account-A: $PROJECT_A"

# Write fixtures JSON.
log "writing $OUT_DIR/crud-fixtures.json"
cat > "$OUT_DIR/crud-fixtures.json" <<EOF
{
  "baseUrl": "$BASE_URL",
  "jwtAccountAdminA": "$JWT_AAA",
  "jwtAccountAdminB": "$JWT_AAB",
  "jwtNoBindings": "$JWT_NOB",
  "jwtInvitee": "$JWT_INV",
  "jwtBootstrap": "$JWT_BOOT",
  "userAAAId": "$USER_AAA",
  "userAABId": "$USER_AAB",
  "userNOBId": "$USER_NOB",
  "userINVId": "$USER_INV",
  "accountAId": "$ACCOUNT_A",
  "accountBId": "$ACCOUNT_B"
}
EOF

if [ "$PATCH_ENV" = "true" ]; then
  log "    patching environments/local.postman_environment.json"
  python3 "$AUTHZ_FIXTURES_DIR/patch-env.py" \
    "$OUT_DIR/crud-fixtures.json" \
    "$NEWMAN_DIR/environments/local.postman_environment.json"
fi

log "DONE — crud fixtures saved to $OUT_DIR/crud-fixtures.json"
