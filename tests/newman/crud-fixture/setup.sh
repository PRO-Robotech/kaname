#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

# tests/newman/crud-fixture/setup.sh — CRUD fixture for the iam-account newman suite.
#
# Exports (via environments/local.postman_environment.json):
#   jwtAccountAdminA / jwtAccountAdminB / jwtNoBindings / jwtInvitee / jwtBootstrap,
#   userAAAId / userAABId / userNOBId / userINVId, accountAId / accountBId.
# Every one of them is a strict subset of what tests/authz-fixtures/setup.sh produces —
# that was already written in this file's own header before the change below.
#
# ЭТОТ ФАЙЛ БОЛЬШЕ НЕ ЧЕКАНИТ ТОКЕНЫ. Раньше он был «минимальной альтернативой»
# общему посеву и подписывал свои Bearer'ы САМ — HS256 общим ключом, лежавшим тут же
# в дереве. Посадочного гейта у него при этом не было вовсе: на любом стенде, который
# сегодня разворачивается, край принимает только Hydra-RS256 (и отказывается
# стартовать, если общий ключ до него доезжает), поэтому набор состоял из инертных
# токенов — а записывался и патчился молча, как удачный. Отказ всплывал позже, на
# первом же кейсе, и читался как дефект продукта.
#
# Альтернативы больше нет: посадку опознаёт ОДИН вход — tests/authz-fixtures/setup.sh —
# и он отдаёт выдачу iam. Здесь осталось то, ради чего файл существует: получить набор
# и пропатчить им окружение сьюты.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEWMAN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
AUTHZ_FIXTURES_DIR="$WORKSPACE_DIR/tests/authz-fixtures"

PATCH_ENV="${PATCH_ENV:-true}"

patch_from_authz_fixtures() {
  if [ "$PATCH_ENV" != "true" ]; then
    echo "[crud-fixture] PATCH_ENV != true — окружение сьюты не трогаем." >&2
    return 0
  fi
  echo "[crud-fixture] Patching environments/local.postman_environment.json ..." >&2
  python3 "$AUTHZ_FIXTURES_DIR/patch-env.py" \
    "$AUTHZ_FIXTURES_DIR/out/authz-fixtures.json" \
    "$NEWMAN_DIR/environments/local.postman_environment.json"
}

if [ -f "$AUTHZ_FIXTURES_DIR/out/authz-fixtures.json" ]; then
  echo "[crud-fixture] Full authz-fixtures/out/authz-fixtures.json found — reusing it." >&2
  patch_from_authz_fixtures
  echo "[crud-fixture] DONE — using existing authz-fixtures output." >&2
  exit 0
fi

echo "[crud-fixture] No authz-fixtures output yet — running the single entrance." >&2
bash "$AUTHZ_FIXTURES_DIR/setup.sh"

# Отсутствие набора ПОСЛЕ успешного посева — отдельный исход, а не повод продолжать:
# дальше стоит патч окружения, и он молча записал бы сьюте пустые значения.
if [ ! -f "$AUTHZ_FIXTURES_DIR/out/authz-fixtures.json" ]; then
  echo "[crud-fixture] FATAL: посев завершился, но out/authz-fixtures.json не создан." >&2
  echo "               Патчить окружение нечем; продолжать — значит отдать сьюте пустые токены." >&2
  exit 1
fi

patch_from_authz_fixtures
echo "[crud-fixture] DONE — fixtures obtained through tests/authz-fixtures/setup.sh." >&2
