#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

uid=$(id -u)
gid=$(id -g)
if [[ "$uid" = 0 ]]; then
  printf '%s\n' 'Нативный RID должен выполняться от пользователя исполнителя.' >&2
  exit 1
fi

# Только systemd создаёт область с пределом ядра. Код репозитория и артефакты
# установки принадлежат прежнему пользователю исполнителя.
exec sudo -n /usr/bin/systemd-run --quiet --scope \
  --property=MemoryMax=4G --property=MemorySwapMax=0 -- \
  /usr/bin/setpriv --reuid "$uid" --regid "$gid" --init-groups -- \
  /usr/bin/env -i "HOME=$HOME" "PATH=$PATH" "USER=$(id -un)" "LOGNAME=$(id -un)" \
  "LANG=${LANG:-C.UTF-8}" "GOROOT=${GOROOT:?}" "GOTOOLCHAIN=${GOTOOLCHAIN:?}" \
  "PYTHONPATH=${PYTHONPATH:?}" "NPM_CONFIG_PREFIX=${NPM_CONFIG_PREFIX:?}" \
  PYTHONDONTWRITEBYTECODE=1 \
  "KANAME_RID_NODE_BINARY=${KANAME_RID_NODE_BINARY:?}" \
  "KANAME_RID_NEWMAN_MODULE=${KANAME_RID_NEWMAN_MODULE:?}" \
  /usr/bin/python3 .github/scripts/run-rid-native.py --require-hosted-memory-scope "$@"
