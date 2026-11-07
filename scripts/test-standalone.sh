#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# Перепись и исходные потоки сохраняются до запуска Go, вне удаляемого клона.
set -uo pipefail
command -v go >/dev/null 2>&1 || {
    echo "НЕ ВЫПОЛНИЛОСЬ: инструмента нет — go не найден" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || {
    echo "НЕ ВЫПОЛНИЛОСЬ: инструмента нет — python3 не найден" >&2; exit 2; }
exec python3 "$(dirname -- "$0")/standalone-capture.py" "$@"
