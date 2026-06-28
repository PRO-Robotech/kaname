#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# scripts/wave-a-audit.sh — count Phase + KAC + W refs in kacho-iam (Wave A acceptance gate).
# Excludes: verifies-KAC-N annotations (workspace §13 finding pattern), migration filenames (Wave M), commits.

set -euo pipefail
cd "$(dirname "$0")/.."

print_kind() {
  local label="$1"; shift
  local count
  count=$(grep -rln "$@" --include='*.go' --include='*.py' --include='*.sql' internal/ cmd/ tests/newman/cases/ 2>/dev/null | wc -l)
  printf '%-40s %5d\n' "$label" "$count"
}

print_kind "Phase \\d (markers in code)"                  -E 'Phase [0-9]'
print_kind "\\bE[0-9]\\b (markers)"                       -E '\bE[0-9]\b'
print_kind "\\bW[0-9]\\.[0-9]\\b (Wave markers)"          -E '\bW[0-9]\.[0-9]\b'
print_kind "KAC-N total"                                  -E 'KAC-[0-9]'
print_kind "KAC-N legitimate (// verifies / # verifies)"  -E '(//|#) *verifies.*KAC-[0-9]'

echo
echo "Wave A goal: first 3 metrics ≤ 0; last (verifies-KAC) ≤ 10."
