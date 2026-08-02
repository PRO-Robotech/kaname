#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# audit-list-filter.sh — CI gate for kacho-iam's listing surface: every method that
# hands a page to a caller must narrow it, and must declare HOW.
#
# This is a THIN wrapper. What is checked, and why the analysis parses the tree
# instead of searching its text, is documented on tools/listfiltergate; how this
# service is laid out is documented on services/iam/tools/auditlistfilter. Only the
# invocation lives here.
#
# Why this file is new. iam had no gate of this class at all, while having the widest
# listing surface in the repository — 30 methods. Nothing was red because the set of
# services to analyse was written by hand and iam was not in it.
#
# Arguments are forwarded as-is:
#   --root=<dir>        audit another tree (used by the gate's own tests).
#   --proto-root=<dir>  where to resolve the proto files and the authorization model.

set -euo pipefail

# The service root is resolved BEFORE changing directory, and passed explicitly:
# `go run ./services/…` has to be issued from the module root, so the default
# "audit the current directory" would otherwise audit the repository instead of this
# service. A --root given by the caller appears later on the command line and wins.
SERVICE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$(dirname "$0")/../../.."

exec go run ./services/iam/tools/auditlistfilter/cmd/audit-list-filter \
  --root="$SERVICE_ROOT" "$@"
