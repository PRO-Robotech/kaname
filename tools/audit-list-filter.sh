#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# audit-list-filter.sh — CI gate for kacho-iam's public List<Resource>: the page
# a caller receives must be narrowed to the rows that caller may see (per-object,
# `viewer ∪ v_list` asked of each object of the page), not merely to their project.
#
# This is a THIN wrapper. What is checked, and why the analysis parses the tree
# instead of searching its text, is documented on tools/listfiltergate; how this
# service is laid out is documented on services/iam/tools/auditlistfilter. Only
# the invocation lives here.
#
# Why iam was outside this gate until now. The CI step driving this class looped
# over compute, nlb, registry, storage and vpc. iam — which carries the largest
# narrowable List surface on the platform — was absent, so the blind spot sat
# exactly where the subject is densest. Wiring it in produced three findings on
# the first run. All three are excluded below, each for its own reason and each
# with a stated predicate for when the exclusion stops being true.
#
# Arguments are forwarded as-is:
#   --allow=<resource>  exclude a resource with no per-object grants to narrow
#                       to; an entry with nothing left to exclude is itself a
#                       finding.
#   --root=<dir>        audit another tree (used by the gate's own tests).

set -euo pipefail

# ── Exclusions, and why each one has a subject ────────────────────────────────
#
# `conditions` — excluded because narrowing it TODAY would hand back an empty page
# to every project-tier principal, INCLUDING the editor who created the condition.
#
# The model declares `iam_condition` with the full verb set, so per-object grants
# look expressible — but nothing ever writes one. `iam.condition` is absent from
# the reconciler's materialisable set (services/iam/internal/domain/feed_registry.go)
# and from the direct-scan specs, and Create emits only the structural project
# pointer. So `viewer`/`v_list` on a condition resolve for exactly one population:
# whoever reaches it through the `super_admin from project` cascade.
#
# That is why this is NOT the same finding as its nine siblings: the seven iam types
# that are narrowed per object are all in that materialisable set. Conditions are the
# one that is not, and the sibling assumption does not transfer.
#
# The real defect sits one layer down and is NOT a list-filter defect: a project
# editor may create a condition and then cannot read, update or delete it, because
# those RPCs are gated per object at the edge while nothing materialises the object.
# Narrowing List on top of that would remove the last thing that still worked.
# Recorded in services/iam/docs/architecture/list-filter-exclusions.md; it needs an
# owner decision, not a filter.
#
# This exclusion EXPIRES ON AN EXTERNAL FACT, not on someone remembering: the moment
# `iam.condition` becomes materialisable, the premise is gone and the filter is owed.
# That is asserted mechanically by TestConditionsExclusion_ExpiresWhenConditionsBecomeMaterialisable
# (services/iam/tools/auditlistfilter/exclusion_expiry_test.go), which FAILS while the
# exclusion is still listed here after the fact changes.
#
# ── The other two ─────────────────────────────────────────────────────────────
#
# Both are SUB-COLLECTIONS of a parent object, and neither is a grantable object
# in its own right: the authorization model declares no `sa_key` and no
# `user_token` type, so there is no per-object relation to ask about and nothing
# for a page filter to narrow to. The grant lives on the PARENT, and the edge
# gates each RPC on exactly that parent:
#
#   sa_keys      → v_list @ iam_service_account, from_request_field service_account_id
#   user_tokens  → v_list @ iam_user,            from_request_field user_id
#
# So the unit of authorization is the parent object, and it is enforced. This is
# the same shape as vpc's addresspool exclusion: a surface whose rows carry no
# individual grants.
#
# The exclusion expires by itself in the direction that matters: should either
# ever become a grantable type, the entry stays valid only until someone adds the
# filter — and the gate reports an --allow that matches no discovered resource as
# a finding, so it cannot outlive the resource either.
#
# Reasoning recorded in services/iam/docs/architecture/list-filter-exclusions.md.

SERVICE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$(dirname "$0")/../../.."

exec go run ./services/iam/tools/auditlistfilter/cmd/audit-list-filter \
  --allow=conditions --allow=sa_keys --allow=user_tokens --root="$SERVICE_ROOT" "$@"
