// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_verbs.go — per-rule verb expansion + back-compat
// tier derivation. Pure domain (stdlib only) so BOTH the arm-emit path
// (access_binding.scope_grant_tuples) and the reconciler
// (reconcile.ruleObjectTuples) derive the SAME per-object verbs+tier from a rule.
// Both paths call THESE functions directly (no duplicated, drift-prone copies), so
// parity between them is guaranteed by the compiler, not a self-test.

import "strings"

// ClosedVerbs — the closed per-verb set the FGA model materializes as `v_*`
// relations. A rule's verb `*` expands to exactly this set (O-3: bounded, never an
// open `*`-relation). Order is fixed for deterministic emission.
var ClosedVerbs = []string{"get", "list", "create", "update", "delete"}

var closedVerbIndex = func() map[string]struct{} {
	m := make(map[string]struct{}, len(ClosedVerbs))
	for _, v := range ClosedVerbs {
		m[v] = struct{}{}
	}
	return m
}()

// IsClosedVerb reports whether verb is in the closed CRUD set the FGA model
// materializes as a `v_<verb>` relation. A domain verb (start/stop/move/…) is NOT
// closed — it carries access via the back-compat tier tuple, not a `v_<verb>`.
func IsClosedVerb(verb string) bool {
	_, ok := closedVerbIndex[strings.ToLower(verb)]
	return ok
}

// ResolveVerbsAndTier expands a rule's authored verbs (verb `*` → ClosedVerbs) and
// derives the per-RULE back-compat tier (strongest verb-class among the rule's
// verbs), mapped the SAME way the consumer authz-gate resolves an action:
// get/list → viewer ; create/update (+ domain mutations) → editor ; delete → admin.
// Per-RULE, never whole-role (B-11). The tier tuple keeps tier-based Check
// call-sites working; the v_* tuples carry the precise per-verb enforcement.
func ResolveVerbsAndTier(authored []string) (verbs []string, tier string) {
	expanded := authored
	for _, v := range authored {
		if v == "*" {
			expanded = ClosedVerbs
			break
		}
	}
	hasEditor, hasAdmin := false, false
	for _, v := range expanded {
		switch verbBackCompatTier(v) {
		case "admin":
			hasAdmin = true
		case "editor":
			hasEditor = true
		}
	}
	switch {
	case hasAdmin:
		tier = "admin"
	case hasEditor:
		tier = "editor"
	default:
		tier = "viewer"
	}
	return expanded, tier
}

// ScopeSelfVerbs returns the UNION of authored verbs the role's rules grant on the
// binding's OWN scope resource-type — i.e. on the scope object itself
// (`account:<X>`/`project:<X>`/`cluster:<X>`). RBAC explicit-model 2026 P4 (D-7 /
// КФ-3 / C-01): a rules-role bound on a scope must materialize its tier (+ verb-
// bearing v_*) ON THE SCOPE ANCHOR ITSELF — the write-authz anchor / self-access
// that the removed binding-time scope_grant/anchor emit produced. The reconciler is
// now the SINGLE materialization path, so this projection feeds a scope-self
// desired member (reconcile.desiredRuleMembers), NOT a binding-time emit.
//
// A rule contributes its verbs when EITHER its (module,resource) is the FULL `*.*`
// wildcard (the system superuser shape — migration 0031: admin/edit/view) OR its
// (module,resource) is exactly ("iam", scopeResource) — e.g. an `iam.account` rule
// on an account-scoped binding. scopeResource is the scope's resource type:
// "account"|"project". (cluster has no per-resource iam rule; only the `*.*`
// superuser shape grants cluster-self — handled by the wildcard branch.)
//
// Returns nil when no rule applies to the scope self (a content-only role —
// e.g. `compute.instance` rules — grants nothing ON the account/project object,
// only on its content; the scope-self member is then absent, fail-closed).
func (rs Rules) ScopeSelfVerbs(scopeResource string) []string {
	var collected []string
	matched := false
	for _, r := range rs {
		applies := false
		if r.Module == wildcard {
			// FULL `*.*` superuser shape; a half-wildcard (`*.concrete`/`concrete.*`)
			// is not a real seed shape and never grants scope-self (fail-closed).
			for _, res := range r.Resources {
				if res == wildcard {
					applies = true
					break
				}
			}
		} else if r.Module == "iam" && scopeResource != "" {
			for _, res := range r.Resources {
				if res == scopeResource {
					applies = true
					break
				}
			}
		}
		if !applies {
			continue
		}
		matched = true
		collected = append(collected, r.Verbs...)
	}
	if !matched {
		return nil
	}
	verbs, _ := ResolveVerbsAndTier(collected)
	return verbs
}

// verbBackCompatTier maps a rule verb to the tier the consumer authz-gate resolves
// it to (resolveActionToRelation parity): get/list → viewer, delete → admin, else
// editor (create/update/domain mutations). ONLY for the back-compat tier tuple;
// the v_* tuples carry the precise per-verb enforcement. delete→admin (NOT editor)
// keeps Check(delete)→admin allowed for a rule granting delete.
//
// The read-style domain verbs getTargetStates / listOperations resolve to VIEWER —
// in lockstep with authzmap.verbClass and the consumer resolveActionToRelation map
// (authorize_service.go), which both classify them as read-tier. Keeping all three
// aligned is the tier-parity invariant (F-53): a rules-role must emit the SAME tier
// the legacy permissions did, never a stronger one (no escalation). Without this,
// the nlb loadbalancer.operator / target_manager roles would emit editor on
// listeners/targetGroups where legacy emitted viewer.
func verbBackCompatTier(verb string) string {
	switch strings.ToLower(verb) {
	case "get", "list", "view", "watch", "describe", "read",
		"gettargetstates", "listoperations":
		return "viewer"
	case "delete":
		return "admin"
	default:
		return "editor"
	}
}
