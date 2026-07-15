// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// tuples.go — per-object FGA tuple builder for materialized role.rules ARM_LABELS
// membership (RBAC rules-model 2026). For ONE label-matched object the
// per-object v_<verb> + back-compat tier tuples are derived from the producing
// RULE's verbs (domain.ResolveVerbsAndTier), so the reconciler can emit/eager-
// revoke the tuple of a single member on a diff.
//
// This is a use-case-layer concern (it owns the authzmap dependency), keeping the
// domain pure.

import (
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ruleObjectTuples builds the per-object FGA tuple set for ONE label-matched
// object of an ARM_LABELS rule. It REUSES the per-object
// emit semantics (access_binding.emitNamesRule): the tier + closed per-verb v_*
// relations are derived from the RULE'S VERBS (domain.ResolveVerbsAndTier), NOT
// from the role's compiled permissions (ARM_LABELS rules are excluded from
// CompileRules). v_<verb> tuples are emitted ONLY when (a) the FGA type
// carries v_* relations (TypeHasVerbRelations) AND (b) the verb is in the closed
// CRUD set; otherwise access is carried by the back-compat tier tuple. ok=false
// when the (objectType) has no FGA object type (a typo'd type never grants —
// fail-closed). The subject is the binding's subject (already FGA-formatted).
func ruleObjectTuples(subject string, verbs []string, objectType, objectID string) ([]domain.MembershipTuple, bool) {
	fgaType, ok := fgaObjectType(objectType)
	if !ok {
		return nil, false
	}
	expanded, tier := domain.ResolveVerbsAndTier(verbs)
	object := fmt.Sprintf("%s:%s", fgaType, objectID)
	emitVerbs := authzmap.TypeHasVerbRelations(fgaType)

	seen := map[domain.MembershipTuple]struct{}{}
	var out []domain.MembershipTuple
	add := func(relation string) {
		t := domain.MembershipTuple{User: subject, Relation: relation, Object: object}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if emitVerbs {
		for _, v := range expanded {
			if !domain.IsClosedVerb(v) {
				continue
			}
			add("v_" + v)
		}
	}
	// Back-compat tier tuple — carries domain-verb access + keeps tier-based Check
	// call-sites working. Always emitted (parity with B emitNamesRule).
	add(tier)
	return out, true
}

// scopeSelfRuleFP — the sentinel rule_fp attributing the scope-self member (D-7).
// It is NOT a content rule's fingerprint; using a fixed, NUL-free sentinel gives the
// scope-self member its own access_binding_target_members row + emitted-tuple ledger
// lineage so the symmetric revoke / diff treats it independently of content members.
const scopeSelfRuleFP = "scope_self"

// scopeSelfMember builds the DesiredMember for the binding's scope anchor itself
// (D-7 / КФ-3 / C-01) from the role's scope-self verbs. The member object_type is
// the dotted iam scope key (iam.account / iam.project) so it round-trips through
// fgaObjectType for the symmetric revoke; the FGA tuples target the bare scope
// object (account:<X>/project:<X>). ok=false when the role grants nothing on the
// scope self OR the scope type has no dotted iam mapping (cluster — D-9 short-circuit
// owns cluster super-admin, not this per-object path).
func scopeSelfMember(subject string, scopeType, scopeID string, verbs []string) (DesiredMember, bool) {
	dotted := "iam." + scopeType // iam.account / iam.project (cluster has no mapping)
	if _, ok := fgaObjectType(dotted); !ok {
		return DesiredMember{}, false
	}
	tuples, ok := scopeSelfTuples(subject, scopeType, scopeID, verbs)
	if !ok {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP:     scopeSelfRuleFP,
		ObjectType: dotted,
		ObjectID:   scopeID,
		Status:     domain.VerificationActive,
		Tuples:     tuples,
	}, true
}

// scopeSelfTuples builds the FGA tuple set materialized ON THE BINDING'S OWN SCOPE
// OBJECT (`account:<X>`/`project:<X>`) from the role's scope-self verbs
// (RBAC explicit-model 2026 P4 / D-7 / КФ-3 / C-01). It is the unified-reconciler
// equivalent of the removed binding-time scope-anchor/scope_grant emit: the tier
// (back-compat) tuple is the write-authz anchor / no-access-loss anchor, plus the
// closed v_* set when the scope type is verb-bearing (account/project, #218).
//
// Only the verb-bearing hierarchy scopes account/project materialize a per-object
// scope-self member. cluster is DELIBERATELY excluded: cluster super-admin is served
// by the D-9 flat short-circuit (cluster:cluster_kacho_root#system_admin), NOT a
// per-object tuple — materializing per-object on cluster is the Q-2/D-9 anti-pattern.
// The sole caller (scopeSelfMember) already gates cluster out (fgaObjectType
// "iam.cluster" is absent from the objectTypes registry), so this function never
// receives scopeType=="cluster"; the guard below is the explicit fail-closed fence
// (scope_self_cluster_guard_test.go pins the invariant against a future iam.cluster
// type re-enabling the dead path). ok=false when scopeType is not a per-object
// hierarchy scope or there are no verbs (a content-only role grants nothing on the
// anchor).
func scopeSelfTuples(subject, scopeType, scopeID string, verbs []string) ([]domain.MembershipTuple, bool) {
	if scopeID == "" || len(verbs) == 0 {
		return nil, false
	}
	switch scopeType {
	case "account", "project":
		// per-object verb-bearing hierarchy scopes — materialized below.
	default:
		// cluster (D-9 short-circuit owns it) + any non-hierarchy scope → no member.
		return nil, false
	}
	_, tier := domain.ResolveVerbsAndTier(verbs)
	object := scopeType + ":" + scopeID
	emitVerbs := authzmap.TypeHasVerbRelations(scopeType)

	seen := map[domain.MembershipTuple]struct{}{}
	var out []domain.MembershipTuple
	add := func(relation string) {
		t := domain.MembershipTuple{User: subject, Relation: relation, Object: object}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if emitVerbs {
		for _, v := range verbs {
			if !domain.IsClosedVerb(v) {
				continue
			}
			add("v_" + v)
		}
	}
	// Back-compat tier tuple — the write-authz / no-access-loss anchor (account/project).
	add(tier)
	return out, true
}

// fgaObjectType resolves the FGA object_type for a dotted closed-table key
// (e.g. "compute.instance" → "compute_instance"). Thin alias over the canonical
// authzmap.FGAObjectType so the reconciler's tuple-object derivation and the
// verify-gate's ledger lookup (review #5) share ONE mapping and cannot drift.
func fgaObjectType(objectType string) (string, bool) {
	return authzmap.FGAObjectType(objectType)
}
