// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_fingerprint.go — RBAC rules-model 2026 content-hash fingerprint.
//
// Per-rule membership is keyed by rule_fp — a CONTENT-HASH of the
// rule — NOT a positional index, because a role's rules[] is mutable: reordering
// or removing a rule must NOT desync the materialized membership.
// Two rules with identical semantics (same module/resources/verbs/selector,
// any field order) hash to the SAME fp; any semantic difference yields a distinct
// fp. The fp is a stable hex digest used as a storage key (role_rule_selectors
// PK, access_binding_target_members coordinate) and a reconcile diff key.
//
// Pure domain: stdlib only (crypto/sha256 + sort), no pgx/grpc.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Fingerprint returns the content-hash of a rule (rule_fp). It is order-stable:
// the element lists and matchLabels keys are sorted before hashing, so the SAME
// rule authored in a different field order produces the SAME fp. The arm marker
// is folded in so an ARM_NAMES and an ARM_LABELS rule over the same
// modules/resources/verbs never collide.
//
// The digest covers EVERY semantic field of the rule (module, resources, verbs,
// resource_names, match_labels) so a change to any of them — including a single
// label value or one verb — yields a different fp (the reorder/remove
// invariant rests on this).
func (r Rule) Fingerprint() string {
	h := sha256.New()
	// Each section is length-prefixed + NUL-separated so distinct field groupings
	// can never alias. The module is a scalar — hashed as a
	// single-element labelled section so an fp from the prior single-element
	// modules-array form is preserved (live N=1 round-trip stable).
	writeSortedList(h, "m", []string{r.Module})
	writeSortedList(h, "r", r.Resources)
	writeSortedList(h, "v", r.Verbs)
	writeSortedList(h, "n", r.ResourceNames)
	writeSortedLabels(h, r.MatchLabels)
	return hex.EncodeToString(h.Sum(nil))
}

// writeSortedList hashes a labelled, order-normalised string list. The section
// label + element count guard against cross-section/cardinality aliasing.
func writeSortedList(h interface{ Write([]byte) (int, error) }, section string, list []string) {
	cp := append([]string(nil), list...)
	sort.Strings(cp)
	_, _ = h.Write([]byte(section + "\x00"))
	for _, e := range cp {
		_, _ = h.Write([]byte(e))
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write([]byte{1}) // section terminator
}

// writeSortedLabels hashes the matchLabels map order-independently (keys sorted).
func writeSortedLabels(h interface{ Write([]byte) (int, error) }, labels map[string]string) {
	_, _ = h.Write([]byte("l\x00"))
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(labels[k]))
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write([]byte{1})
}

// RuleLabelSelector — the reconciler-facing projection of ONE ARM_LABELS rule:
// the rule_fp it is keyed by, the dotted object types it selects (cartesian
// modules×resources), the matchLabels equality selector, and the authored verbs
// (which drive the per-object tier + v_* relations the reconciler emits — the
// tier is NOT taken from the role's compiled permissions, since ARM_LABELS rules
// are excluded from CompileRules). It carries no pgx/grpc — pure domain.
type RuleLabelSelector struct {
	RuleFP      string
	ObjectTypes []string
	MatchLabels map[string]string
	Verbs       []string
}

// LabelSelectors projects a role's rules to the ARM_LABELS selectors the
// reconciler materializes. ARM_ANCHOR / ARM_NAMES rules are excluded (they emit
// at Create-time, not via the reconciler). The dotted types are
// `{module}.<resource>` over each label rule's resources (the module is scalar —
// no module unroll; wildcards are already rejected on a label rule
// by Rule.Validate, so no `*` reaches here in a well-formed role).
//
// Retained as the ARM_LABELS-only view (back-compat). RBAC explicit-model 2026
// routes the reconciler through MaterializingSelectors (ALL arms); use that
// for the unified materializer.
func (rs Rules) LabelSelectors() []RuleLabelSelector {
	var out []RuleLabelSelector
	for _, r := range rs {
		if r.Arm() != ArmLabels {
			continue
		}
		// A well-formed ARM_LABELS rule never carries a wildcard module/resource
		// (Rule.Validate rejects `*` combined with a selector), so no expansion is
		// possible or needed here.
		types := dottedTypes(r, false)
		// Defensive copies — the selector must not alias the role's backing slices.
		ml := make(map[string]string, len(r.MatchLabels))
		for k, v := range r.MatchLabels {
			ml[k] = v
		}
		verbs := append([]string(nil), r.Verbs...)
		out = append(out, RuleLabelSelector{
			RuleFP:      r.Fingerprint(),
			ObjectTypes: types,
			MatchLabels: ml,
			Verbs:       verbs,
		})
	}
	return out
}

// RuleSelector — the UNIFIED reconciler-facing projection of ONE materializing rule
// (RBAC explicit-model 2026). It carries the arm so the reconciler picks
// the match strategy: ARM_ANCHOR(all) → every object of ObjectTypes inside scope;
// ARM_NAMES → only ResourceNames; ARM_LABELS → labels @> MatchLabels. The per-object
// FGA tuples (v_* + tier) are derived from Verbs (the tier is NOT taken from the
// role's compiled permissions — ARM_LABELS/ARM_ANCHOR-materialized rules are not in
// CompileRules). Pure domain, no pgx/grpc.
type RuleSelector struct {
	RuleFP        string
	Arm           Arm
	ObjectTypes   []string
	ResourceNames []string          // ARM_NAMES only
	MatchLabels   map[string]string // ARM_LABELS only
	Verbs         []string
}

// MaterializingSelectors projects a role's rules to the UNIFIED selector set the
// reconciler materializes — ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS.
// Binding-time scope_grant emission is removed; the reconciler is the single path.
//
// This is the SCOPE-AGNOSTIC (role-level) projection used to persist
// role_rule_selectors (the forward fast-path JOIN index): a wildcard `*.*` rule is
// EXPANDED to the full materializable type set so a freshly-registered
// object fast-path-matches an owner binding. The per-binding scope gate
// (MaterializingSelectorsInScope, consumed by the reconciler's LoadBinding) still
// prevents a GLOBAL/CLUSTER binding from per-object materializing, so
// expanding the role-level index is safe — the index over-includes, the binding
// scope narrows.
func (rs Rules) MaterializingSelectors() []RuleSelector {
	return rs.materializingSelectors(true)
}

// MaterializingSelectorsInScope is the SCOPE-AWARE projection the reconciler uses to
// compute a binding's desired membership (LoadBinding). A wildcard `*.*` rule is
// expanded to the full materializable type set ONLY for a BOUNDED scope
// (ACCOUNT/PROJECT) — per-object owner content. For a
// GLOBAL/CLUSTER scope the wildcard yields NO ObjectTypes: cluster super-admin is the
// flat short-circuit, never per-object. A non-wildcard rule is
// scope-independent (its dotted types are explicit).
func (rs Rules) MaterializingSelectorsInScope(scope Scope) []RuleSelector {
	return rs.materializingSelectors(scopeIsBounded(scope))
}

// scopeIsBounded reports whether a scope materializes wildcard content per-object
// (ACCOUNT/PROJECT). CLUSTER (+ unspecified, fail-closed) does not.
func scopeIsBounded(scope Scope) bool {
	return scope == ScopeAccount || scope == ScopeProject
}

// materializingSelectors is the shared projection. expandWildcard controls whether a
// wildcard `*.*` rule expands to the full materializable type set (true) or yields no
// ObjectTypes (false — flat short-circuit). A selector with empty ObjectTypes matches
// nothing in the reconciler (fail-closed — never a broad anchor).
func (rs Rules) materializingSelectors(expandWildcard bool) []RuleSelector {
	var out []RuleSelector
	for _, r := range rs {
		types := dottedTypes(r, expandWildcard)
		sel := RuleSelector{
			RuleFP:      r.Fingerprint(),
			Arm:         r.Arm(),
			ObjectTypes: types,
			Verbs:       append([]string(nil), r.Verbs...),
		}
		switch r.Arm() {
		case ArmNames:
			sel.ResourceNames = append([]string(nil), r.ResourceNames...)
		case ArmLabels:
			ml := make(map[string]string, len(r.MatchLabels))
			for k, v := range r.MatchLabels {
				ml[k] = v
			}
			sel.MatchLabels = ml
		}
		out = append(out, sel)
	}
	return out
}

// dottedTypes returns the `{module}.<resource>` closed-table keys a rule selects.
// A concrete rule maps each resource to `{module}.<resource>`. A wildcard rule
// (`*` module OR `*` resource) is the `*.*` superuser shape: when expandWildcard is
// true (BOUNDED scope) it expands to the full materializable type set so
// the owner becomes an explicit per-object admin on every object kind in the scope;
// when false (GLOBAL/CLUSTER) it yields NO types — that is the cluster
// super-admin short-circuit, not per-object materialization. The module is scalar
// (no module unroll).
func dottedTypes(r Rule, expandWildcard bool) []string {
	if r.Module == wildcard {
		if expandWildcard {
			return AllMaterializableTypes()
		}
		return nil
	}
	types := make([]string, 0, len(r.Resources))
	for _, res := range r.Resources {
		if res == wildcard {
			if expandWildcard {
				// `concrete.*` — every materializable type within the module.
				return materializableTypesForModule(r.Module)
			}
			continue
		}
		types = append(types, r.Module+"."+res)
	}
	return types
}

// materializableTypesForModule returns the sorted materializable types of ONE module
// (the `concrete.*` half-wildcard expansion). Used by dottedTypes for a bounded-scope
// `<module>.*` rule. Empty when the module has no materializable types (fail-closed).
func materializableTypesForModule(module string) []string {
	prefix := module + "."
	var out []string
	for _, ty := range AllMaterializableTypes() {
		if len(ty) > len(prefix) && ty[:len(prefix)] == prefix {
			out = append(out, ty)
		}
	}
	return out
}
