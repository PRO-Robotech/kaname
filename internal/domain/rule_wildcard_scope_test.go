// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_wildcard_scope_test.go — RBAC explicit-model 2026 / issue #224.
//
// Owner role `*.*.*` bound at a BOUNDED scope (ACCOUNT/PROJECT) MUST forward-
// materialize per-object CONTENT: the wildcard rule expands to the full closed set
// of materializable object types, materialized per-object via the ARM_ANCHOR path
// (every object of those types inside the scope, narrowed by IsContainedIn). A
// wildcard rule bound at GLOBAL/CLUSTER scope MUST NOT per-object materialize — it
// is the D-9 cluster super-admin short-circuit (one flat cluster relation).
//
// Acceptance: D-3 (bounded vs GLOBAL `*.*.*`), D-8a/C-01b (owner content forward),
// D-9 (cluster short-circuit). This is the domain-layer locus of the #224 fix:
// dottedTypes previously dropped wildcard for ALL scopes, yielding 0 content.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerWildcardRules is the seeded owner role shape (migration 0035):
// [{module:"*", resources:["*"], verbs:["*"]}].
func ownerWildcardRules() Rules {
	return Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}}
}

// TestAllMaterializableTypes_CoversMirrorAndIAMDirect — the closed type set a
// wildcard rule expands to must cover every materializable type (mirror-fed +
// iam-direct), since owner is admin on EVERY object kind in the account.
func TestAllMaterializableTypes_CoversMirrorAndIAMDirect(t *testing.T) {
	got := AllMaterializableTypes()
	require.NotEmpty(t, got, "wildcard expansion set must be non-empty")

	// Sorted + deduped (deterministic selector → stable fast-path index).
	require.True(t, sort.StringsAreSorted(got), "AllMaterializableTypes must be sorted")
	seen := map[string]struct{}{}
	for _, ty := range got {
		_, dup := seen[ty]
		require.False(t, dup, "AllMaterializableTypes must be deduped: %s", ty)
		seen[ty] = struct{}{}
	}

	// Must include representative mirror-fed + iam-direct types.
	for _, want := range []string{"vpc.network", "compute.instance", "iam.project", "iam.account"} {
		_, ok := seen[want]
		assert.True(t, ok, "wildcard expansion must include %s", want)
	}
}

// TestMaterializingSelectorsInScope_WildcardBounded_ExpandsToAllTypes — issue #224
// core: a wildcard rule @ ACCOUNT scope expands to ALL materializable types as one
// ARM_ANCHOR selector (per-object content materialization), NOT empty.
func TestMaterializingSelectorsInScope_WildcardBounded_ExpandsToAllTypes(t *testing.T) {
	rs := ownerWildcardRules()

	for _, scope := range []Scope{ScopeAccount, ScopeProject} {
		sels := rs.MaterializingSelectorsInScope(scope)
		require.Len(t, sels, 1, "scope %s: one selector for the wildcard rule", scope)
		sel := sels[0]
		assert.Equal(t, ArmAnchor, sel.Arm, "wildcard `all` selector is ARM_ANCHOR")
		assert.NotEmpty(t, sel.ObjectTypes,
			"scope %s: wildcard MUST expand to per-object content types (issue #224)", scope)
		assert.ElementsMatch(t, AllMaterializableTypes(), sel.ObjectTypes,
			"scope %s: wildcard expands to the full materializable type set", scope)
		assert.ElementsMatch(t, []string{wildcard}, sel.Verbs, "verbs carried through")
	}
}

// TestMaterializingSelectorsInScope_WildcardGlobal_NoPerObject — D-9: a wildcard
// rule @ CLUSTER/GLOBAL scope must NOT per-object materialize (empty ObjectTypes);
// cluster super-admin is the flat short-circuit, not per-object content.
func TestMaterializingSelectorsInScope_WildcardGlobal_NoPerObject(t *testing.T) {
	rs := ownerWildcardRules()
	for _, scope := range []Scope{ScopeCluster, ScopeUnspecified} {
		sels := rs.MaterializingSelectorsInScope(scope)
		require.Len(t, sels, 1, "scope %s: selector still projected (empty types)", scope)
		assert.Empty(t, sels[0].ObjectTypes,
			"scope %s: GLOBAL wildcard MUST NOT per-object materialize (D-9 short-circuit)", scope)
	}
}

// TestMaterializingSelectors_RolePersistence_ExpandsWildcard — the scope-agnostic
// role-level projection (used to persist role_rule_selectors for the forward fast-
// path JOIN) expands wildcard to the full type set so a freshly-registered object
// fast-path-matches the owner binding. The per-binding scope gate (LoadBinding via
// MaterializingSelectorsInScope) still prevents a GLOBAL binding from materializing
// per-object — the role-level index is safe to expand.
func TestMaterializingSelectors_RolePersistence_ExpandsWildcard(t *testing.T) {
	rs := ownerWildcardRules()
	sels := rs.MaterializingSelectors()
	require.Len(t, sels, 1)
	assert.Equal(t, ArmAnchor, sels[0].Arm)
	assert.ElementsMatch(t, AllMaterializableTypes(), sels[0].ObjectTypes,
		"role-level persistence expands wildcard (fast-path forward index)")
}

// TestOwnerRoleSelector_MigrationLockstep — the owner role_rule_selectors row is seeded
// with HARD-CODED constants (rule_fp + object_types), RE-SEEDED as the materializable
// type set grows (iam-content types added by migration 0039; the registry namespace
// resource added by the registry owner-selector migration).
// They MUST equal the Go projection of domain.OwnerRoleRules(); if a future change to
// the owner rule or the materializable type set drifts from the SQL constant, this guard
// fails — forcing the migration to be updated in lockstep.
//
// rule_fp is UNCHANGED across every re-seed (it hashes the RULE, not object_types); only
// object_types grows. The constant below mirrors the latest re-seed migration's list.
func TestOwnerRoleSelector_MigrationLockstep(t *testing.T) {
	const migrationRuleFP = "3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4"
	migrationObjectTypes := []string{
		"compute.disk", "compute.image", "compute.instance", "compute.snapshot",
		"iam.accessBinding", "iam.account", "iam.group", "iam.project",
		"iam.role", "iam.serviceAccount", "iam.user",
		"loadbalancer.listeners", "loadbalancer.networkLoadBalancers", "loadbalancer.targetGroups",
		"registry.registries", "registry.repositories",
		"vpc.address", "vpc.gateway", "vpc.network", "vpc.networkInterface",
		"vpc.routeTable", "vpc.securityGroup", "vpc.subnet",
	}

	sels := OwnerRoleRules().MaterializingSelectors()
	require.Len(t, sels, 1, "owner role projects exactly one selector")
	assert.Equal(t, ArmAnchor, sels[0].Arm, "owner selector is ARM_ANCHOR (migration 0039 arm='anchor')")
	assert.Equal(t, migrationRuleFP, sels[0].RuleFP,
		"owner rule_fp drifted from the migration constant — update the migration in lockstep")
	assert.Equal(t, migrationObjectTypes, sels[0].ObjectTypes,
		"owner object_types drifted from migration 0039 constant — update the migration in lockstep")
}

// TestSystemWildcardRoleSelectors_MigrationLockstep — the wildcard catalog system roles
// (admin/edit/view) are seeded into role_rule_selectors by migration 0053 with HARD-CODED
// (rule_fp + object_types) constants (SQL cannot compute the Go sha256 fingerprint). They
// MUST equal the Go projection of each role's authored rule; if a future change to a
// wildcard role's verbs or to the materializable type set drifts from the SQL constant,
// this guard fails — forcing migration 0053 to be updated in lockstep (same discipline as
// TestOwnerRoleSelector_MigrationLockstep for owner).
//
//   - admin (`*.*.*`)               → rule_fp identical to owner (same rule shape).
//   - edit  (`*.*` get/list/update) → distinct rule_fp (verbs differ).
//   - view  (`*.*` read/list/get)   → distinct rule_fp.
//
// All three project the SAME anchor object_types (the full materializable set) — only
// the verbs (and thus rule_fp) differ; verbs are not stored in role_rule_selectors.
func TestSystemWildcardRoleSelectors_MigrationLockstep(t *testing.T) {
	// The full materializable type set migration 0053 hard-codes (mirror of the owner
	// selector list in TestOwnerRoleSelector_MigrationLockstep).
	migrationObjectTypes := []string{
		"compute.disk", "compute.image", "compute.instance", "compute.snapshot",
		"iam.accessBinding", "iam.account", "iam.group", "iam.project",
		"iam.role", "iam.serviceAccount", "iam.user",
		"loadbalancer.listeners", "loadbalancer.networkLoadBalancers", "loadbalancer.targetGroups",
		"registry.registries", "registry.repositories",
		"vpc.address", "vpc.gateway", "vpc.network", "vpc.networkInterface",
		"vpc.routeTable", "vpc.securityGroup", "vpc.subnet",
	}
	cases := []struct {
		name string
		rule Rule
		fp   string // migration 0053 hard-coded rule_fp
	}{
		{"admin", Rule{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}},
			"3a9a54c3276716602674c9995c9321bea53a5ae693684842a389a80ecb1c80c4"},
		{"edit", Rule{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{"get", "list", "update"}},
			"e4919459188e4b7b3786370b6c0899a79b4df159bd1988aef0b3ad23bb5aacfe"},
		{"view", Rule{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{"read", "list", "get"}},
			"fe68d56d542e8b599256b1a7eee6e31eed6db358e7254af4b5e25c7195dcf68e"},
	}
	for _, c := range cases {
		sels := Rules{c.rule}.MaterializingSelectors()
		require.Len(t, sels, 1, "%s projects exactly one selector", c.name)
		assert.Equal(t, ArmAnchor, sels[0].Arm, "%s selector is ARM_ANCHOR (migration 0053 arm='anchor')", c.name)
		assert.Equal(t, c.fp, sels[0].RuleFP,
			"%s rule_fp drifted from the migration 0053 constant — update the migration in lockstep", c.name)
		assert.Equal(t, migrationObjectTypes, sels[0].ObjectTypes,
			"%s object_types drifted from the migration 0053 constant — update the migration in lockstep", c.name)
	}
}

// TestMaterializingSelectorsInScope_NonWildcard_Unchanged — a concrete rule is
// scope-independent (its dotted types are explicit), so the scope variant returns
// the same as the role-level projection. Guards against regressing regular rules.
func TestMaterializingSelectorsInScope_NonWildcard_Unchanged(t *testing.T) {
	rs := Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}
	bounded := rs.MaterializingSelectorsInScope(ScopeProject)
	global := rs.MaterializingSelectorsInScope(ScopeCluster)
	require.Len(t, bounded, 1)
	require.Len(t, global, 1)
	assert.Equal(t, []string{"compute.instance"}, bounded[0].ObjectTypes)
	assert.Equal(t, []string{"compute.instance"}, global[0].ObjectTypes,
		"a concrete rule is scope-independent")
}
