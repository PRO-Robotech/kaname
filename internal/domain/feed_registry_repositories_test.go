// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// feed_registry_repositories_test.go — registry.repositories is MATERIALIZABLE but
// NOT label-selectable (decoupling of the two sets).
//
// registry_repository — per-repo authz object materialized on docker push. It has
// no own-table labels (source of truth = zot), so a match_labels selector is
// inapplicable → label-selectable = false. But it MUST be materializable: a
// bounded-scope owner (`*.*`) or a `registry.*` grant has to expand onto the repo,
// otherwise the owner-tuple never reaches registry_repository and images are
// unreachable even for the owner. The two sets are therefore distinct — materializable
// is a strict superset of label-selectable, differing by exactly registry.repositories.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistryRepositories_Materializable — registry.repositories is in the closed
// materializable set (so the reconciler can materialize per-object v_* on it).
func TestRegistryRepositories_Materializable(t *testing.T) {
	seen := map[string]struct{}{}
	for _, ty := range AllMaterializableTypes() {
		seen[ty] = struct{}{}
	}
	_, ok := seen["registry.repositories"]
	assert.True(t, ok,
		"registry.repositories must be materializable (owner/wildcard grant must reach the repo)")
	// registry.registries stays materializable too (regression guard).
	_, ok = seen["registry.registries"]
	assert.True(t, ok, "registry.registries must stay materializable")
}

// TestRegistryRepositories_NotLabelSelectable — registry.repositories is NOT
// label-selectable (no own-table labels), while registry.registries stays
// label-selectable. IsLabelSelectableType consults ONLY the label-selectable set.
func TestRegistryRepositories_NotLabelSelectable(t *testing.T) {
	assert.False(t, IsLabelSelectableType("registry.repositories"),
		"registry.repositories must NOT be label-selectable (no own-table labels)")
	assert.True(t, IsLabelSelectableType("registry.registries"),
		"registry.registries must stay label-selectable (own-table labels drive authz scope)")
}

// TestRegistryStar_ExpandsToRepositories — a bounded `registry.*` rule expands to
// BOTH registry namespace types (registries + repositories) via the concrete-module
// half-wildcard path, so a project/account owner granted `registry.*` reaches repos.
func TestRegistryStar_ExpandsToRepositories(t *testing.T) {
	got := materializableTypesForModule("registry")
	assert.Contains(t, got, "registry.repositories",
		"`registry.*` must expand onto registry.repositories")
	assert.Contains(t, got, "registry.registries",
		"`registry.*` must expand onto registry.registries")
}

// TestWildcardBounded_ExpandsToRepositories — the owner `*.*` rule bound at a BOUNDED
// scope (ACCOUNT/PROJECT) forward-materializes onto registry.repositories (the
// per-object owner content path now covers repos).
func TestWildcardBounded_ExpandsToRepositories(t *testing.T) {
	rs := Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}}
	for _, scope := range []Scope{ScopeAccount, ScopeProject} {
		sels := rs.MaterializingSelectorsInScope(scope)
		require.Len(t, sels, 1, "scope %s: one wildcard selector", scope)
		assert.Contains(t, sels[0].ObjectTypes, "registry.repositories",
			"scope %s: bounded `*.*` owner must expand onto registry.repositories", scope)
	}
}

// TestMaterializable_IsLabelSelectablePlusRepositories — the materializable set is
// EXACTLY labelSelectableTypes ∪ {registry.repositories}: every label-selectable
// type is materializable, and the ONLY additional materializable type is
// registry.repositories (the two sets are decoupled by exactly this one entry).
func TestMaterializable_IsLabelSelectablePlusRepositories(t *testing.T) {
	mat := map[string]struct{}{}
	for _, ty := range AllMaterializableTypes() {
		mat[ty] = struct{}{}
	}
	// Every label-selectable type is materializable.
	for ty := range labelSelectableTypes {
		_, ok := mat[ty]
		assert.True(t, ok, "label-selectable %s must be materializable", ty)
	}
	// The materializable set has exactly one extra element over label-selectable.
	assert.Equal(t, len(labelSelectableTypes)+1, len(mat),
		"materializable = labelSelectable ∪ {registry.repositories} (exactly one extra)")
	// And that extra element is registry.repositories, which is NOT label-selectable.
	_, matHasRepo := mat["registry.repositories"]
	assert.True(t, matHasRepo, "registry.repositories must be the extra materializable type")
	assert.False(t, IsLabelSelectableType("registry.repositories"),
		"the extra materializable type must not be label-selectable")
}
