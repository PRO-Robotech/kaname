// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func selectorFacts(t *testing.T, added, retired bool) *catalog.Facts {
	t.Helper()
	rows := seed.LiteralRows()
	rows.Modules = append(rows.Modules, "erp")
	rows.Resources = append(rows.Resources, catalog.ResourceRow{Module: "erp", Resource: "contracts", ObjectType: "custom_contract"})
	rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: "erp", Resource: "contracts", Verb: "get", PerObject: true})
	halves := catalog.Halves{Live: rows}
	if added {
		resource := catalog.ResourceRow{Module: "erp", Resource: "invoices", ObjectType: "custom_invoice"}
		if retired {
			halves.Retired.Resources = append(halves.Retired.Resources, resource)
		} else {
			halves.Live.Resources = append(halves.Live.Resources, resource)
		}
		// Глагол без живой строки ресурса не должен вернуть снятый тип.
		halves.Live.Verbs = append(halves.Live.Verbs, catalog.VerbRow{Module: "erp", Resource: "invoices", Verb: "get", PerObject: true})
	}
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	return facts
}

func TestLiveRuleSelectorsFollowCatalogAndKeepScopeAndFingerprint(t *testing.T) {
	rules := domain.Rules{{Module: "erp", Resources: []string{"*"}, Verbs: []string{"get"}}}
	policy := domain.PolicyOfRole(true, "erp")
	first, second, retired := selectorFacts(t, false, false), selectorFacts(t, true, false), selectorFacts(t, true, true)
	require.Empty(t, rules.MaterializingSelectors()[0].ObjectTypes, "прежний API не подменяет реестр живым каталогом")
	for _, test := range []struct {
		facts *catalog.Facts
		types []string
	}{
		{first, []string{"erp.contracts"}},
		{second, []string{"erp.contracts", "erp.invoices"}},
		{retired, []string{"erp.contracts"}},
	} {
		role := test.facts.MaterializingSelectors(rules)
		require.Len(t, role, 1)
		require.Equal(t, test.types, role[0].ObjectTypes)
		require.Equal(t, rules[0].Fingerprint(), role[0].RuleFP)
		require.Equal(t, domain.ArmAnchor, role[0].Arm)
		for _, scope := range []domain.Scope{domain.ScopeAccount, domain.ScopeProject} {
			require.Equal(t, role, test.facts.MaterializingSelectorsInScope(rules, scope))
		}
		for _, scope := range []domain.Scope{domain.ScopeCluster, domain.ScopeUnspecified} {
			selectors := test.facts.MaterializingSelectorsInScope(rules, scope)
			require.Len(t, selectors, 1)
			require.Empty(t, selectors[0].ObjectTypes)
			projection := test.facts.MaterializedTypeProjection(rules[0], scope)
			require.True(t, projection.WildcardSuppressed)
			require.Equal(t, domain.RuleTypeWildcardModuleResources, projection.WildcardKind)
		}
		projected, err := test.facts.ProjectGrantRules(rules, policy)
		require.NoError(t, err)
		require.Equal(t, test.types, projected.Selectors[0].ObjectTypes)
		for _, dotted := range test.types {
			require.Equal(t, []string{"get"}, projected.Selectors[0].Grants[dotted])
			require.Contains(t, projected.Verbs, domain.RoleVerb{ObjectType: dotted, Verb: "get"})
		}
		require.Empty(t, projected.Capabilities)
	}
	projection := second.MaterializedTypeProjection(rules[0], domain.ScopeProject)
	require.False(t, projection.UsesStaticRegistry())
	require.Equal(t, "erp", projection.WildcardModule)
	require.Equal(t, domain.RuleTypeWildcardModuleResources, projection.WildcardKind)
	projection.ObjectTypes[0] = "changed"
	require.Equal(t, []string{"erp.contracts", "erp.invoices"}, second.MaterializingSelectors(rules)[0].ObjectTypes)
}

func TestLiveRuleSelectorsPreserveBuiltInExclusionsAndExplicitArms(t *testing.T) {
	facts := literalFacts(t)
	wildcard := domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}}}
	require.Equal(t, wildcard.MaterializingSelectors(), facts.MaterializingSelectors(wildcard))
	policy := domain.PolicyOfRole(true, "")
	projected, err := facts.ProjectGrantRules(wildcard, policy)
	require.NoError(t, err)
	require.Equal(t, facts.GrantSelectors(wildcard.MaterializingSelectors(), policy), projected.Selectors)
	legacy := make(map[string]bool)
	for _, dotted := range domain.AllMaterializableTypes() {
		legacy[dotted] = true
	}
	for _, resource := range authzmap.CatalogSeedResources() {
		if !legacy[resource.Dotted] {
			require.NotContains(t, facts.MaterializingSelectors(wildcard)[0].ObjectTypes, resource.Dotted)
		}
	}
	explicit := domain.Rules{
		{Module: "erp", Resources: []string{"contracts"}, Verbs: []string{"get"}, ResourceNames: []string{"one"}},
		{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "one"}},
		{Module: "erp", Resources: []string{"contracts"}, Verbs: []string{"get"}, CreatedBySubject: true},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}}},
	}
	require.Equal(t, explicit.MaterializingSelectors(), facts.MaterializingSelectors(explicit))
	require.Equal(t, explicit.MaterializingSelectorsInScope(domain.ScopeCluster), facts.MaterializingSelectorsInScope(explicit, domain.ScopeCluster))
	// Новый каталог не расширяет статический допуск match_labels.
	require.False(t, domain.IsLabelSelectableType("erp.contracts"))
	require.False(t, domain.IsLabelSelectableType("registry.repositories"))
}

func TestLiveRuleSelectorsDoNotTreatContainerOnlyOrMissingFactsAsObjects(t *testing.T) {
	rows := catalog.Rows{
		Modules:   []string{"erp"},
		Resources: []catalog.ResourceRow{{Module: "erp", Resource: "contracts", ObjectType: "custom_contract"}},
		Verbs:     []catalog.VerbRow{{Module: "erp", Resource: "contracts", Verb: "create"}},
	}
	facts, err := catalog.NewFacts(catalog.Halves{Live: rows})
	require.NoError(t, err)
	rules := domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}
	require.Empty(t, facts.MaterializingSelectors(rules)[0].ObjectTypes)
	var missing *catalog.Facts
	require.Empty(t, missing.MaterializingSelectors(rules)[0].ObjectTypes)
	require.Equal(t, domain.RuleTypeWildcardAllModules, missing.MaterializedTypeProjection(rules[0], domain.ScopeProject).WildcardKind)
}

func TestLiveRegrainSelectorsPreserveBothFingerprintLayouts(t *testing.T) {
	facts := selectorFacts(t, true, false)
	rules := domain.Rules{
		{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "create"}},
		{Module: "erp", Resources: []string{"*"}, Verbs: []string{"get"}},
	}
	legacy := domain.RegrainSelectors(rules)
	live := facts.RegrainSelectors(rules)
	require.Len(t, live, len(legacy))
	require.Len(t, live, 3, "legacy mixed FP, wildcard FP и ordinary mixed FP")
	for i := range legacy {
		require.Equal(t, legacy[i].RuleFP, live[i].RuleFP)
		require.Equal(t, legacy[i].Arm, live[i].Arm)
		require.Equal(t, legacy[i].Verbs, live[i].Verbs)
	}
	require.Equal(t, []string{"erp.contracts", "erp.invoices"}, live[1].ObjectTypes)
	require.NotEqual(t, live[0].RuleFP, live[2].RuleFP)
	require.Equal(t, []string{"get"}, live[2].Verbs)
	require.Equal(t, []string{"get", "create"}, rules[0].Verbs)
}
