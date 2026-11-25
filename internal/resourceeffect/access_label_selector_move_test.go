// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelSelectorMoveComparesEffectiveObjectGrants(t *testing.T) {
	facts := objectFacts(t, false)
	binding := objectBinding()
	before := domain.Rules{{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}
	after, err := before.MoveAccessLabelSelectors(
		[]domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: before[0].Fingerprint()}},
		binding.Policy, domain.ModuleSetOf("iam"),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		name                string
		labels, access      map[string]string
		beforeHas, afterHas bool
	}{
		{"права сохраняются", map[string]string{"team": "red"}, map[string]string{"team": "red"}, true, true},
		{"отзыв при несовпадении защищённой метки", map[string]string{"team": "red"}, map[string]string{"team": "blue"}, true, false},
		{"выдача при несовпадении обычной метки", map[string]string{"team": "blue"}, map[string]string{"team": "red"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := capturedObject("iam.project", "p")
			obj.Labels, obj.AccessLabels = tc.labels, tc.access
			binding.Selectors = before.MaterializingSelectorsInScope(domain.ScopeAccount)
			previous := objectDesired(t, facts, binding, obj)
			binding.Selectors = after.MaterializingSelectorsInScope(domain.ScopeAccount)
			current := objectDesired(t, facts, binding, obj)
			require.Equal(t, tc.beforeHas, len(previous) > 0)
			require.Equal(t, tc.afterHas, len(current) > 0)
			if tc.beforeHas && tc.afterHas {
				require.Len(t, previous, 1)
				require.Len(t, current, 1)
				require.NotEqual(t, previous[0].RuleFP, current[0].RuleFP)
				require.NotEmpty(t, previous[0].Tuples)
				require.Equal(t, previous[0].Tuples, current[0].Tuples)
			}
		})
	}
}

func TestAccessLabelSelectorMoveRevokesScopeSelfWhenBothSelectorsMiss(t *testing.T) {
	facts := objectFacts(t, false)
	binding := objectBinding()
	before := domain.Rules{{
		Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}
	after, err := before.MoveAccessLabelSelectors(
		[]domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: before[0].Fingerprint()}},
		binding.Policy, facts,
	)
	require.NoError(t, err)

	account := capturedObject("iam.account", binding.Scope.ID)
	account.Labels = map[string]string{"team": "blue"}
	account.AccessLabels = map[string]string{"team": "blue"}

	binding.Selectors = before.MaterializingSelectorsInScope(domain.ScopeAccount)
	binding.ScopeSelfVerbs = before.ScopeSelfVerbs(binding.Scope.Type, facts.VerbsOfType(binding.Scope.Type))
	previous := objectDesired(t, facts, binding, account)
	require.Len(t, previous, 1)
	require.Equal(t, "scope_self", previous[0].Derivation)
	require.Equal(t, "scope_self", previous[0].RuleFP)
	require.Equal(t, domain.VerificationActive, previous[0].Status)
	require.ElementsMatch(t, []domain.MembershipTuple{
		{User: "user:u", Relation: "v_get", Object: "account:a"},
		{User: "user:u", Relation: "viewer", Object: "account:a"},
	}, previous[0].Tuples)

	binding.Selectors = after.MaterializingSelectorsInScope(domain.ScopeAccount)
	binding.ScopeSelfVerbs = after.ScopeSelfVerbs(binding.Scope.Type, facts.VerbsOfType(binding.Scope.Type))
	require.Empty(t, objectDesired(t, facts, binding, account))
}

func TestAccessLabelSelectorMoveChangesRepositoryGrantsThroughRegistry(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam", "registry"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "project", ObjectType: "project"},
			{Module: "registry", Resource: "registries", ObjectType: "registry_registry", ParentTypes: []string{"project"}, ParentNames: []string{"project"}, PublicReadToChildren: true},
			{Module: "registry", Resource: "repositories", ObjectType: "registry_repository", ParentTypes: []string{"registry_registry"}, ParentNames: []string{"parent"}},
		},
		Verbs: []catalog.VerbRow{
			{Module: "registry", Resource: "registries", Verb: "get", PerObject: true},
			{Module: "registry", Resource: "repositories", Verb: "get", PerObject: true},
		},
	}})
	require.NoError(t, err)

	before := domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
		Children:    []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}},
	}}
	binding := objectBinding()
	binding.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "r"}}}
	after, err := before.MoveAccessLabelSelectors(
		[]domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: before[0].Fingerprint()}},
		binding.Policy, facts,
	)
	require.NoError(t, err)
	require.Equal(t, before[0].Children, after[0].Children)

	oldSelectors := before.MaterializingSelectorsInScope(domain.ScopeAccount)
	newSelectors := after.MaterializingSelectorsInScope(domain.ScopeAccount)
	require.Len(t, oldSelectors, 2)
	require.Len(t, newSelectors, 2)
	require.NotEqual(t, oldSelectors[1].RuleFP, newSelectors[1].RuleFP)

	for _, tc := range []struct {
		name, labels, access, registryID, accountID string
		hadGrant, hasGrant                          bool
	}{
		{"оба селектора совпадают", "red", "red", "r", "a", true, true},
		{"перенос отзывает доступ", "red", "blue", "r", "a", true, false},
		{"перенос выдаёт доступ", "blue", "red", "r", "a", false, true},
		{"предок вне конечной цели", "red", "red", "other", "a", false, false},
		{"предок вне области", "red", "red", "r", "other", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := capturedObject("registry.registries", tc.registryID)
			registry.Labels = map[string]string{"team": tc.labels}
			registry.AccessLabels = map[string]string{"team": tc.access}
			registry.ParentAccountIDs = []string{tc.accountID}
			repository := capturedObject("registry.repositories", "repo")
			repository.ParentAccountIDs = registry.ParentAccountIDs
			want := []domain.MembershipTuple{
				{User: "user:u", Relation: "v_get", Object: "registry_repository:repo"},
				{User: "user:u", Relation: "viewer", Object: "registry_repository:repo"},
			}
			for _, version := range []struct {
				selectors []domain.RuleSelector
				hasGrant  bool
			}{
				{oldSelectors, tc.hadGrant},
				{newSelectors, tc.hasGrant},
			} {
				binding.Selectors = version.selectors
				got := objectDesired(t, facts, binding, repository, registry)
				if !version.hasGrant {
					require.Empty(t, got)
					continue
				}
				require.Len(t, got, 1)
				require.Equal(t, "nested", got[0].Derivation)
				require.Equal(t, version.selectors[1].RuleFP, got[0].RuleFP)
				require.Equal(t, domain.VerificationActive, got[0].Status)
				require.ElementsMatch(t, want, got[0].Tuples)
			}
		})
	}
}
