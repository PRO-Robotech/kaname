// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGrantSelectorLayoutPreservesLegacyFPAndUsesActualResidual(t *testing.T) {
	rules := Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "create"}}}
	raw := rules.MaterializingSelectors()
	ordinary, caps, e := SplitGrantCapabilityRules(rules)
	require.NoError(t, e)
	require.Len(t, caps, 1)
	residual := ordinary.MaterializingSelectors()
	require.NotEqual(t, raw[0].RuleFP, residual[0].RuleFP)
	legacy := RulesForStoredSelectorLayout(rules, []string{raw[0].RuleFP})
	require.Equal(t, raw[0].RuleFP, legacy.MaterializingSelectors()[0].RuleFP)
	current := RulesForStoredSelectorLayout(rules, []string{residual[0].RuleFP})
	require.Equal(t, residual[0].RuleFP, current.MaterializingSelectors()[0].RuleFP)
	require.NotContains(t, current[0].Verbs, "create")
	regrain := RegrainSelectors(rules)
	require.Len(t, regrain, 2)
	require.Equal(t, raw[0].RuleFP, regrain[0].RuleFP)
	require.Equal(t, residual[0].RuleFP, regrain[1].RuleFP)
	// Нет caller version/bool и нет переписывания авторского оригинала.
	require.Equal(t, []string{"get", "create"}, rules[0].Verbs)
}
func TestUnregistrationNarrowsOrdinaryButNeverUsesMirrorAsRoleReference(t *testing.T) {
	rules := Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "bind"}, ResourceNames: []string{"rol_first", "rol_last"}}}
	narrowed, _, changed := rules.WithoutOrdinaryResourceName("iam.role", "rol_last")
	require.True(t, changed)
	ordinary, caps, e := SplitGrantCapabilityRules(narrowed)
	require.NoError(t, e)
	require.Len(t, caps, 2)
	require.Len(t, ordinary, 1)
	require.Equal(t, []string{"rol_first"}, ordinary[0].ResourceNames)
	pure := Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol_last"}}}
	same, _, changed := pure.WithoutOrdinaryResourceName("iam.role", "rol_last")
	require.False(t, changed)
	require.Equal(t, pure, same)
}

// kaname#1034: лимит проверяется над всей ролью, а не над одним правилом.
func TestUnregistrationGlobalRuleLimitOrdinaryMixedAndUnderBudget(t *testing.T) {
	for _, tc := range []struct {
		name             string
		count            int
		meta             bool
		want             int
		otherRemovedName bool
	}{
		{"ordinary64", MaxRules, false, MaxRules, false},
		{"mixed64", MaxRules, true, MaxRules, false},
		{"underbudget", 2, true, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := Rules{{Module: "iam", Resources: []string{"account", "project"}, Verbs: []string{"get"}, ResourceNames: []string{"removed", "kept"}}}
			for len(rules) < tc.count {
				rules = append(rules, Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
			}
			if tc.meta {
				rules[len(rules)-1] = Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol_target"}}
			}
			require.NoError(t, rules.Validate(TenantPolicy(), ModuleSetOf("iam")))
			_, err := CompileRules(rules)
			require.NoError(t, err)
			narrowed, _, changed := rules.WithoutOrdinaryResourceName("iam.account", "removed")
			require.True(t, changed)
			require.Len(t, narrowed, tc.want)
			require.LessOrEqual(t, len(narrowed), MaxRules)
			require.NoError(t, narrowed.Validate(TenantPolicy(), ModuleSetOf("iam")))
			ordinary, caps, err := SplitGrantCapabilityRules(narrowed)
			require.NoError(t, err)
			perms, err := CompileRules(ordinary)
			require.NoError(t, err)
			require.NotContains(t, perms, Permission("iam.account.removed.get"))
			require.Contains(t, perms, Permission("iam.account.kept.get"))
			require.Contains(t, perms, Permission("iam.project.kept.get"))
			require.Equal(t, tc.otherRemovedName, containsPermissionForUnregister(perms, "iam.project.removed.get"))
			if tc.meta {
				_, before, err := SplitGrantCapabilityRules(rules)
				require.NoError(t, err)
				require.Equal(t, before, caps)
			} else {
				require.Empty(t, caps)
			}
			require.Equal(t, []string{"removed", "kept"}, rules[0].ResourceNames)
		})
	}
}

func containsPermissionForUnregister(perms Permissions, permission Permission) bool {
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}
