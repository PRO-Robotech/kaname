// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestMoveAccessLabelSelectorsKeepsSelectedParentAndChildCoordinates(t *testing.T) {
	before := domain.Rules{
		{
			Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"company": "a"},
			Children: []domain.Rule{{
				Resources: []string{"project"}, Verbs: []string{"get", "list"},
				MatchLabels: map[string]string{"team": "a"},
			}},
		},
		{Module: "iam", Resources: []string{"project"}, Verbs: []string{"update"}, MatchLabels: map[string]string{"team": "b"}},
	}
	original := before[0].Fingerprint()
	child := 0
	got, err := before.MoveAccessLabelSelectors([]domain.AccessLabelSelectorMove{
		{RuleIndex: 0, ChildIndex: &child, Fingerprint: before[0].Children[child].Fingerprint()},
		{RuleIndex: 0, Fingerprint: original},
	}, domain.TenantPolicy(), domain.ModuleSetOf("iam"))
	require.NoError(t, err)
	require.Equal(t, domain.Rules{
		{
			Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
			MatchAccessLabels: map[string]string{"company": "a"},
			Children: []domain.Rule{{
				Resources: []string{"project"}, Verbs: []string{"get", "list"},
				MatchAccessLabels: map[string]string{"team": "a"},
			}},
		},
		before[1],
	}, got)
	require.Equal(t, original, before[0].Fingerprint())

	got[0].Children[child].MatchAccessLabels["team"] = "other"
	got[1].Verbs[0] = "get"
	require.Equal(t, "a", before[0].Children[child].MatchLabels["team"])
	require.Equal(t, []string{"update"}, before[1].Verbs)
}

func TestMoveAccessLabelSelectorsRejectsStaleOrInvalidSelection(t *testing.T) {
	label := domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}
	plain := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}
	rules := domain.Rules{label, plain}
	pos := domain.AccessLabelSelectorMove{RuleIndex: 0, Fingerprint: label.Fingerprint()}
	missingChild := 0
	for _, tc := range []struct {
		name  string
		moves []domain.AccessLabelSelectorMove
	}{
		{"empty", nil},
		{"duplicate", []domain.AccessLabelSelectorMove{pos, pos}},
		{"stale", []domain.AccessLabelSelectorMove{{RuleIndex: 0, Fingerprint: plain.Fingerprint()}}},
		{"stale after valid selection", []domain.AccessLabelSelectorMove{pos, {RuleIndex: 1, Fingerprint: label.Fingerprint()}}},
		{"no selector", []domain.AccessLabelSelectorMove{{RuleIndex: 1, Fingerprint: plain.Fingerprint()}}},
		{"invalid rule", []domain.AccessLabelSelectorMove{{RuleIndex: 2, Fingerprint: label.Fingerprint()}}},
		{"invalid child", []domain.AccessLabelSelectorMove{{RuleIndex: 0, ChildIndex: &missingChild, Fingerprint: label.Fingerprint()}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, plan, err := rules.PlanAccessLabelSelectorMoves(tc.moves, domain.TenantPolicy(), domain.ModuleSetOf("iam"))
			require.Error(t, err)
			require.Nil(t, got)
			require.Nil(t, plan)
			require.Nil(t, rules[0].MatchAccessLabels)
			require.Equal(t, pos.Fingerprint, rules[0].Fingerprint())
		})
	}
}

func TestPlanAccessLabelSelectorMovesCopiesOnlyOriginalPredicatePairs(t *testing.T) {
	before := domain.Rules{{
		Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"company": "a", "empty": ""},
		Children: []domain.Rule{{
			Resources: []string{"project"}, Verbs: []string{"list"},
			MatchLabels: map[string]string{"team": "ops"},
		}},
	}}
	child := 0
	next, plan, err := before.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{
		{RuleIndex: 0, ChildIndex: &child, Fingerprint: before[0].Children[child].Fingerprint()},
		{RuleIndex: 0, Fingerprint: before[0].Fingerprint()},
	}, domain.TenantPolicy(), domain.ModuleSetOf("iam"))
	require.NoError(t, err)
	require.Len(t, plan, 2)
	ruleIndex, childIndex := plan[0].Position()
	require.Zero(t, ruleIndex)
	require.Zero(t, childIndex)
	ruleIndex, childIndex = plan[1].Position()
	require.Zero(t, ruleIndex)
	require.Equal(t, -1, childIndex)

	// Изменения любой из карт роли после извлечения не меняют исходный предикат.
	before[0].MatchLabels["company"] = "b"
	next[0].Children[0].MatchAccessLabels["team"] = "dev"
	container := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "account-1",
		Labels:       map[string]string{"company": "a", "empty": "", "team": "ops", "display": "ordinary"},
		AccessLabels: map[string]string{"unrelated": "protected", "empty": ""},
	}
	project := domain.MirrorObject{ObjectType: "iam.project", ObjectID: "project-1",
		Labels: map[string]string{"company": "a", "empty": "", "team": "ops"},
	}
	require.False(t, plan[0].MatchesObject(container))
	require.False(t, plan[1].MatchesObject(project))
	copied, changed, err := plan[1].CopyAccessLabels(container)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, map[string]string{"company": "a", "empty": "", "unrelated": "protected"}, copied)
	require.Equal(t, map[string]string{"unrelated": "protected", "empty": ""}, container.AccessLabels)
	container.AccessLabels = copied
	copied, changed, err = plan[1].CopyAccessLabels(container)
	require.NoError(t, err)
	require.False(t, changed)
	require.Nil(t, copied)

	copied, changed, err = plan[0].CopyAccessLabels(project)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, map[string]string{"team": "ops"}, copied)
	require.Nil(t, project.AccessLabels)
	delete(container.Labels, "empty")
	require.False(t, plan[1].MatchesObject(container))
	copied, changed, err = plan[1].CopyAccessLabels(container)
	require.NoError(t, err)
	require.False(t, changed)
	require.Nil(t, copied)
}

func TestPlanAccessLabelSelectorMovesRejectsInvalidProtectedMerge(t *testing.T) {
	rules := domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "ops", "env": "prod"},
	}}
	_, plan, err := rules.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{{Fingerprint: rules[0].Fingerprint()}},
		domain.TenantPolicy(), domain.ModuleSetOf("iam"))
	require.NoError(t, err)
	require.Len(t, plan, 1)

	object := domain.MirrorObject{ObjectType: "iam.project", ObjectID: "project-1",
		Labels:       map[string]string{"team": "ops", "env": "prod"},
		AccessLabels: map[string]string{"team": "dev"},
	}
	copied, changed, err := plan[0].CopyAccessLabels(object)
	require.ErrorContains(t, err, "conflicting access label")
	require.False(t, changed)
	require.Nil(t, copied)
	require.Equal(t, map[string]string{"team": "dev"}, object.AccessLabels)

	object.AccessLabels = make(map[string]string, 64)
	for i := range 64 {
		object.AccessLabels[fmt.Sprintf("key%d", i)] = "value"
	}
	copied, changed, err = plan[0].CopyAccessLabels(object)
	require.ErrorContains(t, err, "cardinality")
	require.False(t, changed)
	require.Nil(t, copied)
	require.Len(t, object.AccessLabels, 64)
}
