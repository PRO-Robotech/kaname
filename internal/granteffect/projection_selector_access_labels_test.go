// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package granteffect

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProjectionJSONProtectedSelectorPreservesLegacyBytes(t *testing.T) {
	s := domain.RuleSelector{RuleFP: "fp", Arm: domain.ArmLabels, ObjectTypes: []string{"iam.project"}, MatchLabels: map[string]string{"team": "a"}, Grants: map[string][]string{"iam.project": {"get"}}}
	raw, err := ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.NoError(t, err)
	require.Equal(t, `{"Capabilities":[],"Selectors":[{"FP":"fp","Arm":"labels","Types":["iam.project"],"Names":[],"Labels":{"team":"a"},"Container":null,"Creator":false,"Grants":{"iam.project":["get"]}}],"Verbs":[]}`, string(raw))
	s.Arm = domain.ArmAccessLabels
	s.MatchAccessLabels = s.MatchLabels
	s.MatchLabels = nil
	protected, err := ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.NoError(t, err)
	require.Contains(t, string(protected), `"AccessLabels":{"team":"a"}`)
	require.NotEqual(t, string(raw), string(protected))
	s.Container = &domain.ContainerSelector{Type: "iam.account", Arm: domain.ArmAccessLabels, MatchAccessLabels: map[string]string{"env": "prod"}}
	nested, err := ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.NoError(t, err)
	require.Contains(t, string(nested), `"MatchAccessLabels":{"env":"prod"}`)
	s.Container.MatchAccessLabels["env"] = "dev"
	changed, err := ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.NoError(t, err)
	require.NotEqual(t, string(nested), string(changed))
	s.MatchLabels = map[string]string{"team": "a"}
	_, err = ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.Error(t, err)
}
