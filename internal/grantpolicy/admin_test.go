// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

func TestScopeAdminWitnessPreservesTypedPathNamesLabelsAndCreator(t *testing.T) {
	scope := domain.ScopeAnchor{Type: "project", ID: "prj_a"}
	objects := map[string]scopeObject{
		"project": {anchor: scope, account: "acc_a", labels: domain.Labels{"env": "prod"}},
		"account": {anchor: domain.ScopeAnchor{Type: "account", ID: "acc_a"}, account: "acc_a"},
	}
	base := granteffect.Effect{Kind: granteffect.ScopeAdmin, Type: "project", Constraints: []granteffect.Constraint{{Type: "account", Path: []authzmodel.EffectHop{{From: "project", Pointer: "account", To: "account"}}, Region: grantcoverage.Region{Objects: grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{"acc_a"}}, Creator: grantcoverage.Creator{Kind: grantcoverage.AnyCreator}}}}}
	require.True(t, scopeEffectMatches(base, scope, objects))
	for _, test := range []struct {
		name string
		edit func(*granteffect.Constraint)
	}{
		{"other account", func(c *granteffect.Constraint) { c.Region.Objects.IDs = []string{"acc_b"} }},
		{"unproved pointer", func(c *granteffect.Constraint) {
			c.Path = []authzmodel.EffectHop{{From: "project", Pointer: "billing_owner", To: "account"}}
		}},
		{"creator restriction", func(c *granteffect.Constraint) {
			c.Region.Creator = grantcoverage.Creator{Kind: grantcoverage.ExactCreator, Subject: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_a"}}
		}},
		{"labels retained", func(c *granteffect.Constraint) { c.Region.Labels = map[string]string{"env": "prod"} }},
		{"different within", func(c *granteffect.Constraint) { c.Within = &domain.ScopeAnchor{Type: "account", ID: "acc_b"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := base
			copy.Constraints = append([]granteffect.Constraint{}, base.Constraints...)
			test.edit(&copy.Constraints[0])
			require.False(t, scopeEffectMatches(copy, scope, objects))
		})
	}
}
func TestProposedControlCarrierRejectsFiniteTargetBeforeAdmin(t *testing.T) {
	b := granteffect.Binding{SourceID: "proposed", Role: domain.Role{ID: "rol_a", Rules: domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}}, Scope: domain.ScopeAnchor{Type: "account", ID: "acc_a"}, Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_a"}, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.role", ID: "rol_a"}}}, CapabilityVersion: 1}
	require.Error(t, validateProposed(b))
	b.Target = domain.AccessTarget{AllInScope: true}
	require.NoError(t, validateProposed(b))
}
