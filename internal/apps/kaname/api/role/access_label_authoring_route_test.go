// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package role

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type positiveRouteFactory struct {
	kaname.RoleAuthorityWriterFactory
}

func (*positiveRouteFactory) RoleMutationWriter(context.Context, kaname.RoleMutationRequest, domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return nil, nil
}

type positiveRouteProjection struct {
	Writer
	projection catalog.GrantProjection
	failure    error
}

func (w *positiveRouteProjection) ProjectRoleMutationRules(context.Context, domain.Role) (catalog.GrantProjection, error) {
	return w.projection, w.failure
}
func positiveRouteRules() domain.Rules {
	return domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{"3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"}}}
}

func TestPositiveApplyAdmissionIsScopedToPreparedFactory(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "accessLabel", ObjectType: "iam_grant_access_label"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "accessLabel", Verb: "apply"}}}})
	require.NoError(t, err)
	for _, selection := range []rolePolicySelection{{}, {configured: true}} {
		_, err = selection.projectAdmissionRules(facts, positiveRouteRules(), domain.TenantPolicy())
		require.Error(t, err)
	}
	selection := rolePolicySelection{configured: true, factory: &positiveRouteFactory{}}
	projection, err := selection.projectAdmissionRules(facts, positiveRouteRules(), domain.TenantPolicy())
	require.NoError(t, err)
	require.Len(t, projection.Capabilities, 1)
	require.Equal(t, domain.GrantCapabilityApplyAccessLabel, projection.Capabilities[0].Kind)
	require.Empty(t, projection.Permissions)
}

func TestPositiveApplyWorkerProjectionNeverFallsBack(t *testing.T) {
	role := domain.Role{Rules: positiveRouteRules()}
	_, err := projectWriterRoleRules(context.Background(), nil, role, nil)
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	sentinel := errors.New("prepared projection rejected")
	_, err = projectWriterRoleRules(context.Background(), &positiveRouteProjection{failure: sentinel}, role, nil)
	require.ErrorIs(t, err, sentinel)
	caps := []domain.GrantCapabilityRule{{Kind: domain.GrantCapabilityApplyAccessLabel, DefinitionID: "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"}, {Kind: domain.GrantCapabilityCreateBinding}}
	projected, err := projectWriterRoleRules(context.Background(), &positiveRouteProjection{projection: catalog.GrantProjection{Capabilities: caps}}, role, nil)
	require.NoError(t, err)
	require.Equal(t, caps, projected.Capabilities)
}

func TestPositiveApplyDirectWorkerRefusesLegacyBeforeBody(t *testing.T) {
	for _, create := range []bool{true, false} {
		called := false
		_, err := (rolePolicySelection{}).runPrepared(context.Background(), nil, domain.Role{Rules: positiveRouteRules()}, create, true, nil, "", nil, func(context.Context, Writer) (domain.Role, error) { called = true; return domain.Role{}, nil })
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
		require.False(t, called)
	}
}

func TestProtectedSelectorTransportAndPreparedWriterGuards(t *testing.T) {
	proto := &iamv1.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchAccessLabels: map[string]string{"team": "retained"}}
	require.NoError(t, refuseNestedRulesOnInput([]*iamv1.Rule{proto}))
	rules := rulesFromProto([]*iamv1.Rule{proto})
	proto.MatchAccessLabels["team"] = "changed"
	require.Equal(t, "retained", rules[0].MatchAccessLabels["team"])
	require.Nil(t, rules[0].MatchLabels)

	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"iam"},
		Resources: []catalog.ResourceRow{{Module: "iam", Resource: "project", ObjectType: "project"}},
		Verbs:     []catalog.VerbRow{{Module: "iam", Resource: "project", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	for _, selection := range []rolePolicySelection{{}, {configured: true}} {
		_, err = selection.projectAdmissionRules(facts, rules, domain.TenantPolicy())
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
	}
	allowed := rolePolicySelection{configured: true, factory: &positiveRouteFactory{}}
	projection, err := allowed.projectAdmissionRules(facts, rules, domain.TenantPolicy())
	require.NoError(t, err)
	require.Len(t, projection.Selectors, 1)
	require.Equal(t, domain.ArmAccessLabels, projection.Selectors[0].Arm)

	// Вложенный селектор также требует подготовленной записи при прямом
	// вызове worker, где транспортные проверки не выполняются.
	nested := domain.Rules{{Children: rules}}
	for _, wanted := range []domain.Rules{rules, nested} {
		value := domain.Role{Rules: wanted}
		_, err = projectWriterRoleRules(context.Background(), nil, value, nil)
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
		for _, create := range []bool{true, false} {
			_, err = (rolePolicySelection{}).runPrepared(context.Background(), nil, value, create, true, nil, "", nil,
				func(context.Context, Writer) (domain.Role, error) {
					t.Fatal("защищённый селектор дошёл до обычной записи роли")
					return domain.Role{}, nil
				})
			require.ErrorIs(t, err, iamerr.ErrUnavailable)
		}
	}
}

func TestSelectorMoveRequiresPreparedAuthorityBeforeBody(t *testing.T) {
	mask := []string{"rules"}
	moves := []domain.AccessLabelSelectorMove{{RuleIndex: 0}}
	called := false
	body := func(context.Context, Writer) (domain.Role, error) {
		called = true
		return domain.Role{}, nil
	}

	for _, selection := range []rolePolicySelection{
		{},
		{configured: true, factory: &positiveRouteFactory{}},
	} {
		_, err := selection.runPrepared(context.Background(), nil, domain.Role{}, false, true, &mask, "1", moves, body)
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.False(t, called)
	}
}
