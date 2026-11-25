// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/stretchr/testify/require"
)

func TestProjectionCheckpointAccessLabelNeedsCatalogAndExactPlan(t *testing.T) {
	const first = "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	const second = "4d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	rows := bundleRows()
	rows.Live.Resources = append(rows.Live.Resources, catalog.ResourceRow{Module: "iam", Resource: "accessLabel", ObjectType: grantcapability.AccessLabelObjectType})
	rows.Live.Verbs = append(rows.Live.Verbs, catalog.VerbRow{Module: "iam", Resource: "accessLabel", Verb: "apply"})
	b, err := NewBundle(context.Background(), authzmodel.DSL, rows, ProjectorVersion)
	require.NoError(t, err)
	role := domain.Role{Rules: domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{first}}}}
	projection, err := b.Projection(role)
	require.NoError(t, err)
	require.Len(t, projection.Capabilities, 1)
	require.Equal(t, domain.GrantCapabilityApplyAccessLabel, projection.Capabilities[0].Kind)
	require.Equal(t, domain.AccessLabelDefinitionID(first), projection.Capabilities[0].DefinitionID)
	require.Empty(t, projection.Capabilities[0].BoundRoleID)
	require.Empty(t, projection.Selectors)
	require.Empty(t, projection.Verbs)
	canonical, err := ProjectionJSON(projection.Selectors, projection.Verbs, projection.Capabilities)
	require.NoError(t, err)
	require.Equal(t, digest(canonical), projection.Checkpoint.ProjectionID)
	missing, err := ProjectionJSON(nil, nil)
	require.NoError(t, err)
	require.NotEqual(t, digest(missing), projection.Checkpoint.ProjectionID, "пустая сохранённая проекция не подтверждает apply")

	role.Rules[0].ResourceNames = []string{second}
	changed, err := b.Projection(role)
	require.NoError(t, err)
	require.NotEqual(t, projection.Checkpoint.AuthoredID, changed.Checkpoint.AuthoredID)
	require.NotEqual(t, projection.Checkpoint.ProjectionID, changed.Checkpoint.ProjectionID)
	projection.Capabilities[0].DefinitionID = second
	role.Rules[0].ResourceNames = []string{first}
	again, err := b.Projection(role)
	require.NoError(t, err)
	require.Equal(t, domain.AccessLabelDefinitionID(first), again.Capabilities[0].DefinitionID)

	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-axis", true: "retired-axis"}[retired], func(t *testing.T) {
			withoutAxis := rows
			withoutAxis.Live.Verbs = append([]catalog.VerbRow{}, rows.Live.Verbs[:len(rows.Live.Verbs)-1]...)
			if retired {
				withoutAxis.Retired.Verbs = []catalog.VerbRow{rows.Live.Verbs[len(rows.Live.Verbs)-1]}
			}
			bundle, err := NewBundle(context.Background(), authzmodel.DSL, withoutAxis, ProjectorVersion)
			require.NoError(t, err)
			_, err = bundle.Projection(role)
			require.Error(t, err)
		})
	}
	for name, model := range map[string]string{
		"missing-plan": strings.Replace(authzmodel.DSL, accessLabelModel, "\n", 1),
		"wrong-subjects": strings.Replace(authzmodel.DSL, accessLabelModel,
			"\ntype iam_grant_access_label\n  relations\n    define apply: [user, service_account]\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, authzmodel.DSL, model)
			// Изолируем проверку Projection от более раннего admission модели.
			// Такой изменённый Bundle не передаётся публичному writer.
			compiler, err := New(model, rows)
			require.NoError(t, err)
			altered := *b
			altered.compiler, altered.modelSource = compiler, model
			_, err = altered.Projection(role)
			require.Error(t, err)
		})
	}
}

func TestProjectionJSONAccessLabelPayloadAndLegacyBytes(t *testing.T) {
	const first domain.AccessLabelDefinitionID = "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	const second domain.AccessLabelDefinitionID = "4d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	legacy := []domain.GrantCapabilityRule{
		{RuleFP: "b", Kind: domain.GrantCapabilityBindRole, BoundRoleID: "rol_target"},
		{RuleFP: "a", Kind: domain.GrantCapabilityCreateBinding},
	}
	encoded, err := ProjectionJSON(nil, nil, legacy)
	require.NoError(t, err)
	const prior = `{"Capabilities":[{"RuleFP":"a","Kind":"create_binding","BoundRoleID":""},{"RuleFP":"b","Kind":"bind_role","BoundRoleID":"rol_target"}],"Selectors":[],"Verbs":[]}`
	require.Equal(t, prior, string(encoded), "прежний JSON, включая отсутствие DefinitionID, неизменен")
	a := domain.GrantCapabilityRule{RuleFP: "same-origin", Kind: domain.GrantCapabilityApplyAccessLabel, DefinitionID: first}
	z := a
	z.DefinitionID = second
	forward, err := ProjectionJSON(nil, nil, []domain.GrantCapabilityRule{a, z})
	require.NoError(t, err)
	backward, err := ProjectionJSON(nil, nil, []domain.GrantCapabilityRule{z, a})
	require.NoError(t, err)
	require.Equal(t, string(forward), string(backward))
	require.Less(t, strings.Index(string(forward), string(first)), strings.Index(string(forward), string(second)))
	one, err := ProjectionJSON(nil, nil, []domain.GrantCapabilityRule{a})
	require.NoError(t, err)
	other, err := ProjectionJSON(nil, nil, []domain.GrantCapabilityRule{z})
	require.NoError(t, err)
	require.NotEqual(t, digest(one), digest(other))

	for _, malformed := range []domain.GrantCapabilityRule{
		{Kind: "unknown"},
		{Kind: domain.GrantCapabilityCreateBinding, DefinitionID: first},
		{Kind: domain.GrantCapabilityCreateBinding, BoundRoleID: "rol_target"},
		{Kind: domain.GrantCapabilityBindRole},
		{Kind: domain.GrantCapabilityBindRole, BoundRoleID: "*"},
		{Kind: domain.GrantCapabilityBindRole, BoundRoleID: "rol_target", DefinitionID: first},
		{Kind: domain.GrantCapabilityApplyAccessLabel},
		{Kind: domain.GrantCapabilityApplyAccessLabel, DefinitionID: "*"},
		{Kind: domain.GrantCapabilityApplyAccessLabel, DefinitionID: "3D9cd5bf-906f-4bbe-8a8b-234ba2efa54a"},
		{Kind: domain.GrantCapabilityApplyAccessLabel, DefinitionID: first, BoundRoleID: "rol_target"},
	} {
		_, err := ProjectionJSON(nil, nil, []domain.GrantCapabilityRule{malformed})
		require.Error(t, err, "%+v", malformed)
	}
}
