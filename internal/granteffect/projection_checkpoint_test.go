// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestProjectionCheckpointUsesRelevantInputsAndCopies(t *testing.T) {
	rows := bundleRows()
	build := func(rows catalog.Halves) *Bundle {
		b, err := NewBundle(context.Background(), authzmodel.DSL, rows, ProjectorVersion)
		require.NoError(t, err)
		return b
	}
	b := build(rows)
	role := domain.Role{ID: "role", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}}
	original, err := b.Projection(role)
	require.NoError(t, err)
	require.NotEmpty(t, original.Checkpoint.AuthoredID)
	require.NotEmpty(t, original.Selectors)
	require.NotEmpty(t, original.Verbs)
	// Read-only callback и metadata не участвуют в authored semantics.
	metadata := role
	metadata.ID, metadata.Name, metadata.Description = "other", "other", "other"
	metadata.TypeVerbs = func(string, string) ([]string, bool) {
		t.Fatal("checkpoint вызвал read-only TypeVerbs")
		return nil, false
	}
	withCallback, err := b.Projection(metadata)
	require.NoError(t, err)
	require.Equal(t, original.Checkpoint, withCallback.Checkpoint)
	withCallback.Selectors[0].ObjectTypes[0] = "changed"
	require.Equal(t, "account", role.Rules[0].Resources[0])
	rows.Live.Modules = append(rows.Live.Modules, "unrelated")
	other := build(rows)
	foreign, err := other.Projection(role)
	require.NoError(t, err)
	require.NotEqual(t, b.Identity().CatalogID, other.Identity().CatalogID)
	require.Equal(t, original.Checkpoint, foreign.Checkpoint, "чужой модуль не меняет checkpoint роли")
	rows.Live.Verbs[0].PerObject = false
	changed, err := build(rows).Projection(role)
	require.NoError(t, err)
	require.NotEqual(t, original.Checkpoint.RelevantCatalogID, changed.Checkpoint.RelevantCatalogID)
	role.Rules[0].ResourceNames = []string{"one"}
	authored, err := b.Projection(role)
	require.NoError(t, err)
	require.NotEqual(t, original.Checkpoint.AuthoredID, authored.Checkpoint.AuthoredID)
	require.NotEqual(t, original.Checkpoint.ProjectionID, authored.Checkpoint.ProjectionID)
	original.Selectors[0].Grants["iam.account"] = []string{"invented"}
	original.Catalog.Live.Resources[0].ObjectType = "changed"
	original.Modules[0] = "changed"
	again, err := b.Projection(domain.Role{ID: "role", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}})
	require.NoError(t, err)
	require.Equal(t, foreign.Checkpoint, again.Checkpoint)
	_, err = (*Bundle)(nil).Projection(role)
	require.Error(t, err)
	_, err = b.Projection(domain.Role{Rules: domain.Rules{{Module: "missing", Resources: []string{"account"}, Verbs: []string{"get"}}}})
	require.Error(t, err)
}

func TestProjectionCanonicalFormKeepsCreatorAndStoredContainer(t *testing.T) {
	s := domain.RuleSelector{RuleFP: "one", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.serviceAccount"}, CreatedBySubject: true, Grants: map[string][]string{"iam.serviceAccount": {"get", "list"}}, Container: &domain.ContainerSelector{Type: "iam.account", OwnerFP: "authored-only", Arm: domain.ArmNames, ResourceNames: []string{"b", "a"}}}
	first, err := ProjectionJSON([]domain.RuleSelector{s}, []domain.RoleVerb{{ObjectType: "iam.serviceAccount", Verb: "list"}, {ObjectType: "iam.serviceAccount", Verb: "get"}})
	require.NoError(t, err)
	require.True(t, json.Valid(first))
	s.Container.OwnerFP = ""
	s.Container.ResourceNames = []string{"a", "b"}
	s.Grants["iam.serviceAccount"] = []string{"list", "get"}
	second, err := ProjectionJSON([]domain.RuleSelector{s}, []domain.RoleVerb{{ObjectType: "iam.serviceAccount", Verb: "get"}, {ObjectType: "iam.serviceAccount", Verb: "list"}})
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))
	s.CreatedBySubject = false
	third, err := ProjectionJSON([]domain.RuleSelector{s}, nil)
	require.NoError(t, err)
	require.NotEqual(t, string(first), string(third))
}
