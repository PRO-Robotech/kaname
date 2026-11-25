// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func initialRegistrationCaptureFixture(t *testing.T) *resourceRegistrationPreparation {
	t.Helper()
	parents, _, module, intent := resourceRegistrationPrepareFixture(t)
	const project, account = "prj-next", "acc-next"
	parentCaptureObject(t, parents, "object", "key", "", domain.WritePolicy{
		Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}},
	})
	parentCaptureProject(t, parents, project, account)
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceMirror, typ: "example.object", id: "key"})
	intent.Tuple.User, intent.Tuple.Relation = "project:"+project, "project"
	intent.Mirror.ParentProjectID = project
	intent.Mirror.ParentChain = domain.ProjectHierarchy(project, account).Links
	intent.Mirror.Labels = map[string]string{"team": "ordinary"}
	intent.Mirror.SourceVersion = time.Date(2026, 11, 25, 16, 0, 0, 0, time.UTC)
	p, err := prepareResourceRegistration(context.Background(), parents, module, intent)
	require.NoError(t, err)
	require.Equal(t, account, p.row.ParentAccountID, "данные владельца берутся из канонической строки проекта")

	for _, kind := range []resourceSourceKind{
		resourceSourceDescendantEdges, resourceSourceRegistrationPointers, resourceSourceObjectReceipts,
		resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceFactLedgerHolders,
	} {
		parentCaptureRows(t, parents, resourceSourceKey{kind: kind, typ: "object", id: "key"})
	}
	for _, kind := range []resourceSourceKind{resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceBindingsNamingObject, resourceSourceMetadataPolicyReceipt} {
		parentCaptureRows(t, parents, resourceSourceKey{kind: kind, typ: "example.object", id: "key"})
	}
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.project", id: project},
		map[string]any{"id": project, "account_id": account, "labels": map[string]string{"ordinary-parent": "yes"}})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.account", id: account},
		map[string]any{"id": account, "access_labels": map[string]string{"protected-parent": "yes"}})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "project", id: project},
		map[string]any{"object_type": "project", "object_id": project, "relation": "account", "subject": "account:" + account})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "account", id: account},
		map[string]any{"object_type": "account", "object_id": account, "relation": "cluster", "subject": "cluster:" + domain.ClusterSingletonID})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "cluster", id: domain.ClusterSingletonID})
	for _, scope := range []domain.ScopeAnchor{{Type: "project", ID: project}, {Type: "account", ID: account}, {Type: "cluster", ID: domain.ClusterSingletonID}} {
		parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceFactLedgerHolders, typ: scope.Type, id: scope.ID})
		parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRegistrationScopeBindings, typ: scope.Type, id: scope.ID})
	}
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceClusterFactHolders, typ: "cluster", id: domain.ClusterSingletonID})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRegistrationOtherClusterBindings, typ: "cluster", id: domain.ClusterSingletonID})
	return p
}

func TestInitialRegistrationCaptureUsesAbsentRootAndCanonicalNew(t *testing.T) {
	p := initialRegistrationCaptureFixture(t)
	capture, err := p.captureInitialRegistrationLabels(context.Background(), domain.Labels{"team": "protected"})
	require.NoError(t, err)
	require.Same(t, p.parents.source, capture.source)
	require.False(t, capture.source.sealed)
	require.Equal(t, p.row.SourceVersion, capture.sourceVersion)
	require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(p.module.actor)}, capture.actor)
	require.Equal(t, domain.ResourceRef{Type: "example.object", ID: "key"}, capture.image.Root)
	require.Equal(t, "prj-next", capture.image.New.ParentProjectID)
	require.Equal(t, []string{"acc-next"}, capture.image.New.ParentAccountIDs)
	require.Equal(t, map[string]string{"team": "protected"}, capture.image.New.AccessLabels)
	require.Equal(t, map[string]string{"team": "ordinary"}, capture.image.New.Labels)
	require.Len(t, capture.image.Ancestors, 3)
	require.Equal(t, map[string]string{"ordinary-parent": "yes"}, capture.image.Ancestors[0].Object.Labels)
	require.Equal(t, map[string]string{"protected-parent": "yes"}, capture.image.Ancestors[1].Object.AccessLabels)
	require.Equal(t, []authzmodel.EffectHop{
		{From: "object", Pointer: "project", To: "project"},
		{From: "project", Pointer: "account", To: "account"},
		{From: "account", Pointer: "cluster", To: "cluster"},
	}, capture.image.Ancestors[2].Path)
	require.Len(t, capture.ancestors, 3)
	require.Empty(t, capture.bindings)
	p.row.Labels["team"] = "mutated"
	require.Equal(t, map[string]string{"team": "ordinary"}, capture.image.New.Labels)
}

func TestInitialRegistrationCaptureKeepsAuthoredBindingWithoutSelectorRow(t *testing.T) {
	p := initialRegistrationCaptureFixture(t)
	parents := p.parents
	const bindingID, roleID = "acb-initial", "rol-initial"
	expires := time.Date(2026, 11, 26, 16, 0, 0, 0, time.UTC)
	rules := domain.Rules{{Module: "example", Resources: []string{"object"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "protected"}}}
	rulesJSON, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	bindingRow := map[string]any{"id": bindingID, "role_id": roleID, "scope": int(domain.ScopeProject),
		"resource_type": "project", "resource_id": "prj-next", "status": "PENDING", "expires_at": expires,
		"grant_capability_version": 1, "labels": map[string]string{}, "target": map[string]bool{"allInScope": true}}
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRegistrationScopeBindings, typ: "project", id: "prj-next"}, bindingRow)
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: bindingID}, bindingRow)
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: bindingID},
		map[string]any{"binding_id": bindingID, "subject_type": "user", "subject_id": "usr-first", "ordinal": 0},
		map[string]any{"binding_id": bindingID, "subject_type": "user", "subject_id": "usr-second", "ordinal": 1})
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: roleID},
		map[string]any{"id": roleID, "project_id": "prj-next", "rules": json.RawMessage(rulesJSON),
			"permissions": []string{}, "labels": map[string]string{}, "live": true})
	for _, kind := range []resourceSourceKind{resourceSourceRoleSelectors, resourceSourceRoleVerbs} {
		parentCaptureRows(t, parents, resourceSourceKey{kind: kind, typ: "role", id: roleID})
	}
	parentCaptureRows(t, parents, resourceSourceKey{kind: resourceSourceRolePendingVerbs, typ: "role", id: roleID}, map[string]any{"role_id": roleID})

	capture, err := p.captureInitialRegistrationLabels(context.Background(), domain.Labels{"team": "protected"})
	require.NoError(t, err)
	require.Len(t, capture.bindings, 1)
	got := capture.bindings[0]
	require.Equal(t, bindingID, got.binding.SourceID)
	require.Equal(t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr-first"}, {Type: domain.SubjectTypeUser, ID: "usr-second"}}, got.binding.Subjects)
	require.Equal(t, 1, got.binding.CapabilityVersion)
	require.Equal(t, rules[0].MatchAccessLabels, got.authoredRules[0].MatchAccessLabels)
	require.True(t, got.pending)
	require.True(t, got.projectionPending)
	require.Equal(t, &expires, got.expiresAt)
}

func TestInitialRegistrationCaptureRefusesOldSourcesAndUnprovenScope(t *testing.T) {
	for _, kind := range []resourceSourceKind{resourceSourceMirror, resourceSourceRegistrationScopes,
		resourceSourceObjectReceipts, resourceSourceObjectRetirement, resourceSourcePointerFacts, resourceSourceDescendantEdges,
		resourceSourceObjectLedger} {
		p := initialRegistrationCaptureFixture(t)
		typ := "object"
		if kind == resourceSourceMirror || kind == resourceSourceObjectLedger {
			typ = "example.object"
		}
		parentCaptureRows(t, p.parents, resourceSourceKey{kind: kind, typ: typ, id: "key"}, map[string]string{"old": "source"})
		capture, err := p.captureInitialRegistrationLabels(context.Background(), domain.Labels{"team": "protected"})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "прошлая регистрация, даже без зеркала, не является пустым OLD")
		require.Nil(t, capture)
	}
	for _, mutate := range []func(*resourceRegistrationPreparation){
		func(p *resourceRegistrationPreparation) { p.row.SourceVersion = time.Time{} },
		func(p *resourceRegistrationPreparation) { p.row.SourceVersion = p.row.SourceVersion.Add(time.Second) },
		func(p *resourceRegistrationPreparation) { p.row.Labels["team"] = "mismatch" },
		func(p *resourceRegistrationPreparation) { p.row.ParentAccountID = "acc-other" },
		func(p *resourceRegistrationPreparation) { p.row.ParentChain = p.row.ParentChain[:1] },
		func(p *resourceRegistrationPreparation) { p.parents.source.sealed = true },
	} {
		p := initialRegistrationCaptureFixture(t)
		mutate(p)
		capture, err := p.captureInitialRegistrationLabels(context.Background(), domain.Labels{"team": "protected"})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.Nil(t, capture)
	}
	p := initialRegistrationCaptureFixture(t)
	parentCaptureRows(t, p.parents, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "project", id: "prj-next"},
		map[string]any{"object_type": "project", "object_id": "prj-next", "relation": "account", "subject": "account:acc-other"})
	capture, err := p.captureInitialRegistrationLabels(context.Background(), domain.Labels{"team": "protected"})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, capture)
}
