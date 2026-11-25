// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveCopiesFromSelectedProjectProjection(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "account", ObjectType: "account"},
			{Module: "iam", Resource: "project", ObjectType: "project"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "iam", Resource: "account", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "project", Verb: "get", PerObject: true},
		},
	}})
	require.NoError(t, err)
	role := domain.Rules{
		{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "direct"}},
		{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, ResourceNames: []string{"acc-graph"}, Children: []domain.Rule{
			{Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "nested"}},
		}},
	}
	child := 0
	proposed, moves, err := role.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{
		{RuleIndex: 0, Fingerprint: role[0].Fingerprint()},
		{RuleIndex: 1, ChildIndex: &child, Fingerprint: role[1].Children[0].Fingerprint()},
	}, domain.PolicyOfRole(false, ""), facts)
	require.NoError(t, err)
	ref := domain.ResourceRef{Type: "iam.project", ID: "prj-child"}
	own := domain.MirrorObject{ObjectType: ref.Type, ObjectID: ref.ID, ParentAccountIDs: []string{"acc-own"},
		Labels: map[string]string{"team": "direct"}, AccessLabels: map[string]string{"owner": "kept"}}
	leaf := domain.MirrorObject{ObjectType: ref.Type, ObjectID: ref.ID, ParentAccountIDs: []string{"acc-graph"},
		Labels: map[string]string{"team": "nested"}, AccessLabels: map[string]string{"team": "stale"}}
	account := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "acc-graph", ParentAccountIDs: []string{"acc-graph"}}
	graph := accessLabelMoveGraph{Present: true, Object: own, Project: &resourceeffect.ProjectGraphProjection{
		Object: &leaf, Ancestors: []domain.MirrorObject{account},
	}}
	graphs := map[domain.ResourceRef]accessLabelMoveGraph{ref: graph}
	budget := &relverdict.AdministrativeReadBudget{}
	coordinates, err := accessLabelMoveRetainedCoordinates(t.Context(), accessLabelSelectorMoveCapture{Graphs: graphs}, budget)
	require.NoError(t, err)
	require.ElementsMatch(t, []domain.ResourceRef{ref, {Type: account.ObjectType, ID: account.ObjectID}}, coordinates)
	plan := func(indices ...int) (accessLabelMoveCopyPlan, error) {
		return planAccessLabelMoveCopies(t.Context(), moves, map[domain.ResourceRef][]int{ref: indices}, graphs, budget)
	}

	direct, err := plan(0)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"team": "direct", "owner": "kept"}, direct.labels[ref])
	require.Empty(t, direct.projectPairs)
	nested, err := plan(1)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"team": "nested", "owner": "kept"}, nested.labels[ref])
	require.Equal(t, map[string]string{"team": "nested"}, nested.projectPairs[ref])
	require.Equal(t, map[string]string{"owner": "kept"}, own.AccessLabels)
	require.Equal(t, map[string]string{"team": "stale"}, leaf.AccessLabels)

	_, err = plan(0, 1)
	require.Error(t, err, "разные положения не могут записать одно значение по порядку обхода")
	_, err = compileAccessLabelMoveEffect(t.Context(), facts, nil, graphs, nested, nil, time.Unix(123456, 0), budget)
	require.NoError(t, err)
	_, err = compileAccessLabelMoveEffect(t.Context(), facts, nil, graphs, accessLabelMoveCopyPlan{labels: nested.labels}, nil, time.Unix(123456, 0), budget)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "совпадающей метки зеркала без выбранной позиции недостаточно")

	graph.Project = &resourceeffect.ProjectGraphProjection{ConfirmedAbsent: ref}
	graphs[ref] = graph
	_, err = plan(1)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	_, err = plan(0)
	require.NoError(t, err)

	t.Run("область роли включает собственную строку проекта", func(t *testing.T) {
		p := parentCaptureFixture(t)
		p.catalogs["iam.project"] = &resourceCatalogCapture{rows: []resourceCatalogRow{
			{identity: domain.CatalogTypeIdentity{Dotted: "iam.project", ObjectType: "project"}, live: true},
		}}
		p.catalogs["iam.account"] = &resourceCatalogCapture{rows: []resourceCatalogRow{
			{identity: domain.CatalogTypeIdentity{Dotted: "iam.account", ObjectType: "account"}, live: true},
		}}
		parentCaptureProject(t, p, ref.ID, "acc-own")
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: ref.Type, id: ref.ID},
			map[string]any{"id": ref.ID, "account_id": "acc-own", "labels": own.Labels, "access_labels": own.AccessLabels})
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: ref.Type, id: ref.ID},
			map[string]any{"object_type": ref.Type, "object_id": ref.ID, "parent_account_id": "acc-graph", "labels": leaf.Labels})
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceParentEdges, typ: "project", id: ref.ID},
			resourceObjectParentEdge{Type: "account", ID: account.ObjectID, Depth: 1})
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: account.ObjectType, id: account.ObjectID},
			map[string]string{"id": account.ObjectID})
		captured := accessLabelSelectorMoveCapture{
			Before: domain.Role{ID: "rol-local", AccountID: "acc-graph", Rules: role}, Moves: moves, ProposedRules: proposed,
		}
		scope := reconcile.BindingScope{Scope: domain.ScopeAnchor{Type: "account", ID: "acc-graph"}, Target: domain.AccessTarget{AllInScope: true}}
		_, err := p.captureAccessLabelMoveDefinitionCandidates(t.Context(), captured, scope, map[domain.ResourceRef][]int{ref: {1}})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "совпадение зеркала не разрешает запись в аккаунт собственной строки")
	})
}
