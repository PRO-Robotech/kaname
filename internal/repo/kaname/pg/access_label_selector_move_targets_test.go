// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveBindingTargetsReadOldPredicateWithoutGrants(t *testing.T) {
	const parentType, childType = "vpc.network", "vpc.subnet"
	parentLabels, childLabels := map[string]string{"team": "red"}, map[string]string{"stage": "prod"}
	role := domain.Role{ID: "rol-move", Rules: domain.Rules{{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"update"}, MatchLabels: parentLabels,
		Children: []domain.Rule{{Resources: []string{"subnet"}, Verbs: []string{"get"}, MatchLabels: childLabels}},
	}}}
	child := 0
	// Индексы выбранных действий отличаются от позиций в развёрнутом правиле.
	request := []domain.AccessLabelSelectorMove{
		{RuleIndex: 0, ChildIndex: &child, Fingerprint: role.Rules[0].Children[0].Fingerprint()},
		{RuleIndex: 0, Fingerprint: role.Rules[0].Fingerprint()},
	}
	_, moves, err := role.Rules.PlanAccessLabelSelectorMoves(request, domain.PolicyOfRole(false, ""), domain.ModuleSetOf("vpc"))
	require.NoError(t, err)
	sels := role.Rules.MaterializingSelectorsInScope(domain.ScopeAccount)
	at := time.Unix(123456, 0)

	for _, tc := range []struct {
		name              string
		target            domain.AccessTarget
		parents, selected []string
	}{
		{"finite", domain.AccessTarget{Resources: []domain.ResourceRef{{Type: parentType, ID: "empty"}, {Type: parentType, ID: "root"}}}, []string{"empty", "root"}, []string{"empty", "root"}},
		{"whole", domain.AccessTarget{AllInScope: true}, []string{"empty", "root", "extra", "outside"}, []string{"empty", "extra", "root"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := parentCaptureFixture(t)
			binding := domain.AccessBinding{ID: "acb-move", RoleID: role.ID, Scope: domain.ScopeAccount,
				ResourceType: "account", ResourceID: "acc-a", Target: tc.target, Status: domain.AccessBindingStatusActive}
			bs := reconcile.BindingScope{BindingID: binding.ID, RoleID: string(role.ID), Scope: scopeAnchorFor(binding),
				Target: tc.target, Selectors: sels, Active: true, Subjects: []domain.Subject{{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}}}
			for _, selector := range sels {
				require.Empty(t, domain.GrantRecipients(bs.Subjects, selector.Verbs, selector.Container != nil))
			}
			captured := accessLabelSelectorMoveCapture{Before: role, Moves: moves,
				Carriers: []accessLabelSelectorMoveScope{{Before: bs, Carrier: accessLabelSelectorMoveCarrier{Binding: binding}}}}

			old := func(kind resourceSourceKind, typ string, predicate any, ids ...string) {
				t.Helper()
				raw, err := json.Marshal(predicate)
				require.NoError(t, err)
				var rows []any
				for _, id := range ids {
					rows = append(rows, map[string]string{"object_type": typ, "object_id": id})
				}
				parentCaptureRows(t, p, resourceSourceKey{kind: kind, typ: typ, id: string(binding.ID), projection: string(raw)}, rows...)
			}
			targetIDs := tc.target.ResourceIDsForTypes([]string{parentType})
			if targetIDs == nil {
				targetIDs = []string{}
			}
			predicate := resourceSelectorPredicate{RuleFP: sels[0].RuleFP, Arm: domain.ArmLabels, Scope: bs.Scope, Labels: parentLabels, Targets: targetIDs}
			old(resourceSourceSelectorObjects, parentType, predicate, tc.parents...)
			predicate.RuleFP, predicate.Container = sels[1].RuleFP, true
			old(resourceSourceSelectorObjects, parentType, predicate, tc.parents...)
			old(resourceSourceNestedDescendants, childType, resourceNestedPredicate{RuleFP: sels[1].RuleFP, ContainerType: parentType, ContainerIDs: tc.selected},
				"child", "wrong-label", "wrong-account")

			object := func(typ, id, account string, labels map[string]string) {
				parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: typ, id: id},
					map[string]any{"object_type": typ, "object_id": id, "parent_account_id": account, "labels": labels})
			}
			for _, id := range tc.parents {
				account := "acc-a"
				if id == "outside" {
					account = "acc-b"
				}
				object(parentType, id, account, parentLabels)
			}
			object(childType, "child", "acc-a", childLabels)
			object(childType, "wrong-label", "acc-a", nil)
			object(childType, "wrong-account", "acc-b", childLabels)
			for model, dotted := range map[string]string{"vpc_network": parentType, "vpc_subnet": childType} {
				catalog := &resourceCatalogCapture{rows: []resourceCatalogRow{{live: true, identity: domain.CatalogTypeIdentity{Dotted: dotted, ObjectType: model}}}}
				p.catalogs[model], p.catalogs[dotted] = catalog, catalog
			}
			edges := resourceSourceKey{kind: resourceSourceParentEdges, typ: "vpc_subnet", id: "child"}
			parentCaptureRows(t, p, edges, map[string]any{"parent_type": "vpc_network", "parent_id": "root", "depth": 1})

			census, err := p.captureAccessLabelMoveBindingTargets(t.Context(), captured)
			require.NoError(t, err)
			targets, err := census.targetsAt(t.Context(), at, p.source.budget)
			require.NoError(t, err)
			want := map[domain.ResourceRef][]int{{Type: childType, ID: "child"}: {0}}
			for _, id := range tc.selected {
				want[domain.ResourceRef{Type: parentType, ID: id}] = []int{1}
			}
			require.Equal(t, want, targets)

			parentCaptureRows(t, p, edges)
			_, err = p.captureAccessLabelMoveBindingTargets(t.Context(), captured)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "потомок из прямой переписи потерял выбранного предка")
		})
	}
}

func TestAccessLabelMoveBindingTargetsFinalTTLAndBudget(t *testing.T) {
	at := time.Unix(123456, 0)
	expires := at.Add(time.Second)
	ref := domain.ResourceRef{Type: "iam.project", ID: "p"}
	census := accessLabelMoveTargetCensus{
		{carrier: accessLabelSelectorMoveCarrier{Binding: domain.AccessBinding{Status: domain.AccessBindingStatusActive, ExpiresAt: &expires}}, targets: map[domain.ResourceRef][]int{ref: {0, 1}}},
		{carrier: accessLabelSelectorMoveCarrier{Binding: domain.AccessBinding{Status: domain.AccessBindingStatusPending}}, targets: map[domain.ResourceRef][]int{ref: {1}}},
	}
	budget := &relverdict.AdministrativeReadBudget{}
	targets, err := census.targetsAt(t.Context(), at, budget)
	require.NoError(t, err)
	require.Equal(t, []int{0, 1}, targets[ref])
	targets, err = census.targetsAt(t.Context(), expires, budget)
	require.NoError(t, err)
	require.Equal(t, []int{1}, targets[ref], "ожидающая выдача сохраняет выбор без действующего права")
	require.False(t, census[1].carrier.activeAt(expires))
	require.NoError(t, budget.Charge(budget.RemainingRows(), 0))
	targets, err = census.targetsAt(t.Context(), at, budget)
	require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit)
	require.Nil(t, targets)
}
