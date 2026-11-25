// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveDefinitionCandidatesUseProposedOwnersAndCopies(t *testing.T) {
	const registry, repo = "registry.registries", "registry.repositories"
	rootFilter := map[string]string{"team": "red", "zone": "west"}
	childFilter := map[string]string{"stage": "prod"}
	zone := map[string]string{"zone": "west"}
	role := domain.Role{ID: "rol-move", AccountID: "acc-move", Rules: domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"update"}, MatchLabels: rootFilter,
			Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}, MatchLabels: childFilter}}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, MatchLabels: zone},
	}}
	child := 0
	proposed, moves, err := role.Rules.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{
		{RuleIndex: 0, Fingerprint: role.Rules[0].Fingerprint()},
		{RuleIndex: 0, ChildIndex: &child, Fingerprint: role.Rules[0].Children[0].Fingerprint()},
		{RuleIndex: 1, Fingerprint: role.Rules[1].Fingerprint()},
	}, domain.PolicyOfRole(false, ""), domain.ModuleSetOf("registry"))
	require.NoError(t, err)
	captured := accessLabelSelectorMoveCapture{Before: role, ProposedRules: proposed, Moves: moves}
	old := map[domain.ResourceRef][]int{
		{Type: registry, ID: "old-root"}: {0, 2}, {Type: registry, ID: "partial-root"}: {2},
		{Type: registry, ID: "zone-only"}: {2}, {Type: repo, ID: "old-child"}: {1},
	}
	p := parentCaptureFixture(t)
	scope := reconcile.BindingScope{Scope: domain.ScopeAnchor{Type: "account", ID: string(role.AccountID)}, Target: domain.AccessTarget{AllInScope: true}}
	object := func(typ, id string, labels, protected map[string]string) {
		t.Helper()
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: typ, id: id}, map[string]any{
			"object_type": typ, "object_id": id, "parent_account_id": scope.Scope.ID, "labels": labels, "access_labels": protected,
		})
	}
	object(registry, "old-root", rootFilter, nil)
	object(registry, "protected-root", nil, rootFilter)
	object(registry, "partial-root", zone, map[string]string{"team": "red"})
	object(registry, "zone-only", zone, nil)
	object(repo, "old-child", childFilter, nil)
	object(repo, "child-of-protected", nil, childFilter)
	object(repo, "child-of-partial", nil, childFilter)
	// Без ранее опубликованного FP предложенные предикаты всё равно обязаны
	// увидеть объекты. В fixture для старых FP результата запроса нет.
	sourceRows := func(kind resourceSourceKind, typ string, predicate any, ids ...string) {
		t.Helper()
		raw, err := json.Marshal(predicate)
		require.NoError(t, err)
		var rows []any
		for _, id := range ids {
			rows = append(rows, map[string]string{"object_type": typ, "object_id": id})
		}
		parentCaptureRows(t, p, resourceSourceKey{kind: kind, typ: typ, id: string(role.ID), projection: string(raw)}, rows...)
	}
	selectors := proposed.MaterializingSelectors()
	for _, selector := range selectors {
		protected := selector.MatchAccessLabels
		if selector.Container != nil {
			protected = selector.Container.MatchAccessLabels
		}
		sourceRows(resourceSourceRoleSelectorObjects, registry, resourceSelectorPredicate{RuleFP: selector.RuleFP, Arm: domain.ArmAccessLabels,
			Container: selector.Container != nil, AccessLabels: protected, Targets: []string{}, Scope: scope.Scope}, "protected-root")
	}
	// Защищённая половина предиката у partial-root существовала ДО переноса,
	// недостающую половину добавляет другой перенос. zone-only такого охвата не даёт.
	sourceRows(resourceSourceRoleNestedDescendants, repo, resourceNestedPredicate{RuleFP: selectors[1].RuleFP, ContainerType: registry,
		ContainerIDs: []string{"old-root", "partial-root", "protected-root"}, Scope: &scope.Scope}, "old-child", "child-of-partial", "child-of-protected")

	candidates, err := p.captureAccessLabelMoveDefinitionCandidates(t.Context(), captured, scope, old)
	require.NoError(t, err)
	require.Equal(t, []domain.ResourceRef{
		{Type: registry, ID: "old-root"}, {Type: registry, ID: "partial-root"}, {Type: registry, ID: "protected-root"}, {Type: registry, ID: "zone-only"},
		{Type: repo, ID: "child-of-partial"}, {Type: repo, ID: "child-of-protected"}, {Type: repo, ID: "old-child"},
	}, candidates)
	require.NotContains(t, old, domain.ResourceRef{Type: registry, ID: "protected-root"})
	require.NotContains(t, old, domain.ResourceRef{Type: repo, ID: "child-of-partial"})

	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: repo, id: "child-of-partial"}, map[string]any{
		"object_type": repo, "object_id": "child-of-partial", "parent_account_id": "acc-other", "access_labels": childFilter,
	})
	_, err = p.captureAccessLabelMoveDefinitionCandidates(t.Context(), captured, scope, old)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}
