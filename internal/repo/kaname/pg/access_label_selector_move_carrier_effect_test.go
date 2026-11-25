// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveCarrierCandidatesExpandNestedFiniteTargetAfterCopy(t *testing.T) {
	const parentType, childType = "registry.registries", "registry.repositories"
	parent := domain.ResourceRef{Type: parentType, ID: "partial-root"}
	child := domain.ResourceRef{Type: childType, ID: "new-child"}
	ledger := domain.ResourceRef{Type: childType, ID: "old-ledger-entry"}
	account := domain.ResourceRef{Type: "iam.account", ID: "acc-move"}
	parentLabels := map[string]string{"team": "red", "zone": "west"}
	zone := map[string]string{"zone": "west"}
	childLabels := map[string]string{"stage": "prod"}
	role := domain.Role{ID: "rol-move", AccountID: domain.AccountID(account.ID), Rules: domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"update"}, MatchLabels: parentLabels,
			Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}, MatchAccessLabels: childLabels}}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, MatchLabels: zone},
	}}
	policy := domain.PolicyOfRole(false, "")
	proposed, moves, err := role.Rules.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{
		{RuleIndex: 0, Fingerprint: role.Rules[0].Fingerprint()},
		{RuleIndex: 1, Fingerprint: role.Rules[1].Fingerprint()},
	}, policy, domain.ModuleSetOf("registry"))
	require.NoError(t, err)
	require.Len(t, proposed.MaterializingSelectors(), 3)

	for _, status := range []domain.AccessBindingStatus{domain.AccessBindingStatusActive, domain.AccessBindingStatusPending} {
		t.Run(string(status), func(t *testing.T) {
			p := parentCaptureFixture(t)
			target := domain.AccessTarget{Resources: []domain.ResourceRef{parent}}
			subject := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-move"}
			binding := domain.AccessBinding{ID: "acb-move", RoleID: role.ID, Scope: domain.ScopeAccount,
				ResourceType: "account", ResourceID: account.ID, Target: target, Status: status, CreatedAt: time.Unix(123456, 0),
				SubjectType: subject.Type, SubjectID: subject.ID, Subjects: []domain.Subject{subject}}
			before := reconcile.BindingScope{BindingID: binding.ID, RoleID: string(role.ID), Scope: scopeAnchorFor(binding),
				Target: target, Subjects: binding.Subjects, Policy: policy, Active: status == domain.AccessBindingStatusActive,
				Selectors: role.Rules.MaterializingSelectorsInScope(binding.Scope)}
			after := before
			after.Selectors = proposed.MaterializingSelectorsInScope(binding.Scope)
			object := func(ref domain.ResourceRef, labels, accessLabels map[string]string) {
				t.Helper()
				parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: ref.Type, id: ref.ID}, map[string]any{
					"object_type": ref.Type, "object_id": ref.ID, "parent_account_id": account.ID, "labels": labels, "access_labels": accessLabels,
				})
			}
			object(parent, zone, map[string]string{"team": "red"})
			object(child, nil, childLabels)

			sourceRows := func(kind resourceSourceKind, typ string, predicate any, refs ...domain.ResourceRef) {
				t.Helper()
				raw, err := json.Marshal(predicate)
				require.NoError(t, err)
				rows := make([]any, 0, len(refs))
				for _, ref := range refs {
					rows = append(rows, map[string]string{"object_type": ref.Type, "object_id": ref.ID})
				}
				parentCaptureRows(t, p, resourceSourceKey{kind: kind, typ: typ, id: string(binding.ID), projection: string(raw)}, rows...)
			}
			for i, scope := range []reconcile.BindingScope{before, after} {
				kind := resourceSourceSelectorObjects
				if i == 1 {
					kind = resourceSourceRoleProposedSelectorObjects
				}
				for _, selector := range scope.Selectors {
					owner := selector
					if selector.Container != nil {
						var err error
						owner, err = reconcile.CapturedNestedOwnerSelector(selector)
						require.NoError(t, err)
					}
					predicate := resourceSelectorPredicate{RuleFP: selector.RuleFP, Container: selector.Container != nil,
						Arm: owner.Arm, Targets: []string{parent.ID}, Labels: owner.MatchLabels, Scope: scope.Scope, AccessLabels: owner.MatchAccessLabels}
					var matches []domain.ResourceRef
					if owner.Arm == domain.ArmLabels && len(owner.MatchLabels) == 1 {
						matches = append(matches, parent)
					}
					sourceRows(kind, parentType, predicate, matches...)
				}
			}
			// Only the independent zone selector matches the snapshot. Its copy
			// completes the protected owner predicate of the other moved rule.
			nested := after.Selectors[1]
			require.NotNil(t, nested.Container)
			sourceRows(resourceSourceRoleProposedNestedDescendants, childType, resourceNestedPredicate{
				RuleFP: nested.RuleFP, ContainerType: parentType, ContainerIDs: []string{parent.ID},
			}, child)

			carrier := accessLabelSelectorMoveCarrier{Binding: binding, Coordinates: map[domain.ResourceRef]bool{ledger: true}}
			coordinates := map[domain.ResourceRef]bool{ledger: true}
			require.NoError(t, p.captureBindingDiffScope(t.Context(), nil, coordinates, before, resourceSourceSelectorObjects))
			require.NoError(t, p.captureBindingDiffScope(t.Context(), nil, coordinates, after, resourceSourceRoleProposedSelectorObjects))
			keys, err := p.finishBindingDiffKeys(t.Context(), coordinates)
			require.NoError(t, err)
			require.ElementsMatch(t, []domain.ResourceRef{account, parent, ledger}, keys)
			captured := accessLabelSelectorMoveCapture{Before: role, ProposedRules: proposed, Moves: moves,
				Carriers: []accessLabelSelectorMoveScope{{Carrier: carrier, Before: before, Proposed: after, Coordinates: keys}}}
			captured.BindingTargets, err = p.captureAccessLabelMoveBindingTargets(t.Context(), captured)
			require.NoError(t, err)
			require.Len(t, captured.BindingTargets, 1)
			require.Equal(t, map[domain.ResourceRef][]int{parent: {1}}, captured.BindingTargets[0].targets)

			overlay, err := p.captureAccessLabelMoveCarrierCandidates(t.Context(), captured)
			require.NoError(t, err)
			require.Len(t, overlay, 1)
			require.Equal(t, parentLabels, overlay[parent].AccessLabels)
			require.ElementsMatch(t, []domain.ResourceRef{account, parent, child, ledger}, captured.Carriers[0].Coordinates)
			require.Equal(t, map[domain.ResourceRef][]int{parent: {1}}, captured.BindingTargets[0].targets)
			for key := range p.source.entries {
				if key.kind != resourceSourceRoleProposedNestedDescendants {
					continue
				}
				guard, err := classifyAccessLabelMoveProposedPredicate(key, after)
				require.NoError(t, err)
				require.Equal(t, []domain.ResourceRef{parent}, guard.Children)
				_, err = classifyAccessLabelMoveProposedPredicate(key, before)
				require.Error(t, err, "исходная редакция не удостоверяет предложенный fingerprint")
			}
		})
	}
}
