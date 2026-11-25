// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Область определения не имеет субъектов выдачи. Кандидаты включают совпадения
// предложенных селекторов и потомков выбранных контейнеров, независимо от
// GrantRecipients. Сами копии выводятся только из прежнего набора oldTargets.
func (p *resourceParentCapture) captureAccessLabelMoveDefinitionCandidates(
	ctx context.Context, captured accessLabelSelectorMoveCapture, scope reconcile.BindingScope, oldTargets map[domain.ResourceRef][]int,
) ([]domain.ResourceRef, error) {
	role := captured.Before
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || oldTargets == nil ||
		!nativeQuestionToken(string(role.ID)) || !scope.Target.AllInScope || len(scope.Target.Resources) != 0 ||
		len(captured.Moves) == 0 || len(captured.ProposedRules) != len(role.Rules) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	anchor, err := accessLabelMoveRoleScope(role)
	if err != nil || scope.Scope != anchor {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := p.source.budget.Charge(len(oldTargets)+len(captured.ProposedRules), 0); err != nil {
		return nil, err
	}
	coordinates := make(map[domain.ResourceRef]bool, len(oldTargets))
	confirm := func(object domain.MirrorObject) error {
		if !object.IsContainedIn(anchor) {
			return kaname.ErrSourceUnconfirmed
		}
		return p.confirmAccessLabelMoveDefinitionProject(ctx, object)
	}
	graphs := make(map[domain.ResourceRef]accessLabelMoveGraph, len(oldTargets))
	for ref, indices := range oldTargets {
		graph, err := p.captureAccessLabelMoveCopyGraph(ctx, ref, captured.Moves, indices)
		if err != nil {
			return nil, err
		}
		if err = confirm(graph.Object); err != nil {
			return nil, err
		}
		for _, index := range indices {
			source, err := accessLabelMoveCopySource(captured.Moves[index], graph)
			if err != nil {
				return nil, err
			}
			if source.ObjectType == domain.ScopeTypeProjectDotted && !source.IsContainedIn(anchor) {
				return nil, kaname.ErrSourceUnconfirmed
			}
		}
		graphs[ref] = graph
		coordinates[ref] = true
	}
	copyPlan, err := planAccessLabelMoveCopies(ctx, captured.Moves, oldTargets, graphs, p.source.budget)
	if err != nil {
		return nil, err
	}
	// Контейнер может получить недостающий ключ от ДРУГОГО переноса,
	// а остальными ключами защищённого предиката уже обладать в снимке.
	byType := make(map[string][]domain.MirrorObject)
	copies := copyPlan.labels
	for ref := range copies {
		byType[ref.Type] = append(byType[ref.Type], overlaySelectorMoveLabels(graphs[ref].Object, copies))
	}

	source := resourceSourceKey{kind: resourceSourceRoleSelectorObjects, id: string(role.ID)}
	for _, selector := range captured.ProposedRules.MaterializingSelectors() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if selector.Arm != domain.ArmAccessLabels && (selector.Container == nil || selector.Container.Arm != domain.ArmAccessLabels) {
			continue
		}
		predicate := selector
		if selector.Container != nil {
			predicate, err = reconcile.CapturedNestedOwnerSelector(selector)
			if err != nil {
				return nil, err
			}
		}
		objects, err := p.captureSelectorFrom(ctx, source, predicate, anchor, scope.Target, selector.RuleFP, selector.Container != nil)
		if err != nil {
			return nil, err
		}
		if err := p.source.budget.Charge(len(objects), 0); err != nil {
			return nil, err
		}
		var owners []string
		for _, object := range objects {
			if err := confirm(object); err != nil {
				return nil, err
			}
			if !predicate.MatchesObject(object) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			coordinates[domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}] = true
			if selector.Container != nil {
				owners = append(owners, object.ObjectID)
			}
		}
		if selector.Container == nil {
			continue
		}
		if predicate.Arm == domain.ArmAccessLabels {
			copied := byType[selector.Container.Type]
			if err := p.source.budget.Charge(len(copied), 0); err != nil {
				return nil, err
			}
			for _, object := range copied {
				if predicate.MatchesObject(object) {
					owners = append(owners, object.ObjectID)
				}
			}
		}
		descendants, err := p.captureNestedDescendantsFrom(ctx, source, scope, selector, owners)
		if err != nil {
			return nil, err
		}
		if err := p.source.budget.Charge(len(descendants), 0); err != nil {
			return nil, err
		}
		for _, object := range descendants {
			if err := confirm(object); err != nil {
				return nil, err
			}
			coordinates[domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}] = true
		}
	}
	return sortedRefs(slices.Collect(maps.Keys(coordinates))), ctx.Err()
}
