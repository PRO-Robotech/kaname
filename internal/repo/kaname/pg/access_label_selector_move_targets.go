// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Кандидаты одной выдачи нужны отдельно до финальных часов: TTL может
// закончиться во время ожидания, а другая выдача всё ещё выбирать тот же объект.
type accessLabelMoveBindingTargets struct {
	carrier accessLabelSelectorMoveCarrier
	targets map[domain.ResourceRef][]int
}

type accessLabelMoveTargetCensus []accessLabelMoveBindingTargets

// captureAccessLabelMoveBindingTargets снимает OLD-предикаты существующих
// выдач роли. Даже пустой набор получателей или потомков не отменяет чтение
// предиката. Для роли без выдач этот источник пуст: поиск по области самих
// определений меток требует отдельного проверяемого источника владельца роли.
func (p *resourceParentCapture) captureAccessLabelMoveBindingTargets(
	ctx context.Context, captured accessLabelSelectorMoveCapture,
) (accessLabelMoveTargetCensus, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil ||
		captured.Before.ID == "" || len(captured.Moves) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	budget := p.source.budget
	if err := budget.Charge(len(captured.Moves)+len(captured.Carriers), 0); err != nil {
		return nil, err
	}

	requested, err := accessLabelMoveSelectors(captured, budget)
	if err != nil {
		return nil, err
	}

	census := make(accessLabelMoveTargetCensus, 0, len(captured.Carriers))
	for _, scope := range captured.Carriers {
		bs, binding := scope.Before, scope.Carrier.Binding
		if bs.BindingID != binding.ID || binding.RoleID != captured.Before.ID || bs.RoleID != string(binding.RoleID) ||
			bs.Scope != scopeAnchorFor(binding) || bs.Target.Digest() != binding.Target.Digest() ||
			bs.Active != (binding.Status == domain.AccessBindingStatusActive) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if !scope.Carrier.canSelect() {
			continue
		}
		if err := budget.Charge(len(bs.Selectors)+len(requested), 0); err != nil {
			return nil, err
		}
		old := make(map[string]domain.RuleSelector, len(bs.Selectors))
		for _, selector := range bs.Selectors {
			old[selector.RuleFP] = selector
		}
		entry := accessLabelMoveBindingTargets{carrier: scope.Carrier, targets: make(map[domain.ResourceRef][]int)}
		source := resourceSourceKey{kind: resourceSourceSelectorObjects, id: string(bs.BindingID)}
		for i, selected := range requested {
			selector, ok := old[selected.RuleFP]
			if !ok || selector.Arm != domain.ArmLabels {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err := p.addAccessLabelMoveTargets(ctx, source, bs, selector, captured.Moves[i], i, entry.targets); err != nil {
				return nil, err
			}
		}
		census = append(census, entry)
	}
	return census, ctx.Err()
}

// У ребёнка свой authored fingerprint, но хранимый ключ включает
// fingerprint владельца. Строим проекцию по исходной позиции правила.
func accessLabelMoveSelectors(captured accessLabelSelectorMoveCapture, budget *relverdict.AdministrativeReadBudget) ([]domain.RuleSelector, error) {
	selectors := make([]domain.RuleSelector, 0, len(captured.Moves))
	for _, move := range captured.Moves {
		rule, child := move.Position()
		if rule < 0 || rule >= len(captured.Before.Rules) || child < -1 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		owner := captured.Before.Rules[rule]
		if err := budget.Charge(1+len(owner.Children), 0); err != nil {
			return nil, err
		}
		layout := domain.Rules{owner}.MaterializingSelectors()
		if child >= len(layout)-1 || layout[child+1].Arm != domain.ArmLabels {
			return nil, kaname.ErrSourceUnconfirmed
		}
		selectors = append(selectors, layout[child+1])
	}
	return selectors, nil
}

func (p *resourceParentCapture) addAccessLabelMoveTargets(
	ctx context.Context, source resourceSourceKey, scope reconcile.BindingScope, selector domain.RuleSelector,
	move domain.ValidatedAccessLabelSelectorMove, index int, targets map[domain.ResourceRef][]int,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var candidates []domain.MirrorObject
	var err error
	if selector.Container == nil {
		candidates, err = p.captureSelectorFrom(ctx, source, selector, scope.Scope, scope.Target, selector.RuleFP, false)
	} else {
		candidates, err = p.captureNestedCandidatesFrom(ctx, source, scope, selector, false)
	}
	if err != nil {
		return err
	}
	if err = p.source.budget.Charge(len(candidates), 0); err != nil {
		return err
	}
	roleOwned := source.kind == resourceSourceRoleSelectorObjects
	for _, object := range candidates {
		if source.kind == resourceSourceSelectorObjects && selector.Container != nil &&
			selector.Container.Type == "iam.account" && object.ObjectType == "iam.project" {
			// Существующая выдача использует обычный ключ захвата даже при переносе.
			object, err = p.captureNestedProjectShape(ctx, object)
			if err != nil {
				return err
			}
		}
		if !object.IsContainedIn(scope.Scope) {
			if roleOwned {
				return kaname.ErrSourceUnconfirmed
			}
			continue
		}
		if !move.MatchesObject(object) {
			continue
		}
		if roleOwned {
			if err = p.confirmAccessLabelMoveDefinitionProject(ctx, object); err != nil {
				return err
			}
		}
		if selector.Container != nil {
			if err = p.confirmAccessLabelMoveAncestor(ctx, scope, selector, object, roleOwned); err != nil {
				return err
			}
		}
		ref := domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}
		indices := targets[ref]
		if len(indices) == 0 || indices[len(indices)-1] != index {
			targets[ref] = append(indices, index)
		}
	}
	return ctx.Err()
}

// Потомок взят из прямого запроса по выбранным контейнерам. Обратный обход
// удерживает фактического предка, включая его OLD-метки и границы выдачи.
func (p *resourceParentCapture) confirmAccessLabelMoveAncestor(
	ctx context.Context, bs reconcile.BindingScope, selector domain.RuleSelector, object domain.MirrorObject, roleOwned bool,
) error {
	var ancestors []domain.MirrorObject
	if object.ObjectType == domain.ScopeTypeProjectDotted && selector.Container != nil && selector.Container.Type == domain.ScopeTypeAccountDotted {
		graph, err := p.captureProjectObjectGraph(ctx, object.ObjectID)
		if err != nil {
			return err
		}
		ancestors = graph.Ancestors
	} else {
		var err error
		ancestors, err = p.captureObjectAncestors(ctx, object.ObjectType, object.ObjectID, true)
		if err != nil {
			return err
		}
	}
	if err := p.source.budget.Charge(len(ancestors), 0); err != nil {
		return err
	}
	for _, ancestor := range ancestors {
		selected, err := reconcile.CapturedNestedContainerSelected(selector, bs, ancestor)
		if err != nil {
			return err
		}
		if selected {
			if roleOwned {
				return p.confirmAccessLabelMoveDefinitionProject(ctx, ancestor)
			}
			return nil
		}
	}
	return kaname.ErrSourceUnconfirmed
}

// targetsAt объединяет цели действующих и ожидающих выдач с учётом срока.
// Этот результат сам по себе не разрешает запись защищённых меток.
func (c accessLabelMoveTargetCensus) targetsAt(
	ctx context.Context, at time.Time, budget *relverdict.AdministrativeReadBudget,
) (map[domain.ResourceRef][]int, error) {
	if c == nil || at.IsZero() || budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var result map[domain.ResourceRef][]int
	for _, entry := range c {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.carrier.canSelectAt(at) {
			continue
		}
		if result == nil {
			result = make(map[domain.ResourceRef][]int)
		}
		for key, indices := range entry.targets {
			if err := budget.Charge(1+len(indices), 0); err != nil {
				return nil, err
			}
			result[key] = append(result[key], indices...)
		}
	}
	for key, indices := range result {
		slices.Sort(indices)
		result[key] = slices.Compact(indices)
	}
	return result, ctx.Err()
}
