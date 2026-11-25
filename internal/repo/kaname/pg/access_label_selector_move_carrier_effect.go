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

// Множество для поиска кандидатов включает все копии, которые могут остаться
// после проверки срока. Полную допустимость и фактическое изменение меток
// определяет planAccessLabelMoveCopies на наборе с итоговым decision_at.
func (p *resourceParentCapture) captureAccessLabelMovePotentialOverlay(
	ctx context.Context, moves []domain.ValidatedAccessLabelSelectorMove, targets map[domain.ResourceRef][]int,
) (map[domain.ResourceRef]domain.MirrorObject, error) {
	result := make(map[domain.ResourceRef]domain.MirrorObject)
	for _, key := range sortedRefs(slices.Collect(maps.Keys(targets))) {
		indices := targets[key]
		if err := p.source.budget.Charge(1+len(indices), 0); err != nil {
			return nil, err
		}
		graph, err := p.captureAccessLabelMoveCopyGraph(ctx, key, moves, indices)
		if err != nil {
			return nil, err
		}
		object := graph.Object
		var potential map[string]string
		for _, i := range indices {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			scratch, err := accessLabelMoveCopySource(moves[i], graph)
			if err != nil {
				return nil, err
			}
			scratch.AccessLabels = nil
			pairs, _, err := moves[i].CopyAccessLabels(scratch)
			if err != nil {
				return nil, err
			}
			if err = p.source.budget.Charge(len(pairs), 0); err != nil {
				return nil, err
			}
			for k, v := range pairs {
				if _, exists := object.AccessLabels[k]; exists {
					continue
				}
				if potential == nil {
					potential = make(map[string]string, len(object.AccessLabels)+len(pairs))
					maps.Copy(potential, object.AccessLabels)
				}
				if prior, set := potential[k]; set && prior != v {
					// В общей предварительной карте конфликт нельзя скрыть
					// порядком обхода. Финальный набор учитывает истечение выдач.
					return nil, kaname.ErrAuthorityClassificationChanged
				}
				potential[k] = v
			}
		}
		if potential != nil {
			object.AccessLabels = potential
			result[key] = object
		}
	}
	return result, ctx.Err()
}

// Привязку проверяем с копиями со всех исходных областей, а не только с её
// собственными. Ребёнка доснимаем по реальному контейнеру, который стал
// подходить после добавления ключей в accessLabels.
func (p *resourceParentCapture) captureAccessLabelMoveCarrierCandidates(
	ctx context.Context, captured accessLabelSelectorMoveCapture,
) (map[domain.ResourceRef]domain.MirrorObject, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || captured.Before.ID == "" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	budget := p.source.budget
	targets := make(map[domain.ResourceRef][]int)
	for _, binding := range captured.BindingTargets {
		for key, indices := range binding.targets {
			if err := budget.Charge(1+len(indices), 0); err != nil {
				return nil, err
			}
			targets[key] = append(targets[key], indices...)
		}
	}
	for key, indices := range targets {
		slices.Sort(indices)
		targets[key] = slices.Compact(indices)
	}
	overlay, err := p.captureAccessLabelMovePotentialOverlay(ctx, captured.Moves, targets)
	if err != nil || len(overlay) == 0 {
		return overlay, err
	}
	byType := make(map[string][]domain.MirrorObject)
	for key, object := range overlay {
		byType[key.Type] = append(byType[key.Type], object)
	}
	for i := range captured.Carriers {
		entry := &captured.Carriers[i]
		if !entry.Carrier.canSelect() ||
			(!captured.targetsSnapshotAt.IsZero() && !entry.Carrier.canSelectAt(captured.targetsSnapshotAt)) {
			continue
		}
		scope := entry.Proposed
		if scope.BindingID != entry.Carrier.Binding.ID || scope.RoleID != string(captured.Before.ID) ||
			scope.Scope != scopeAnchorFor(entry.Carrier.Binding) || scope.Target.Digest() != entry.Carrier.Binding.Target.Digest() {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err = budget.Charge(len(scope.Selectors)+len(entry.Coordinates), 0); err != nil {
			return nil, err
		}
		extra, err := p.captureAccessLabelMoveCarrierOverlay(ctx, scope, byType)
		if err != nil {
			return nil, err
		}
		entry.Coordinates = sortedRefs(append(slices.Clone(entry.Coordinates), extra...))
	}
	return overlay, ctx.Err()
}

func (p *resourceParentCapture) captureAccessLabelMoveCarrierOverlay(
	ctx context.Context, scope reconcile.BindingScope, byType map[string][]domain.MirrorObject,
) ([]domain.ResourceRef, error) {
	source := resourceSourceKey{kind: resourceSourceRoleProposedSelectorObjects, id: string(scope.BindingID)}
	budget := p.source.budget
	var extra []domain.ResourceRef
	for _, selector := range scope.Selectors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if selector.Container == nil {
			if selector.Arm != domain.ArmAccessLabels {
				continue
			}
			perObject := len(scope.Target.Resources) > 0
			for _, typ := range selector.ObjectTypes {
				objects := byType[typ]
				if err := budget.Charge(len(objects), 0); err != nil {
					return nil, err
				}
				for _, object := range objects {
					// Совпадение вне области тоже входит в полный проход:
					// materializer выводит для него REJECTED и аудит.
					if (!perObject || scope.Target.Contains(object.ObjectType, object.ObjectID)) && selector.MatchesObject(object) {
						extra = append(extra, domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID})
					}
				}
			}
			continue
		}
		if selector.Container.Arm != domain.ArmAccessLabels {
			continue
		}
		objects := byType[selector.Container.Type]
		if err := budget.Charge(len(objects), 0); err != nil {
			return nil, err
		}
		var owners []string
		for _, object := range objects {
			selected, err := reconcile.CapturedNestedContainerSelected(selector, scope, object)
			if err != nil {
				return nil, err
			}
			if selected {
				owners = append(owners, object.ObjectID)
				extra = append(extra, domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID})
			}
		}
		children, err := p.captureNestedDescendantsFrom(ctx, source, scope, selector, owners)
		if err != nil {
			return nil, err
		}
		if err = budget.Charge(len(children), 0); err != nil {
			return nil, err
		}
		for _, child := range children {
			extra = append(extra, domain.ResourceRef{Type: child.ObjectType, ID: child.ObjectID})
		}
	}
	return extra, ctx.Err()
}
