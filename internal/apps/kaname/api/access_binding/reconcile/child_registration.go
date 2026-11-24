// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// childRegistrationParents выбирает родителей до появления первого ребёнка.
// Решение о кортежах остаётся у того же чистого compiler, что у события объекта;
// здесь добавлены только ограниченный отбор и подтверждение живости под замком.
func (r *Reconciler) childRegistrationParents(ctx context.Context, s ReconcileStore, cat *catalog.Facts, bs BindingScope, sel domain.RuleSelector) ([]DesiredMember, error) {
	if len(cat.ChildRegistrationActions(sel)) == 0 {
		return nil, nil
	}
	human := false
	for _, subject := range bs.Subjects {
		if subject.Type == domain.SubjectTypeUser {
			human = true
			break
		}
	}
	if !human {
		return nil, nil
	}
	lookup := ownerSelectorOf(sel)
	// Пообъектная цель ограничивает чтение своими ID даже при метках владельца.
	// Без цели метки проверяем после чтения области: глобального поиска по
	// меткам всех арендаторов для права регистрации здесь нет.
	if len(bs.Target.Resources) > 0 || lookup.Arm == domain.ArmLabels {
		lookup.Arm = domain.ArmAnchor
		lookup.ResourceNames = nil
		lookup.MatchLabels = nil
	}
	parents, err := r.matchSelectorObjects(ctx, s, lookup, bs.Scope, bs.Target)
	if err != nil {
		return nil, fmt.Errorf("match registration parents %s: %w", sel.RuleFP, err)
	}
	selected := make([]domain.MirrorObject, 0, len(parents))
	coordinates := make([]MemberCoord, 0, len(parents))
	seen := make(map[MemberCoord]bool, len(parents))
	for _, parent := range parents {
		coordinate := MemberCoord{ObjectType: parent.ObjectType, ObjectID: parent.ObjectID}
		if !seen[coordinate] && containerSelected(sel, bs, parent) {
			seen[coordinate] = true
			selected = append(selected, parent)
			coordinates = append(coordinates, coordinate)
		}
	}
	live, err := liveObjects(ctx, s, coordinates)
	if err != nil {
		return nil, fmt.Errorf("lock registration parents %s: %w", sel.RuleFP, err)
	}
	// В полном проходе соседние правила обрабатываются отдельно. Отдаём compiler
	// ровно этот селектор и сохраняем лишь его родительский вклад: повторной
	// выдачи обычных прав и scope-self от этого обхода нет.
	selectedBinding := bs
	selectedBinding.Selectors = []domain.RuleSelector{sel}
	selectedBinding.ScopeSelfVerbs = nil
	var out []DesiredMember
	for _, parent := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !live(MemberCoord{ObjectType: parent.ObjectType, ObjectID: parent.ObjectID}) {
			continue
		}
		members, err := desiredMembersForObject(cat, selectedBinding, parent, nil)
		if err != nil {
			return nil, fmt.Errorf("compile registration parent %s: %w", sel.RuleFP, err)
		}
		for _, member := range members {
			if member.Derivation == "child_registration" && member.RuleFP == sel.RuleFP {
				out = append(out, member)
			}
		}
	}
	return out, nil
}
