// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"maps"
)

// MaxAccessLabelSelectorMoves ограничивает число позиций переноса в одной роли.
const MaxAccessLabelSelectorMoves = MaxRules * (maxChildren + 1)

// AccessLabelSelectorMove указывает правило или его ребёнка в прочитанной
// версии роли. Позиции отсчитываются от нуля. При ChildIndex == nil выбран
// селектор родительского правила. Fingerprint относится к выбранному правилу.
type AccessLabelSelectorMove struct {
	RuleIndex   int
	ChildIndex  *int
	Fingerprint string
}

// ValidatedAccessLabelSelectorMove хранит исходный предикат выбранного правила
// независимо от предложенной версии роли.
type ValidatedAccessLabelSelectorMove struct {
	ruleIndex  int
	childIndex int
	selector   RuleSelector
}

// Position возвращает исходные позиции. Для правила верхнего уровня позиция
// ребёнка равна -1.
func (m ValidatedAccessLabelSelectorMove) Position() (ruleIndex, childIndex int) {
	return m.ruleIndex, m.childIndex
}

// MatchesObject проверяет тип и собственные обычные метки объекта. Для
// переноса родительского предиката передаётся сам контейнер, для переноса
// дочернего предиката — сам ребёнок. Цель выдачи и связь с контейнером
// подтверждает вызывающий путь.
func (m ValidatedAccessLabelSelectorMove) MatchesObject(object MirrorObject) bool {
	return m.selector.MatchesObject(object)
}

// CopyAccessLabels предлагает полную карту меток доступа после копирования
// выбранных пар из удержанного объекта. Флаг показывает, добавились ли пары.
// При конфликте исходное значение метки доступа сохраняется и перенос
// отклоняется. Переданная карта остаётся целой при любом результате.
func (m ValidatedAccessLabelSelectorMove) CopyAccessLabels(object MirrorObject) (map[string]string, bool, error) {
	if !m.MatchesObject(object) {
		return nil, false, nil
	}
	changed := false
	for key := range m.selector.MatchLabels {
		value, exists := object.AccessLabels[key]
		if exists && value != object.Labels[key] {
			return nil, false, fmt.Errorf("conflicting access label at rule %d, child %d", m.ruleIndex, m.childIndex)
		}
		changed = changed || !exists
	}
	if !changed {
		return nil, false, nil
	}

	merged := make(Labels, len(object.AccessLabels)+len(m.selector.MatchLabels))
	for key, value := range object.AccessLabels {
		merged[LabelKey(key)] = LabelVal(value)
	}
	for key := range m.selector.MatchLabels {
		merged[LabelKey(key)] = LabelVal(object.Labels[key])
	}
	if err := merged.Validate(); err != nil {
		return nil, false, err
	}
	accessLabels := make(map[string]string, len(merged))
	for key, value := range merged {
		accessLabels[string(key)] = string(value)
	}
	return accessLabels, true, nil
}

// MoveAccessLabelSelectors строит предложенное содержимое роли из прежних
// правил. Выбранные matchLabels целиком переходят в matchAccessLabels.
// Перед записью владелец транзакции сверяет версию роли, полноту исходных
// данных и разницу фактических прав, включая наследование от контейнера.
func (rs Rules) MoveAccessLabelSelectors(moves []AccessLabelSelectorMove, policy RulePolicy, modules ModuleSet) (Rules, error) {
	next, _, err := rs.PlanAccessLabelSelectorMoves(moves, policy, modules)
	return next, err
}

// PlanAccessLabelSelectorMoves строит предложенное содержимое роли и извлекает
// исходные предикаты из тех же проверенных позиций. Порядок соответствует moves.
func (rs Rules) PlanAccessLabelSelectorMoves(moves []AccessLabelSelectorMove, policy RulePolicy, modules ModuleSet) (Rules, []ValidatedAccessLabelSelectorMove, error) {
	if len(rs) == 0 || len(rs) > MaxRules || len(moves) == 0 || len(moves) > len(rs)*(maxChildren+1) {
		return nil, nil, fmt.Errorf("Illegal argument: invalid number of rules or access label selector moves")
	}

	if err := rs.Validate(policy, modules); err != nil {
		return nil, nil, err
	}

	next := make(Rules, len(rs))
	for i, r := range rs {
		next[i] = cloneGrantRule(r)
	}

	type position struct {
		rule, child int
	}
	seen := make(map[position]bool, len(moves))
	validated := make([]ValidatedAccessLabelSelectorMove, 0, len(moves))
	for _, move := range moves {
		if move.RuleIndex < 0 || move.RuleIndex >= len(rs) {
			return nil, nil, fmt.Errorf("Illegal argument: rule index %d is out of range", move.RuleIndex)
		}

		pos := position{rule: move.RuleIndex, child: -1}
		current, changed := &rs[pos.rule], &next[pos.rule]
		if move.ChildIndex != nil {
			pos.child = *move.ChildIndex
			if pos.child < 0 || pos.child >= len(current.Children) {
				return nil, nil, fmt.Errorf("Illegal argument: child index %d of rule %d is out of range", pos.child, pos.rule)
			}
			current, changed = &current.Children[pos.child], &changed.Children[pos.child]
		}

		if seen[pos] {
			return nil, nil, fmt.Errorf("Illegal argument: duplicate access label selector move at rule %d, child %d", pos.rule, pos.child)
		}
		seen[pos] = true
		if current.Fingerprint() != move.Fingerprint {
			return nil, nil, fmt.Errorf("Illegal argument: access label selector changed at rule %d, child %d", pos.rule, pos.child)
		}
		if len(current.MatchLabels) == 0 {
			return nil, nil, fmt.Errorf("Illegal argument: rule %d, child %d must have only a matchLabels selector", pos.rule, pos.child)
		}

		effective := *current
		effective.Module = rs[pos.rule].Module
		validated = append(validated, ValidatedAccessLabelSelectorMove{
			ruleIndex: pos.rule, childIndex: pos.child,
			selector: RuleSelector{Arm: ArmLabels, ObjectTypes: dottedTypes(effective, false), MatchLabels: maps.Clone(current.MatchLabels)},
		})
		changed.MatchAccessLabels = changed.MatchLabels
		changed.MatchLabels = nil
	}
	if err := next.Validate(policy, modules); err != nil {
		return nil, nil, err
	}
	return next, validated, nil
}
