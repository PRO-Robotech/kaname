// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// nested.go — разворачивание выдачи с ВЛОЖЕННЫМ правилом роли (kaname#874,
// приёмка docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, Р3, Р5).
//
// # Та же семантика, что у решения
//
// Селектор вложенного правила (`RuleSelector.Container` непуст) охватывает
// объект своего типа, когда среди его предков есть контейнер, ВЫБРАННЫЙ выдачей:
// он проходит ветвь правила-владельца (якорь, имена, метки), входит в цель
// выдачи (назван ею либо цель — вся область) и лежит в области выдачи. Ровно
// это же спрашивает предикат ветви выдач решения (`relverdict/grantarm.go`), и
// материализованное множество обязано совпадать с ответом решения (ND-02).
//
// Два пути, одно суждение:
//   - полный проход выдачи: контейнеры выбираются тем же отбором, что объекты
//     правила верхнего уровня (`matchSelectorObjects` — цель, ветвь, область),
//     затем их потомки нужного типа читаются индексом рёбер по предку;
//   - путь по объекту (регистрация, перенос, смена меток): предки объекта
//     читаются один раз на проход, и контейнер ищется среди них тем же отбором
//     в форме Go (`selectorMatchesObject`).
//
// # Классу — не применяется
//
// Выдаче СИСТЕМНОМУ КЛАССУ вложенное правило членов `v_*` на потомках не даёт
// (Р5, ND-10): у класса одна дорога к потомкам — `public_reader` объявленного
// контейнера, и снятие объявления обязано снимать чтение. Вложенное правило у
// класса служит только основанием `public_reader` (public_reader.go).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// isClassBinding — субъект выдачи — системный класс.
func isClassBinding(bs BindingScope) bool {
	return bs.SubjectType == string(domain.SubjectTypeSystemClass)
}

// ownerSelectorOf — отбор правила-владельца вложенного селектора в форме
// селектора над типом контейнера.
func ownerSelectorOf(sel domain.RuleSelector) domain.RuleSelector {
	c := sel.Container
	return domain.RuleSelector{
		RuleFP:        c.OwnerFP,
		Arm:           c.Arm,
		ObjectTypes:   []string{c.Type},
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

// containerSelected — контейнер `a` выбран выдачей для вложенного селектора
// `sel`: его тип — тип владельца, он проходит ветвь владельца, входит в цель и
// лежит в области выдачи.
func containerSelected(sel domain.RuleSelector, bs BindingScope, a domain.MirrorObject) bool {
	if a.ObjectType != sel.Container.Type || !selectorMatchesObject(ownerSelectorOf(sel), a) {
		return false
	}
	if len(bs.Target.Resources) > 0 && !bs.Target.Contains(a.ObjectType, a.ObjectID) {
		return false
	}
	return a.IsContainedIn(bs.Scope)
}

// nestedCoversObject — путь по объекту: вложенный селектор охватывает объект `o`
// с предками `ancestors`.
func nestedCoversObject(sel domain.RuleSelector, bs BindingScope, o domain.MirrorObject, ancestors []domain.MirrorObject) bool {
	if isClassBinding(bs) || !selectorMatchesObject(sel, o) {
		return false
	}
	for _, a := range ancestors {
		if containerSelected(sel, bs, a) {
			return true
		}
	}
	return false
}

// matchNestedObjects — полный проход: объекты, которые вложенный селектор
// охватывает в выдаче `bs`.
func (r *Reconciler) matchNestedObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector, bs BindingScope) ([]domain.MirrorObject, error) {
	containers, err := r.matchSelectorObjects(ctx, s, ownerSelectorOf(sel), bs.Scope, bs.Target)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		if containerSelected(sel, bs, c) {
			ids = append(ids, c.ObjectID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	desc, err := s.MatchDescendants(ctx, sel.ObjectTypes, sel.Container.Type, ids)
	if err != nil {
		return nil, fmt.Errorf("match nested selector %s: %w", sel.RuleFP, err)
	}
	out := desc[:0:0]
	for _, o := range desc {
		// Своя ветвь вложенного правила (имена, метки) сужает поверх охвата.
		if selectorMatchesObject(sel, o) {
			out = append(out, o)
		}
	}
	return out, nil
}
