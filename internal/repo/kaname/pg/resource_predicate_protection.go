// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Классификация формы чтения предшествует coordinator. Найденные строки не
// определяют полноту: пустой NAMES всё равно защищает названные отсутствующие
// объекты, а пустой LABELS census не становится локальным из-за нулевого ответа.
// Эти данные остаются proposal: сервер подтверждает форму по текущим carrier,
// selector и target и сам выводит actual producer keys перед manifest.
type resourcePredicateProtection struct {
	Source   string               `json:"source"`
	Global   bool                 `json:"global"`
	Objects  []domain.ResourceRef `json:"objects"`
	Scopes   []domain.ScopeAnchor `json:"scopes"`
	Children []domain.ResourceRef `json:"children"`
}

func classifyResourcePredicate(key resourceSourceKey) (resourcePredicateProtection, error) {
	out := resourcePredicateProtection{}
	if !nativeQuestionToken(key.typ) || !nativeQuestionToken(key.id) {
		return out, kaname.ErrSourceUnconfirmed
	}
	source, err := json.Marshal(struct {
		Kind                resourceSourceKind
		Type, ID, Predicate string
	}{key.kind, key.typ, key.id, key.projection})
	if err != nil {
		return out, err
	}
	out.Source = string(source)
	switch key.kind {
	case resourceSourceSelectorObjects:
		var predicate resourceSelectorPredicate
		if json.Unmarshal([]byte(key.projection), &predicate) != nil {
			return out, kaname.ErrSourceUnconfirmed
		}
		if _, _, err := resourceSelectorObjectsSQL(key, 1); err != nil {
			return out, err
		}
		var ids []string
		if len(predicate.Targets) > 0 {
			// Все finite target IDs сохраняются, даже если текущая LABELS проверка не
			// нашла ни одного: будущий label change/создание не должны стать phantom.
			ids = slices.Clone(predicate.Targets)
		} else {
			switch predicate.Arm {
			case domain.ArmNames:
				ids = slices.Clone(predicate.Names)
			case domain.ArmAnchor:
				if predicate.Scope.Type == "cluster" {
					out.Global = true
				} else {
					out.Scopes = []domain.ScopeAnchor{predicate.Scope}
				}
			case domain.ArmLabels, domain.ArmAccessLabels:
				// Исторический whole-binding LABELS включает foreign REJECTED rows.
				// Без finite target это действительно полный predicate данного типа.
				out.Global = true
			default:
				return out, kaname.ErrSourceUnconfirmed
			}
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		for _, id := range ids {
			out.Objects = append(out.Objects, domain.ResourceRef{Type: key.typ, ID: id})
		}
	case resourceSourceNestedDescendants:
		var predicate resourceNestedPredicate
		if json.Unmarshal([]byte(key.projection), &predicate) != nil {
			return out, kaname.ErrSourceUnconfirmed
		}
		if _, _, err := resourceNestedDescendantsSQL(key, 1); err != nil {
			return out, err
		}
		ids := slices.Clone(predicate.ContainerIDs)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		for _, id := range ids {
			out.Children = append(out.Children, domain.ResourceRef{Type: predicate.ContainerType, ID: id})
		}
	default:
		return out, kaname.ErrSourceUnconfirmed
	}
	return out, nil
}

// GLOBAL здесь вытекает из исходного predicate, не из ошибки, лимита или
// неизвестного owner. Ошибка классификации возвращается без смены режима.
func (c *resourceSourceCapture) requiresGlobalPredicate() (bool, error) {
	if c == nil || c.sealed || c.lifetime == nil || c.lifetime.prepared != nil {
		return false, kaname.ErrSourceUnconfirmed
	}
	global := false
	for key := range c.entries {
		if key.kind != resourceSourceSelectorObjects && key.kind != resourceSourceNestedDescendants {
			continue
		}
		protection, err := classifyResourcePredicate(key)
		if err != nil {
			return false, err
		}
		global = global || protection.Global
	}
	return global, nil
}
