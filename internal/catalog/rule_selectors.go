// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"sort"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// buildMaterializableTypes раскрывает подстановки по живым строкам снимка.
// У известных типов сохраняется прежний допуск: наличие строки каталога само
// по себе не делает служебный тип материализуемым. Новые типы участвуют, когда
// живой каталог объявляет хотя бы один собственный глагол объекта.
func (f *Facts) buildMaterializableTypes() []string {
	static := make(map[string]bool)
	for _, dotted := range domain.AllMaterializableTypes() {
		static[dotted] = true
	}
	seen := make(map[string]bool)
	var out []string
	for _, resource := range f.resources {
		dotted := resource.Module + "." + resource.Resource
		if seen[dotted] || domain.IsRetiredType(dotted) {
			continue
		}
		if !static[dotted] {
			if _, known := authzmap.FGAObjectType(dotted); known || len(f.verbsByFGAType[resource.ObjectType]) == 0 {
				continue
			}
		}
		seen[dotted] = true
		out = append(out, dotted)
	}
	sort.Strings(out)
	return out
}

func (f *Facts) materializableTypes() []string {
	if f == nil {
		return nil
	}
	return f.materializableDotted
}

// MaterializingSelectors строит индекс роли с подстановками по этому снимку.
// Явные типы, отпечатки, ветви и контейнеры сохраняются; Grants заполняет
// GrantSelectors, который также отсекает глаголы снятых и неизвестных типов.
func (f *Facts) MaterializingSelectors(rules domain.Rules) []domain.RuleSelector {
	return rules.MaterializingSelectorsForTypes(f.materializableTypes())
}

// MaterializingSelectorsInScope строит селекторы выдачи в её текущей области.
// На cluster и неизвестной области подстановки не материализуются по объектам.
func (f *Facts) MaterializingSelectorsInScope(rules domain.Rules, scope domain.Scope) []domain.RuleSelector {
	return rules.MaterializingSelectorsInScopeForTypes(scope, f.materializableTypes())
}

// MaterializedTypeProjection даёт анализу тот же источник типов, что индексам
// роли и выдачи. Признак авторской подстановки не теряется при пустом результате.
func (f *Facts) MaterializedTypeProjection(rule domain.Rule, scope domain.Scope) domain.RuleTypeProjection {
	return rule.MaterializedTypeProjectionForTypes(scope, f.materializableTypes())
}

// RegrainSelectors сохраняет legacy и ordinary FP для обновления уже
// существующих строк. Отбор сохранённых FP и пересечение с их типами остаются
// обязанностью писателя; этот расчёт не создаёт meta права или снятые строки.
func (f *Facts) RegrainSelectors(rules domain.Rules) []domain.RuleSelector {
	return domain.RegrainSelectorsForTypes(rules, f.materializableTypes())
}
