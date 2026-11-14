// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import "github.com/PRO-Robotech/kaname/internal/domain"

// ObjectRelations — общий смысл эмиссии одного правила на объекте. Его используют
// материализатор и компилятор выдаваемого эффекта; собственного ранжирования
// глаголов у потребителей нет. typeVerbs передаётся явно для проб урезанного типа.
func (f *Facts) ObjectRelations(fgaType string, authored, typeVerbs []string, policy domain.RulePolicy) []string {
	_, tier := domain.ResolveVerbsAndTier(authored, typeVerbs)
	granted := f.GrantedVerbs(fgaType, authored, typeVerbs, policy)
	seen := make(map[string]bool, len(granted)+1)
	var out []string
	add := func(relation string) {
		if !seen[relation] {
			seen[relation] = true
			out = append(out, relation)
		}
	}
	for _, verb := range granted {
		add("v_" + verb)
	}
	if tier != "" {
		add(tier)
	}
	return out
}

// ScopeSelfRelations — отношения непосредственно на объекте области. Выбор
// допустимого вида области и области выдачи остаётся у вызывающего. Знак *
// участвует в прежнем выводе яруса, но сам отношением v_* не становится.
func (f *Facts) ScopeSelfRelations(scopeType string, authored, typeVerbs []string) []string {
	_, tier := domain.ResolveVerbsAndTier(authored, typeVerbs)
	seen := make(map[string]bool, len(authored)+1)
	var out []string
	add := func(relation string) {
		if !seen[relation] {
			seen[relation] = true
			out = append(out, relation)
		}
	}
	if len(f.VerbsOfType(scopeType)) > 0 {
		for _, verb := range authored {
			if domain.IsVerbOfType(verb, typeVerbs) {
				add("v_" + domain.NormalizeVerb(verb))
			}
		}
	}
	if tier != "" {
		add(tier)
	}
	return out
}

// ObjectVerbs исключает действия, которые дают отношение на родителе.
// Они не должны дополнительно порождать ярус или глагол на дочернем объекте.
func (f *Facts) ObjectVerbs(dotted string, authored []string) []string {
	out := make([]string, 0, len(authored))
	for _, verb := range authored {
		if _, container := f.ContainerVerb(dotted, verb); !container {
			out = append(out, verb)
		}
	}
	return out
}
