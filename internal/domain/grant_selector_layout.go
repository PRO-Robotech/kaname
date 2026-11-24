// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// RulesForStoredSelectorLayout выбирает форму ordinary rules по фактически
// сохранённым FP. kaname#1034: старые carriers не теряют ordinary доступ;
// отсутствие meta producer не превращается в подтверждённое meta право.
func RulesForStoredSelectorLayout(rules Rules, stored []string) Rules {
	present := map[string]bool{}
	for _, fp := range stored {
		present[fp] = true
	}
	var out Rules
	for _, r := range rules {
		old := Rules{r}
		legacy := false
		for _, s := range old.MaterializingSelectors() {
			if present[s.RuleFP] {
				legacy = true
			}
		}
		ordinary, _, err := SplitGrantCapabilityRules(old)
		if legacy {
			out = append(out, cloneGrantRule(r))
		} else if err == nil {
			out = append(out, ordinary...)
		}
	}
	return out
}

// RegrainSelectors даёт кандидатов обоих форматов. Репозиторий обновляет
// ТОЛЬКО существующий FP и пересекает grants с уже сохранёнными типами.
// Здесь нет восстановления retired selectors или активации meta (kaname#1034).
func RegrainSelectors(rules Rules) []RuleSelector {
	return regrainSelectors(rules, Rules.MaterializingSelectors)
}

// RegrainSelectorsForTypes сохраняет оба сохранённых формата FP, раскрывая
// подстановки по одному явному снимку типов для исходных и ordinary правил.
func RegrainSelectorsForTypes(rules Rules, types []string) []RuleSelector {
	return regrainSelectors(rules, func(rules Rules) []RuleSelector {
		return rules.MaterializingSelectorsForTypes(types)
	})
}

func regrainSelectors(rules Rules, project func(Rules) []RuleSelector) []RuleSelector {
	out := project(rules)
	seen := map[string]bool{}
	for _, s := range out {
		seen[s.RuleFP] = true
	}
	ordinary, _, err := SplitGrantCapabilityRules(rules)
	if err != nil {
		return out
	}
	for _, s := range project(ordinary) {
		if !seen[s.RuleFP] {
			out = append(out, s)
			seen[s.RuleFP] = true
		}
	}
	return out
}
