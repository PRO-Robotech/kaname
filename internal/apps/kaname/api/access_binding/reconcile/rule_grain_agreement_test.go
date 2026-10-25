// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// rule_grain_agreement_test.go — МАТЕРИАЛИЗАТОР И РЕШЕНИЕ О ДОСТУПЕ ДАЮТ ОДИН
// НАБОР ГЛАГОЛОВ ПО ПРАВИЛУ (kaname#878).
//
// Решение о доступе читает глаголы правила со строки его селектора
// (`role_rule_selectors.verbs_by_type`, заполняет `catalog.Facts.GrantSelectors`),
// материализатор — эмитит отношения `v_*` члену правила (`ruleObjectTuples`).
// Расхождение двух сторон — ровно тот класс, ради которого задача заведена:
// глагол, который решение даёт, а материализованный член не несёт, или
// наоборот. Проба сверяет обе стороны на КАЖДОМ селекторе и КАЖДОМ его типе.
//
// Наборы ролей — сценарии пробы решения (`relverdict/rule_grain_integration_test.go`)
// и формы, где глагол зависит от типа: правка, влекущая удаление на листе и не
// влекущая на типе-области, и подстановка глаголов.

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestRuleGrain_MaterializerAndVerdictAgreeOnEveryRule(t *testing.T) {
	cat := catalogfixture.Facts()
	roles := map[string]domain.Rules{
		"два правила разных глаголов": {
			{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}},
			{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"delete"},
				ResourceNames: []string{"reg00000000000000001"}},
		},
		"вложенное правило со своими глаголами": {
			{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
				Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}},
			{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"delete"}},
		},
		"правка на листе и на области": {
			{Module: "iam", Resources: []string{"projects", "service_accounts"}, Verbs: []string{"update"}},
		},
		"подстановка глаголов": {
			{Module: "vpc", Resources: []string{"networks", "subnets"}, Verbs: []string{"*"}},
		},
	}
	checked := 0
	for name, rules := range roles {
		sels := cat.GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())
		if len(sels) == 0 {
			t.Fatalf("%s: селекторов ноль — сверять нечего", name)
		}
		for _, sel := range sels {
			if sel.Grants == nil {
				t.Fatalf("%s: селектор %s без вычисленных глаголов", name, sel.RuleFP)
			}
			for _, dotted := range sel.ObjectTypes {
				tuples, ok := ruleObjectTuples(cat, domain.TenantPolicy(), "user:u", sel.Verbs, dotted, "obj-1")
				var materialized []string
				if ok {
					for _, tp := range tuples {
						if v, isVerb := strings.CutPrefix(tp.Relation, "v_"); isVerb {
							materialized = append(materialized, v)
						}
					}
				}
				verdict := slices.Clone(sel.Grants[dotted])
				sort.Strings(materialized)
				sort.Strings(verdict)
				if !slices.Equal(materialized, verdict) {
					t.Errorf("%s: правило %s, тип %s: материализатор даёт %v, решение о доступе — %v",
						name, sel.RuleFP[:12], dotted, materialized, verdict)
				}
				checked++
			}
		}
	}
	// Перепись: ноль сверенных пар «правило × тип» — не зелёное.
	if checked < 8 {
		t.Fatalf("сверено пар «правило × тип» %d — меньше состава наборов", checked)
	}
	t.Logf("сверено пар «правило × тип»: %d", checked)
}
