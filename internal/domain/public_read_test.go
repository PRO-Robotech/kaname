// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// public_read_test.go — «правило открывает чтение типа целиком» — один
// предикат на две формы правила: авторское правило роли (им судят ворота выдачи
// классу, SC-65) и селектор материализации (им судит разворачивание). Публичное
// чтение наследует сужение правила роли (kaname#856).

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestReadsWholeTypeIsOneJudgementForRuleAndSelector(t *testing.T) {
	const child = "registry.repositories"
	whole := domain.Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}
	for _, tc := range []struct {
		name string
		rule domain.Rule
		want bool
	}{
		{"близнец: якорь, [get, list]", whole, true},
		{"близнец: подстановка ресурса", domain.Rule{Module: "registry", Resources: []string{"*"}, Verbs: []string{"list", "get"}}, true},
		{"по меткам", func() domain.Rule { r := whole; r.MatchLabels = map[string]string{"tier": "gold"}; return r }(), false},
		{"по именам", func() domain.Rule { r := whole; r.ResourceNames = []string{"r1"}; return r }(), false},
		{"только get", func() domain.Rule { r := whole; r.Verbs = []string{"get"}; return r }(), false},
		{"только list", func() domain.Rule { r := whole; r.Verbs = []string{"list"}; return r }(), false},
		{"другой тип", domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}}, false},
	} {
		if got := tc.rule.ReadsWholeType(child); got != tc.want {
			t.Errorf("%s: правило %v, ждали %v", tc.name, got, tc.want)
		}
		sels := domain.Rules{tc.rule}.MaterializingSelectorsInScope(domain.ScopeProject)
		if len(sels) != 1 {
			t.Fatalf("%s: селекторов %d, ждали 1", tc.name, len(sels))
		}
		if got := sels[0].ReadsWholeType(child); got != tc.want {
			t.Errorf("%s: селектор %v, а правило %v — две формы одного правила разошлись", tc.name, got, tc.want)
		}
		c := domain.PublicReadContainer{ChildTypes: []string{child}}
		if _, got := c.CoveredChild(domain.Rules{tc.rule}); got != tc.want {
			t.Errorf("%s: ворота (CoveredChild) %v, ждали %v", tc.name, got, tc.want)
		}
	}
}
