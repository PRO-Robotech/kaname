// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_check_wiring_injection_test.go — доказательство падучести обоих
// разборщиков (`MakefileDeclaresTarget`, `CallsMakeTarget`) в обе стороны.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestMakefileDeclaresTargetInjection(t *testing.T) {
	t.Parallel()
	mk := "sync-permission-catalog:\n\tcp a b\n\n.PHONY: build\nbuild:\n\tgo build ./...\n"
	if !check.MakefileDeclaresTarget(mk, "sync-permission-catalog") {
		t.Fatal("КОНТРОЛЬ: цель объявлена, а разбор её не увидел")
	}
	if check.MakefileDeclaresTarget(mk, "sync-permission-catalog-v2") {
		t.Fatal("разбор увидел цель, которой в Makefile нет")
	}
	// Строка внутри РЕЦЕПТА (с табуляцией), совпадающая по тексту с именем
	// цели, — не объявление.
	mkWithProseInRecipe := "build:\n\techo sync-permission-catalog: not a target here\n"
	if check.MakefileDeclaresTarget(mkWithProseInRecipe, "sync-permission-catalog") {
		t.Fatal("ЗАКОННЫЙ БЛИЗНЕЦ: текст внутри рецепта распознан как объявление цели")
	}
}

func TestCallsMakeTargetInjection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"прямой вызов", "make sync-permission-catalog", true},
		{"через -C текущий", "make -C . sync-permission-catalog", true},
		{"после &&", "cd /x && make sync-permission-catalog", true},
		{"среди нескольких строк", "echo hi\nmake sync-permission-catalog\necho done", true},
		{"чужая цель — находка", "make build", false},
		{"имя только в комментарии оболочки — находка", "# make sync-permission-catalog\necho ok", false},
		{"похожая цель с иным именем — находка", "make sync-permission-catalog-v2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bodies, _, err := check.ExecutableRunBodies("jobs:\n  g:\n    steps:\n      - run: |\n" +
				indentEach(c.body) + "\n")
			if err != nil {
				t.Fatalf("синтетика не разобралась: %v", err)
			}
			got := false
			for _, b := range bodies {
				if check.CallsMakeTarget(b, "sync-permission-catalog") {
					got = true
				}
			}
			if got != c.want {
				t.Errorf("CallsMakeTarget = %v, ожидалось %v (тела: %v)", got, c.want, bodies)
			}
		})
	}
}

// indentEach — YAML-блочный скаляр требует общего отступа у всех строк тела.
func indentEach(body string) string {
	out := ""
	for _, ln := range splitLinesKeepEmpty(body) {
		out += "          " + ln + "\n"
	}
	return out
}

func splitLinesKeepEmpty(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
