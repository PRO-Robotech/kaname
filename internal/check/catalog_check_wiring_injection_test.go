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
	mk := "sync-permission-catalog:\n\tcp a b\n\ncheck-permission-catalog:\n\tcmp a b\n" +
		"\n.PHONY: build\nbuild:\n\tgo build ./...\n"
	for _, target := range []string{check.CatalogSyncTarget, check.CatalogCheckTarget} {
		if !check.MakefileDeclaresTarget(mk, target) {
			t.Fatalf("КОНТРОЛЬ: цель %s объявлена, а разбор её не увидел", target)
		}
	}
	if check.MakefileDeclaresTarget(mk, "sync-permission-catalog-v2") {
		t.Fatal("разбор увидел цель, которой в Makefile нет")
	}
	// ДВЕ ФОРМЫ ОДНОГО ПРЕДМЕТА не вправе смешиваться: гейт судит их
	// РАЗДЕЛЬНО (одну обязан звать конвейер, вторую — нет), и путаница имён
	// сделала бы находку невидимой в обе стороны.
	mkCheckOnly := "check-permission-catalog:\n\tcmp a b\n"
	if check.MakefileDeclaresTarget(mkCheckOnly, check.CatalogSyncTarget) {
		t.Fatal("объявление формы-проверки распознано как объявление пишущей формы")
	}
	mkSyncOnly := "sync-permission-catalog:\n\tcp a b\n"
	if check.MakefileDeclaresTarget(mkSyncOnly, check.CatalogCheckTarget) {
		t.Fatal("объявление пишущей формы распознано как объявление формы-проверки")
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
		// Разведение двух форм: вызов формы-проверки НЕ есть вызов пишущей.
		{"зовётся форма-проверка — пишущая не звана", "make check-permission-catalog", false},
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
				if check.CallsMakeTarget(b, check.CatalogSyncTarget) {
					got = true
				}
			}
			if got != c.want {
				t.Errorf("CallsMakeTarget = %v, ожидалось %v (тела: %v)", got, c.want, bodies)
			}
		})
	}
}

// TestCallsCatalogCheckTargetInjection — вторая форма, ПО СВОЕЙ ОСИ. Без неё
// гейт доказывал бы падучесть только на пишущей цели, а зелёное про звучащую
// форму-проверку держалось бы на том, что имена похожи.
func TestCallsCatalogCheckTargetInjection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"прямой вызов", "make check-permission-catalog", true},
		{"через -C текущий", "make -C . check-permission-catalog", true},
		{"после && в одной строке", "go mod download && make check-permission-catalog", true},
		{"среди нескольких строк", "echo hi\nmake check-permission-catalog\necho done", true},
		{"зовётся ПИШУЩАЯ форма — форма-проверка не звана", "make sync-permission-catalog", false},
		{"имя только в комментарии оболочки — находка", "# make check-permission-catalog\necho ok", false},
		{"похожая цель с иным именем — находка", "make check-permission-catalog-v2", false},
		{"чужая цель — находка", "make build", false},
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
				if check.CallsMakeTarget(b, check.CatalogCheckTarget) {
					got = true
				}
			}
			if got != c.want {
				t.Errorf("CallsMakeTarget(%s) = %v, ожидалось %v (тела: %v)",
					check.CatalogCheckTarget, got, c.want, bodies)
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
