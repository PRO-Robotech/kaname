// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// carried_coordinate_ledger_injection_test.go — доказательство, что
// AdjudicateCarriedLedger способен упасть и смолчать, на синтетике.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func carriedInScopeAll(string) bool { return true }

// TestCarriedCoordinateLedgerInjection_FormAndVocabulary — исход вне
// словаря, запись без координаты.
func TestCarriedCoordinateLedgerInjection_FormAndVocabulary(t *testing.T) {
	t.Parallel()
	doc := "## Раздел\n\n" +
		"| координата | исход |\n|---|---|\n" +
		"| `a.go` | синоним, не из словаря |\n" +
		"|  | оставлено |\n"
	rows, sections, census := check.ParseCarriedCoordinateLedger(doc)
	if census.Tables != 1 || census.Rows != 2 {
		t.Fatalf("разбор синтетики: таблиц %d, строк %d — ожидалось 1 и 2", census.Tables, census.Rows)
	}
	findings := check.AdjudicateCarriedLedger("x.md", rows, sections, func(string) bool { return true },
		carriedInScopeAll, nil)
	// Третья находка — побочный, но верный эффект: строка без координаты несёт
	// исход «оставлено», а раздел не объявляет предикат снятия. Обе оси гейта
	// сработали на одном входе, и это ожидаемо, а не дефект теста.
	if len(findings) != 3 {
		t.Fatalf("ожидалось 3 находки (вне словаря + без координаты + без предиката снятия), "+
			"получено %d: %v", len(findings), findings)
	}
}

// TestCarriedCoordinateLedgerInjection_MissingRemovalPredicate — «оставлено»
// без предиката снятия в разделе — находка; тот же раздел с предикатом —
// молчание.
func TestCarriedCoordinateLedgerInjection_MissingRemovalPredicate(t *testing.T) {
	t.Parallel()
	docWithout := "## Раздел без предиката\n\n" +
		"| координата | исход |\n|---|---|\n" +
		"| `a.go` | оставлено: путь к прежнему |\n"
	rows, sections, _ := check.ParseCarriedCoordinateLedger(docWithout)
	f := check.AdjudicateCarriedLedger("x.md", rows, sections, func(string) bool { return true },
		carriedInScopeAll, nil)
	if len(f) != 1 || !strings.Contains(f[0], "предиката снятия не объявляет") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка о предикате снятия, получено %v", f)
	}

	docWith := "## Раздел с предикатом\n\n" +
		"| координата | исход |\n|---|---|\n" +
		"| `a.go` | оставлено: путь к прежнему |\n\n" +
		"**Предикат снятия — один на всё:** внешний путь выведен из контура.\n"
	rows2, sections2, _ := check.ParseCarriedCoordinateLedger(docWith)
	g := check.AdjudicateCarriedLedger("x.md", rows2, sections2, func(string) bool { return true },
		carriedInScopeAll, nil)
	if len(g) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: раздел, объявивший предикат снятия, дал находку: %v", g)
	}
}

// TestCarriedCoordinateLedgerInjection_SelfExpiration — «оставлено», а
// координаты в дереве нет — находка; та же запись, координата на месте —
// молчание. Кросс-репо путь (вне inScope) НЕ судится ни при каком treeHas.
func TestCarriedCoordinateLedgerInjection_SelfExpiration(t *testing.T) {
	t.Parallel()
	doc := "## Раздел\n\n**Предикат снятия:** X.\n\n" +
		"| координата | исход |\n|---|---|\n" +
		"| `internal/gone.go` | оставлено |\n" +
		"| `services/registry/foreign.go` | оставлено |\n"
	rows, sections, _ := check.ParseCarriedCoordinateLedger(doc)

	treeHasNothing := func(string) bool { return false }
	own := func(coord string) bool { return strings.HasPrefix(coord, "internal/") }

	f := check.AdjudicateCarriedLedger("x.md", rows, sections, treeHasNothing, own, nil)
	if len(f) != 1 || !strings.Contains(f[0], "internal/gone.go") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась ровно одна находка про internal/gone.go (кросс-репо "+
			"путь вне inScope судиться не должен): %v", f)
	}

	treeHasIt := func(c string) bool { return c == "internal/gone.go" }
	g := check.AdjudicateCarriedLedger("x.md", rows, sections, treeHasIt, own, nil)
	if len(g) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: координата на месте, а гейт покраснел: %v", g)
	}
}

// TestCarriedCoordinateLedgerInjection_Completeness — файл, читающий
// зеркальную колонку и не названный ведомостью, — находка.
func TestCarriedCoordinateLedgerInjection_Completeness(t *testing.T) {
	t.Parallel()
	doc := "## Раздел\n\n**Предикат снятия:** X.\n\n" +
		"| координата | исход |\n|---|---|\n" +
		"| `internal/a.go` | оставлено |\n"
	rows, sections, _ := check.ParseCarriedCoordinateLedger(doc)
	treeHas := func(c string) bool { return c == "internal/a.go" || c == "internal/b.go" }

	f := check.AdjudicateCarriedLedger("x.md", rows, sections, treeHas, carriedInScopeAll,
		[]string{"internal/a.go", "internal/b.go"})
	if len(f) != 1 || !strings.Contains(f[0], "internal/b.go") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка о внепись internal/b.go, получено %v", f)
	}

	g := check.AdjudicateCarriedLedger("x.md", rows, sections, treeHas, carriedInScopeAll,
		[]string{"internal/a.go"})
	if len(g) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: все читатели названы, а гейт покраснел: %v", g)
	}
}
