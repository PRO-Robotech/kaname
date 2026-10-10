// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_insert_writes_ledger_injection_test.go — гейт ведомости вставки
// привязки доступа умеет упасть и умеет смолчать (kaname#670).
//
// Инъекции:
//   - настоящий вход: каждый файл дерева, вставляющий привязку, с выключенной
//     записью ведомости — находка называет ЭТОТ файл и его функцию;
//   - законный близнец той же формы (вставка и ведомость в одном замыкании) —
//     молчание;
//   - меняется один факт против близнеца: ведомость в СОСЕДНЕЙ функции — находка;
//   - слово в комментарии и строке предметом не становится.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func scanLedger(t *testing.T, src string) ([]check.BindingInsertSite, check.BindingInsertCensus) {
	t.Helper()
	sites, c, err := check.ScanBindingInsertLedger("x.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	return sites, c
}

func TestBindingInsertLedgerInjection_LawfulTwinInAClosureIsSilent(t *testing.T) {
	t.Parallel()
	sites, c := scanLedger(t, `package p
func f() {
	_ = do(func(w W) error {
		ab, _ := w.AccessBindingsW().Insert(ctx, b)
		return w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples)
	})
}`)
	if c.Inserts != 1 || c.WithLedger != 1 || len(sites) != 1 || !sites[0].WritesLedger {
		t.Fatalf("законный близнец обязан быть сосчитан и не дать находки: перепись %+v, места %+v", c, sites)
	}
}

func TestBindingInsertLedgerInjection_LedgerInAnotherFunctionIsFound(t *testing.T) {
	t.Parallel()
	sites, c := scanLedger(t, `package p
func f() {
	_ = do(func(w W) error {
		_, err := w.AccessBindingsW().Insert(ctx, b)
		return err
	})
	_ = w.AccessBindingsW().InsertEmittedTuples(ctx, id, tuples)
}`)
	if c.Inserts != 1 || len(sites) != 1 || sites[0].WritesLedger {
		t.Fatalf("ведомость вне функции вставки обязана дать находку: перепись %+v, места %+v", c, sites)
	}
	if got := sites[0].String(); !strings.Contains(got, "x.go:4") || !strings.Contains(got, "литерал в f") {
		t.Fatalf("находка обязана назвать координату и функцию, а называет: %q", got)
	}
}

func TestBindingInsertLedgerInjection_WordInProseIsNotASite(t *testing.T) {
	t.Parallel()
	_, c := scanLedger(t, `package p
// w.AccessBindingsW().Insert(ctx, b) — без ведомости
func f() { _ = "w.AccessBindingsW().Insert(ctx, b)" }`)
	if c.Inserts != 0 {
		t.Fatalf("слово в комментарии и строке сосчитано вставкой: %+v", c)
	}
}

// TestBindingInsertLedgerInjection_RealInsertWithoutLedgerIsFound — каждый файл
// дерева, вставляющий привязку, с выключенной записью ведомости: находка
// называет его. Контроль — тот же файл без правки молчит.
func TestBindingInsertLedgerInjection_RealInsertWithoutLedgerIsFound(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	injected := 0
	for _, rel := range corpus.Rels() {
		src := corpus[rel]
		// Отбор — тем же разбором, что судит гейт, а не подстрокой: слово в
		// комментарии (шапка самого гейта) вставкой не является.
		control, _, err := check.ScanBindingInsertLedger(rel, []byte(src))
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		if len(control) == 0 {
			continue
		}
		for _, s := range control {
			if !s.WritesLedger {
				t.Fatalf("контроль: %s без правки уже даёт находку %s — инъекция ничего не докажет", rel, s)
			}
		}
		mutated := strings.ReplaceAll(src, ".InsertEmittedTuples(", ".insertEmittedTuplesRemoved(")
		sites, _, err := check.ScanBindingInsertLedger(rel, []byte(mutated))
		if err != nil {
			t.Fatalf("разбор инъекции %s: %v", rel, err)
		}
		found := false
		for _, s := range sites {
			if !s.WritesLedger && strings.HasPrefix(s.String(), rel+":") {
				found = true
			}
		}
		if !found {
			t.Fatalf("инъекция «без ведомости» в %s не дала находки: %+v", rel, sites)
		}
		injected++
	}
	t.Logf("инъекций настоящим входом: %d файлов", injected)
	if injected == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: файлов, вставляющих привязку, в дереве 0")
	}
}
