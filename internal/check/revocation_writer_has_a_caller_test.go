// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_writer_has_a_caller_test.go — ГЕЙТ ПО ДЕРЕВУ: у каждого писателя
// записи отсечки есть исполнитель (задача kaname#313).
//
// Разбор предмета и то, чего он не видит, — в шапке
// `revocation_writer_has_a_caller.go`.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	revocationWriterCensusFloor = 300

	// revocationWriterCeiling — ПОТОЛОК писателей без исполнителя.
	//
	// Ноль по факту: на этом дереве каждого писателя отсечки кто-то зовёт.
	// Заводился гейт НЕ на нуле — на дереве до починки писатель записи,
	// которой судит читатель предъявления, исполнителя не имел.
	revocationWriterCeiling = 0
)

func TestEveryRevocationWriterHasACaller(t *testing.T) {
	t.Parallel()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var (
		parsed   int
		writers  []check.RevocationWriter
		census   = check.RevocationWriterCensus{Tables: map[string]struct{}{}}
		called   = map[string]struct{}{}
		declared = map[string]int{}
	)
	// ПЕРВЫЙ ПРОХОД — объявления операторов, вынесенные из тела. Они живут в
	// любом файле пакета, поэтому собираются по всему дереву прежде писателей.
	statements := map[string]string{}
	var prodFiles []string
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		prodFiles = append(prodFiles, rel)
		if serr := check.ScanRevocationStatements(rel, src, statements); serr != nil {
			t.Fatalf("разбор объявлений %s: %v", rel, serr)
		}
	}

	// ВТОРОЙ ПРОХОД — писатели и вызовы.
	for _, rel := range prodFiles {
		src, rderr := os.ReadFile(filepath.Join(corpusRoot, rel)) // #nosec G304 -- путь из состава дерева
		if rderr != nil {
			continue
		}
		parsed++
		ws, c, serr := check.ScanRevocationWriters(rel, src, statements)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		writers = append(writers, ws...)
		census.Funcs += c.Funcs
		census.Writers += c.Writers
		for tbl := range c.Tables {
			census.Tables[tbl] = struct{}{}
		}
		if cerr := check.CollectCalledNames(rel, src, called); cerr != nil {
			t.Fatalf("сбор вызовов %s: %v", rel, cerr)
		}
		if derr := check.CollectDeclaredNames(rel, src, declared); derr != nil {
			t.Fatalf("сбор объявлений %s: %v", rel, derr)
		}
	}

	orphans := check.RevocationWritersWithoutACaller(writers, called, declared)

	t.Logf("перепись: прод-файлов Go разобрано %d · функций с телом осмотрено %d · "+
		"объявлений оператора вне тела осмотрено %d · записей отсечки выведено %d (%s) · "+
		"писателей найдено %d · имён вызвано %d · писателей без исполнителя %d (потолок %d)",
		parsed, census.Funcs, len(statements), len(census.Tables),
		strings.Join(check.SortedTables(census), ", "),
		census.Writers, len(called), len(orphans), revocationWriterCeiling)

	if err := check.RevocationWriterPremise(parsed, revocationWriterCensusFloor, census); err != nil {
		t.Fatalf("вердикт беспредметен: %v", err)
	}

	if len(orphans) > revocationWriterCeiling {
		var where []string
		for _, w := range orphans {
			where = append(where, fmt.Sprintf("%s:%d  %s() → %s — %s", w.File, w.Line, w.Name, w.Table, w.Why))
		}
		t.Fatalf("писателей отсечки БЕЗ ИСПОЛНИТЕЛЯ %d при потолке %d:\n  %s\n\n"+
			"Запись отсечки объявлена, писатель для неё написан, а позвать его некому — "+
			"контроль существует в виде кода и не исполняется ни при каком входе. "+
			"Отличить это от работающего контроля наблюдением нельзя: «не отозван» и "+
			"«отзыв не доехал» дают один и тот же ответ.\n"+
			"Исходов два: дать писателю исполнителя на том пути, который обязан "+
			"снимать доступ, либо снять писателя вместе с записью. Оставить как есть "+
			"исходом НЕ является: объявленный отзыв без исполнителя — долг, а не будущее.",
			len(orphans), revocationWriterCeiling, strings.Join(where, "\n  "))
	}
}
