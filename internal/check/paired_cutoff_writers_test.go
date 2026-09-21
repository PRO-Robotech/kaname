// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// paired_cutoff_writers_test.go — ГЕЙТ ПО ДЕРЕВУ: писателя ОДНОЙ записи отсечки
// из двух не существует (задача kaname#313).
//
// Записей отсечки субъекта две, и судят по ним РАЗНЫЕ читатели: первую — хуки
// выдачи, вторую — авторитет отзыва на ПУТИ ЗАПРОСА. Путь снятия доступа,
// дошедший до одной и не дошедший до второй, снимает доступ наполовину и
// выглядит исполненным целиком: глагол отвечает успехом, а предъявление того
// же носителя продолжает приниматься.
//
// Гейт заводился НЕ на нуле: на дереве до починки писателей первой записи было
// пять, вторую клал один.
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
	// pairedCutoffFirst — запись, которую судят хуки выдачи.
	pairedCutoffFirst = "user_token_revocations"
	// pairedCutoffSecond — запись, которую судит авторитет отзыва на пути
	// запроса. Имена подаются гейтом, а не выводятся: пара — это решение, и
	// выведенная пара сменилась бы вместе с деревом молча.
	pairedCutoffSecond = "minted_token_revocations"

	pairedCutoffCeiling = 0
)

func TestSubjectCutoffWritersWriteBothRecords(t *testing.T) {
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

	statements := map[string]string{}
	var prod []string
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь: %v", rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		prod = append(prod, rel)
		if serr := check.ScanRevocationStatements(rel, src, statements); serr != nil {
			t.Fatalf("разбор объявлений %s: %v", rel, serr)
		}
	}

	var writers []check.RevocationWriter
	census := check.RevocationWriterCensus{Tables: map[string]struct{}{}}
	for _, rel := range prod {
		src, rderr := os.ReadFile(filepath.Join(corpusRoot, rel)) // #nosec G304 -- путь из состава дерева
		if rderr != nil {
			continue
		}
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
	}

	// Множество таблиц достраивается ЧЕРЕЗ ВЫЗОВ: дверь, кладущая вторую запись
	// вызовом помощника, пишет её так же, как назвавшая оператор.
	writers = check.PropagateTablesThroughCalls(writers)

	first := 0
	for _, w := range writers {
		for _, tbl := range w.Tables {
			if tbl == pairedCutoffFirst {
				first++
				break
			}
		}
	}
	lonely := check.WritersOfOneCutoffWithoutTheOther(writers, pairedCutoffFirst, pairedCutoffSecond)

	t.Logf("перепись: прод-файлов Go разобрано %d · функций с телом осмотрено %d · "+
		"записей отсечки выведено %d (%s) · писателей найдено %d · из них касаются %s — %d · "+
		"кладут ОДНУ из двух %d (потолок %d)",
		len(prod), census.Funcs, len(census.Tables),
		strings.Join(check.SortedTables(census), ", "), census.Writers,
		pairedCutoffFirst, first, len(lonely), pairedCutoffCeiling)

	if err := check.RevocationWriterPremise(len(prod), revocationWriterCensusFloor, census); err != nil {
		t.Fatalf("вердикт беспредметен: %v", err)
	}
	if first == 0 {
		t.Fatalf("писателей записи %s не найдено ни одного: предмета в дереве нет, "+
			"и «находок ноль» здесь означает «прочитано ноль»", pairedCutoffFirst)
	}

	if len(lonely) > pairedCutoffCeiling {
		var where []string
		for _, f := range lonely {
			where = append(where, fmt.Sprintf("%s:%d  %s() — пишет %s, НЕ пишет %s",
				f.Writer.File, f.Writer.Line, f.Writer.Name, pairedCutoffFirst, f.Missing))
		}
		t.Fatalf("писателей ОДНОЙ записи отсечки из двух: %d при потолке %d:\n  %s\n\n"+
			"Судят по этим записям РАЗНЫЕ читатели: первую — хуки выдачи, вторую — "+
			"авторитет отзыва на пути запроса. Снятие доступа, дошедшее до одной, "+
			"снимает доступ на выдаче и НЕ снимает на предъявлении: прежний носитель "+
			"продолжает аутентифицировать вызовы, а глагол отвечает успехом.\n"+
			"Исход один: класть обе ОДНОЙ дверью и одной транзакцией. Положить вторую "+
			"рядом, вторым вызовом, исходом НЕ является: состояние «одна без другой» "+
			"остаётся представимым, и представится оно на следующем писателе.",
			len(lonely), pairedCutoffCeiling, strings.Join(where, "\n  "))
	}
}
