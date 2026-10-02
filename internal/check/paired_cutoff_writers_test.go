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
	"regexp"
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
)

var (
	cutoffFirstRe  = regexp.MustCompile(`(?is)INTO\s+(?:kaname\.)?` + pairedCutoffFirst + `\b`)
	cutoffSecondRe = regexp.MustCompile(`(?is)INTO\s+(?:kaname\.)?` + pairedCutoffSecond + `\b`)
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

	// ПЕРВЫЙ ПРОХОД — объявления операторов, вынесенные из тела.
	statements := map[string][2]bool{}
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
		if serr := check.ScanPairedStatements(rel, src, cutoffFirstRe, cutoffSecondRe, statements); serr != nil {
			t.Fatalf("разбор объявлений %s: %v", rel, serr)
		}
	}

	var (
		funcs  []check.PairedWriteFunc
		census check.PairedWriteCensus
	)
	for _, rel := range prod {
		src, rderr := os.ReadFile(filepath.Join(corpusRoot, rel)) // #nosec G304 -- путь из состава дерева
		if rderr != nil {
			continue
		}
		fs, c, serr := check.ScanPairedWrites(rel, src, cutoffFirstRe, cutoffSecondRe, statements)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		funcs = append(funcs, fs...)
		census.Funcs += c.Funcs
		census.DoFirst += c.DoFirst
		census.DoSecond += c.DoSecond
		census.DeadCalls += c.DeadCalls
	}

	directFirst := census.DoFirst
	funcs = check.ResolvePairedWrites(funcs, &census)
	findings := check.PairedWriteFindings(funcs)
	reach := 0
	for _, f := range funcs {
		if f.First {
			reach++
		}
	}

	t.Logf("перепись: прод-файлов Go разобрано %d · функций с телом осмотрено %d · "+
		"объявлений оператора вне тела осмотрено %d · пишут %s ПРЯМО %d, с учётом "+
		"вызовов %d · пишут %s прямо %d · вызовов в мёртвых ветвях отброшено %d · "+
		"имён неоднозначных %d · находок %d (потолок 0)",
		len(prod), census.Funcs, len(statements), pairedCutoffFirst, directFirst, reach,
		pairedCutoffSecond, census.DoSecond, census.DeadCalls, census.Ambiguous, len(findings))

	if len(prod) < revocationWriterCensusFloor {
		t.Fatalf("прод-файлов разобрано %d при пороге %d — обход не добрался до дерева",
			len(prod), revocationWriterCensusFloor)
	}
	if directFirst == 0 {
		t.Fatalf("писателей записи %s не найдено ни одного: предмета в дереве нет, "+
			"и «находок ноль» здесь означает «прочитано ноль»", pairedCutoffFirst)
	}
	if census.DoSecond == 0 {
		t.Fatalf("писателей записи %s не найдено ни одного — разбор видит одну "+
			"половину пары и не видит второй", pairedCutoffSecond)
	}

	if len(findings) > 0 {
		var where []string
		for _, f := range findings {
			where = append(where, fmt.Sprintf("%s:%d  %s.%s() — пишет %s, НЕ пишет %s",
				f.File, f.Line, f.Pkg, f.Name, pairedCutoffFirst, pairedCutoffSecond))
		}
		t.Fatalf("писателей ОДНОЙ записи отсечки из двух: %d\n  %s\n\n"+
			"Судят по этим записям РАЗНЫЕ читатели: первую — хуки выдачи, вторую — "+
			"авторитет отзыва на пути запроса. Снятие доступа, дошедшее до одной, "+
			"снимает доступ на выдаче и НЕ снимает на предъявлении: прежний носитель "+
			"продолжает аутентифицировать вызовы, а глагол отвечает успехом.\n"+
			"Исход один: класть обе ОДНОЙ дверью. Положить вторую рядом, вторым "+
			"вызовом, исходом НЕ является: состояние «одна без другой» остаётся "+
			"представимым, и представится оно на следующем писателе.",
			len(findings), strings.Join(where, "\n  "))
	}
}
