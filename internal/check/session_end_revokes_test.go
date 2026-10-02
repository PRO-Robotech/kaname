// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_end_revokes_test.go — ГЕЙТ ПО ДЕРЕВУ: снимающий сессию отзывает
// выданное в ней (задача kaname#313).
//
// До этого прибора у пары «снятие сессии / отзыв семейства» не было НИ ОДНОГО
// гейта, в отличие от пары записей отсечки. Ровно поэтому третий снимающий
// метод уцелел: его не судил ни код, ни проба, ни прибор.
//
// Ротацию обновляющего токена останавливает РОВНО отзыв семейства: оператор
// ротации не читает ни отметку окончания сессии, ни одну из отсечек. Значит
// запись, снятая без отзыва, снята только в записи.
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

var (
	// sessionEndMarkRe — оператор, ставящий отметку окончания записи сессии.
	sessionEndMarkRe = regexp.MustCompile(`(?is)UPDATE\s+(?:kaname\.)?human_sessions\s+SET[^;]*\bended_at\s*=`)
	// familyRevokeRe — оператор, ставящий отметку отзыва семейства.
	familyRevokeRe = regexp.MustCompile(`(?is)UPDATE\s+(?:kaname\.)?token_families[^;]*\brevoked_at\s*=`)
)

const sessionEndCensusFloor = 300

func TestSessionEndingWritersRevokeWhatTheSessionHolds(t *testing.T) {
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
		if serr := check.ScanPairedStatements(rel, src, sessionEndMarkRe, familyRevokeRe, statements); serr != nil {
			t.Fatalf("разбор объявлений %s: %v", rel, serr)
		}
	}

	var (
		funcs  []check.PairedWriteFunc
		census check.PairedWriteCensus
		parsed int
	)
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
		parsed++
		fs, c, serr := check.ScanPairedWrites(rel, src, sessionEndMarkRe, familyRevokeRe, statements)
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
		"объявлений оператора вне тела осмотрено %d · ставят отметку окончания ПРЯМО %d, "+
		"с учётом вызовов %d · отзывают семейство прямо %d · вызовов в мёртвых ветвях "+
		"отброшено %d · имён неоднозначных %d · находок %d (потолок 0)",
		parsed, census.Funcs, len(statements), directFirst, reach, census.DoSecond,
		census.DeadCalls, census.Ambiguous, len(findings))

	if parsed < sessionEndCensusFloor {
		t.Fatalf("прод-файлов разобрано %d при пороге %d — обход не добрался до дерева",
			parsed, sessionEndCensusFloor)
	}
	if directFirst == 0 {
		t.Fatal("операторов, ставящих отметку окончания сессии, не найдено ни одного: " +
			"предмета в дереве нет, и «находок ноль» означает «прочитано ноль». " +
			"Оператор переименован либо снят — гейт обязан уйти вместе с предметом")
	}
	if census.DoSecond == 0 {
		t.Fatal("операторов отзыва семейства не найдено ни одного — разбор видит одну " +
			"половину пары и не видит второй")
	}

	if len(findings) > 0 {
		var where []string
		for _, f := range findings {
			where = append(where, fmt.Sprintf("%s:%d  %s.%s() — снимает сессию, НЕ отзывает семейство",
				f.File, f.Line, f.Pkg, f.Name))
		}
		t.Fatalf("снимающих сессию БЕЗ отзыва выданного в ней: %d\n  %s\n\n"+
			"Ротацию обновляющего токена останавливает РОВНО отзыв семейства: оператор "+
			"ротации не читает ни отметку окончания записи, ни одну из отсечек. Значит "+
			"запись, снятая без отзыва, снята ТОЛЬКО В ЗАПИСИ: её обновляющий токен "+
			"продолжает ротироваться в свежие, а глагол отвечает успехом.\n"+
			"Исход один: отзывать семейство ТОЙ ЖЕ транзакцией, что ставит отметку.",
			len(findings), strings.Join(where, "\n  "))
	}
}
