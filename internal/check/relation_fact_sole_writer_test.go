// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_sole_writer_test.go — У ПРЯМОГО ФАКТА ОДИН ПРОИЗВОДИТЕЛЬ, И ЭТО
// ЖУРНАЛ: в непроверочном коде Go нет ни одной записи в таблицу прямого факта.
//
// Предмет, перечень форм и НАЗВАННАЯ СЛЕПАЯ ЗОНА — в годке
// `relation_fact_sole_writer.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `relation_fact_sole_writer_injection_test.go`.
//
// # Откуда гейт пришёл
//
// Перенесён из корпуса монорепо (`internal/repohygiene/relationfactsolewriter_test.go`),
// снятого вместе с выносом службы (kacho#2597). Таблица и её триггер живут
// целиком здесь; в ведомость остатка гейт не попал, потому что предикат прежней
// адъюдикации искал форму записи пути `"services/iam"`, а этот гейт называет
// предмет ИМЕНЕМ ТАБЛИЦЫ и пути не упоминает вовсе.
//
// # Что изменено при переносе, и почему это не «то же самое»
//
// Прежняя форма читала ТЕЛО файла и сверяла подстроку. В этом дереве так
// нельзя: имя таблицы стоит в комментариях десятка прод-файлов — ровно там, где
// объясняют, что пишет её триггер. Подстрочный разбор дал бы находку на
// объяснении инварианта. Разбор переведён на узлы: запись ищется в строковых
// литералах, комментарии идут ОТДЕЛЬНО и только в перепись.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// factCensusFloor — порог переписи: ниже него «ноль находок» означало бы «ноль
// прочитанного».
const factCensusFloor = 300

// factWalkable — что гейт осматривает. Вынесено функцией: инъекция обязана
// проверять ТОТ ЖЕ отбор, которым судит гейт.
//
// Пробы исключены намеренно: им положено готовить состояние, и запись факта
// в пробе законна. Миграции сюда не попадают by construction — отбор берёт
// только `.go`.
func factWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasSuffix(rel, ".pb.go")
}

// factFindings — находки по найденным записям. Тот же предикат зовёт инъекция.
func factFindings(sites []check.FactWriteSite) []string {
	var out []string
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s:%d  %s %s", s.File, s.Line, s.Verb, check.FactTable))
	}
	sort.Strings(out)
	return out
}

// TestOnlyTheJournalProducesTheDirectFact — сам гейт.
func TestOnlyTheJournalProducesTheDirectFact(t *testing.T) {
	t.Parallel()

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var parsed, strs, comments, inStrings, inComments int
	var sites []check.FactWriteSite
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !factWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		s, census, serr := check.ScanFactWrites(rel, src, check.FactTable, check.FactMutationVerbs)
		if serr != nil {
			t.Fatalf("разбор %s не удался (%v) — гейт не вправе трактовать неразобранный "+
				"файл как «записей нет»", rel, serr)
		}
		parsed++
		strs += census.Strings
		comments += census.Comments
		inStrings += census.TableInStrings
		inComments += census.TableInComments
		sites = append(sites, s...)
	}

	t.Logf("перепись: непроверочных файлов Go разобрано %d, строковых литералов прочитано %d, "+
		"узлов-комментариев прочитано %d; таблицу %s называют: литералов %d, комментариев %d; "+
		"записей найдено %d",
		parsed, strs, comments, check.FactTable, inStrings, inComments, len(sites))

	if parsed < factCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, factCensusFloor)
	}
	if strs == 0 || comments == 0 {
		t.Fatalf("строковых литералов прочитано %d, комментариев %d — разбор перестал "+
			"видеть предмет, и его молчание сказано ни о чём", strs, comments)
	}

	// ПРЕДПОСЫЛКА: таблица вообще существует в коде как читаемая. Ноль упоминаний
	// означает либо переименование (тогда правь check.FactTable вместе с ним),
	// либо что форма перестала её читать — и то и другое обязано быть замечено
	// здесь, а не принято за «нарушений нет».
	if inStrings == 0 {
		t.Fatalf("имя %q не встречается НИ В ОДНОМ строковом литерале непроверочного кода — "+
			"предмета у гейта нет: либо таблица переименована, либо её перестали читать",
			check.FactTable)
	}
	// Вторая половина предпосылки: разбор дошёл до мест, где о таблице ГОВОРЯТ.
	// Ноль здесь означал бы, что комментарии не читаются вовсе, — и тогда
	// доказательство «молчим по существу, а не по слепоте» рассыпается.
	if inComments == 0 {
		t.Fatalf("имя %q не встречается ни в одном комментарии — разбор комментариев не "+
			"дошёл до дерева, и перепись не доказывает, что гейт молчит по существу",
			check.FactTable)
	}

	for _, f := range factFindings(sites) {
		t.Errorf("%s — запись в таблицу прямого факта из кода.\n"+
			"У неё ОДИН производитель: триггер `relation_fact_follows_journal` на журнале "+
			"намерений. Второй писатель кладёт факт, за которым НЕТ строки журнала, — то "+
			"есть без порядка применения, без снятия и без разбора оснований. Ломается это "+
			"в ту сторону, которую не видно: факт ЕСТЬ, и вердикт по нему выносится", f)
	}
}
