// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_projection_sole_writer_test.go — IAM-RV-1-12: У ПРОЕКЦИИ РОЛИ ОДИН
// АВТОР (порт с монорепо `internal/repohygiene/roleverbsolewriter_test.go`,
// снят вынесением службы доступа — `kacho#2597`; держатель
// `TestIAMRV112_RoleVerbProjectionHasASoleWriter` сохранён дословно — на нём
// стоят цитаты `docs/engineering/acceptance/role-verb-projection-sole-writer.md`,
// `rule-segments-have-a-referent.md`, `module-manifest-roles-and-seed-grants.md`
// и прод-комментарии `internal/repo/kaname/pg/{role_withdrawal_repo,
// catalog_consequence_sql,catalog_consequence_sql_test}.go`, написанные ДО
// выноса).
//
// Способность гейта упасть доказана инъекцией —
// role_verb_projection_sole_writer_injection_test.go.
//
// # Почему обход — СОБСТВЕННЫЙ модуль службы, а не дерево платформы
//
// Обе проекции живут целиком внутри службы (`internal/repo/kaname/pg/`);
// платформа об этом предмете ничего не знает. `platformtree.RequireCorpus`
// даёт корень собственной композиции модуля и работает одинаково в монорепо
// и в самостоятельном клоне — пропуска здесь нет by construction.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// roleVerbCensusFloor — порог переписи: ниже него «ноль находок» означало бы
// «ноль прочитанного».
const roleVerbCensusFloor = 300

// roleVerbWalkable — что гейт вообще осматривает: непроверочный Go.
func roleVerbWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
}

// TestIAMRV112_RoleVerbProjectionHasASoleWriter — в непроверочном коде Go
// ровно ОДНА функция вносит строку каждой проекции роли, всякий снимающий
// не-автор переселяет снятое, и все они лежат в слое репозитория.
func TestIAMRV112_RoleVerbProjectionHasASoleWriter(t *testing.T) {
	t.Parallel()
	// Таблиц ДВЕ (kacho#1030): у каждой проекции одного и того же объявления
	// автор обязан быть один. Подпроба на таблицу, а не один проход по обеим:
	// перепись обязана печататься по КАЖДОЙ, иначе «автор один» на суммарном
	// счёте зеленело бы при двух и нуле.
	for _, table := range check.RoleProjectionTables {
		t.Run(table, func(t *testing.T) { roleVerbSoleWriterOf(t, table) })
	}
}

func roleVerbSoleWriterOf(t *testing.T, table string) {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		filesRead int
		mentions  int
		// authors — функции, ВНОСЯЩИЕ строку: «путь::функция».
		authors []string
		// removers — функции, снимающие либо правящие строку.
		removers []string
		// strandedRemovers — снимающие, чей оператор НЕ переселяет снятое.
		strandedRemovers []string
		writers          = map[string]bool{}
		writerKeys       []string
	)
	seenAuthor := map[string]bool{}
	seenRemover := map[string]bool{}

	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !roleVerbWalkable(rel) {
			continue
		}
		b, readErr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if readErr != nil {
			t.Fatalf("чтение %s: %v", rel, readErr)
		}
		filesRead++
		body := string(b)
		if !strings.Contains(body, table) {
			continue
		}
		ops, m, perr := check.RoleProjectionWritesIn(rel, body, table)
		if perr != nil {
			t.Fatalf("разбор %s: %v — файл индекса не разобран, и его молчание ничего не значит", rel, perr)
		}
		mentions += m
		for _, op := range ops {
			key := rel + "::" + op.Func
			if !writers[key] {
				writers[key] = true
				writerKeys = append(writerKeys, key)
			}
			if op.Authors {
				if !seenAuthor[key] {
					seenAuthor[key] = true
					authors = append(authors, key)
				}
				continue
			}
			if !seenRemover[key] {
				seenRemover[key] = true
				removers = append(removers, key)
			}
			if !op.Relocates {
				strandedRemovers = append(strandedRemovers, key+" ("+op.Verb+")")
			}
		}
	}

	t.Logf("осмотрено непроверочных файлов Go: %d; литералов, называющих %s: %d; "+
		"пишущих функций: %d, из них АВТОРОВ (вносят строку): %d, снимающих: %d",
		filesRead, table, mentions, len(writerKeys), len(authors), len(removers))

	if filesRead < roleVerbCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", filesRead, roleVerbCensusFloor)
	}
	if mentions == 0 {
		t.Fatalf("имя %q не встречается в непроверочном коде НИ РАЗУ — предмета у гейта нет: "+
			"либо таблица переименована, либо её перестали читать и писать", table)
	}

	// ── ОСЬ 1: АВТОР ОДИН ────────────────────────────────────────────────────
	if len(authors) != 1 {
		t.Errorf("авторов проекции роли %d, а обязан быть ОДИН: %v\n"+
			"Что такое законная строка, объявляет ТОЛЬКО тот, кто её вносит: он называет "+
			"колонки и значения. Пока вносящих двое, изменение формы строки обязано доехать "+
			"до каждого, а промах МОЛЧАЛИВ — обе реализации компилируются, у обеих есть "+
			"пробы, и расходятся они только на входе, который ни одна проба не подаёт.",
			len(authors), authors)
	}

	// ── ОСЬ 2: СНИМАЮЩИЙ НЕ-АВТОР ПЕРЕСЕЛЯЕТ ─────────────────────────────────
	for _, stranded := range strandedRemovers {
		key := stranded[:strings.Index(stranded, " (")]
		if seenAuthor[key] {
			continue
		}
		t.Errorf("%s — снимает строку проекции роли, НЕ будучи её автором и НЕ переселяя "+
			"снятое в %s.\nСнятие по чужому поводу обязано ПЕРЕСЕЛЯТЬ тем же оператором: "+
			"иначе у арендатора отобрано право, записи об этом нет, и отобранное неотличимо "+
			"от никогда не выданного. Переселение и снятие неделимы ровно тогда, когда стоят "+
			"в одном операторе — поэтому признак читается по литералу, а не по функции.",
			stranded, check.RoleGrantOrphanTable)
	}

	// ── ОСЬ 3: СЛОЙ ──────────────────────────────────────────────────────────
	for _, key := range writerKeys {
		rel := key[:strings.Index(key, "::")]
		if !strings.Contains("/"+rel, check.RoleVerbWriterLayer) {
			t.Errorf("%s — писатель проекции роли ВНЕ слоя репозитория (%s).\n"+
				"Проекция есть состояние репозитория: форму строки, отображение отказов и "+
				"транзакционность держит слой repo/. Решение «как писать» не принадлежит ни "+
				"use-case, ни транспорту — они решают лишь КОГДА и ДЛЯ КАКИХ ролей пересчитывать, "+
				"и зовут писателя через порт.", key, check.RoleVerbWriterLayer)
		}
	}
}
