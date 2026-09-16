// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_method_vocabulary_test.go — ГЕЙТ КЛАССА: словарь способов
// предъявления объявлен ОДНИМ перечнем вместе с правилом вывода уровня
// (приёмка Ф11 `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р8, §8 строка «гейт „словарь один“ — служба»; задача kacho#1280).
//
// # Предмет
//
// Имена способов — password · totp · lookup_secret · webauthn · recovery_code —
// живут в `internal/assurance` вместе с правилом, и второе объявление перечня
// имён в прод-коде службы — находка с координатой. Второе место об одном
// словаре расходится молча: способ, заведённый в один перечень и не заведённый
// в другой, доезжает до сессии безуровневым либо отвергается хранилищем, которое
// правило о нём не спрашивало.
//
// Судится ОБЪЯВЛЕНИЕ ПЕРЕЧНЯ, а не слово: строковый литерал, совпадающий с
// именем способа, бывает именем поля и областью токена (`"webauthn"` в условии
// модели и в области токена) и находкой не является. Перечнем считается узел,
// несущий два и более РАЗЛИЧНЫХ имени словаря: составной литерал, группа
// const/var, перечень ветви case — формы названы в шапке разбора.
//
// # Половина по схеме
//
// Ограничение схемы, перечисляющее значения столбца среди которых есть имя
// словаря, обязано быть его ПОДМНОЖЕСТВОМ: имя вне словаря — находка. Так
// хранилище способов входа (Ф2) называет вид тем же перечнем, а не своим.
//
// # Граница названа
//
// Перечень способов церемонии консоли лежит в доме платформы и обходу не
// доступен (приёмка, Н54): согласие двух домов этот гейт не держит.
//
// Способность упасть и смолчать доказана инъекцией —
// assurance_method_vocabulary_injection_test.go.
package check_test

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// methodVocabulary — имена словаря от ПРОИЗВОДИТЕЛЯ, а не выписанные.
func methodVocabulary(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range assurance.Methods() {
		out = append(out, m.String())
	}
	if len(out) < 2 {
		t.Fatalf("словарь производителя из %d имён — перечня, который можно переобъявить, нет", len(out))
	}
	return out
}

func TestAssuranceMethodVocabularyIsDeclaredOnce(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	vocabulary := methodVocabulary(t)

	// ── половина по коду ────────────────────────────────────────────────────
	goCorpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	var (
		census   check.VocabularyScanCensus
		homeList []check.VocabularyListSite
		findings []string
	)
	for _, rel := range goCorpus.Rels() {
		sites, c, err := check.ScanMethodVocabularyLists(rel, []byte(goCorpus[rel]), vocabulary)
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		census.Files++
		census.Strings += c.Strings
		census.VocabularyStrings += c.VocabularyStrings
		census.Lists += c.Lists
		for _, s := range sites {
			if strings.HasPrefix(rel, check.AssuranceHomeRel+"/") {
				homeList = append(homeList, s)
				continue
			}
			findings = append(findings, s.String())
		}
	}

	// ── половина по схеме ───────────────────────────────────────────────────
	migs, err := check.MigrationCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	files := migs.Rels()
	sort.Slice(files, func(i, j int) bool {
		return migrationOrdinal(path.Base(files[i])) < migrationOrdinal(path.Base(files[j]))
	})
	var (
		schemaFiles       int
		schemaConstraints []check.SchemaValueListSite
	)
	for _, rel := range files {
		schemaFiles++
		cs := check.ScanSchemaValueLists(rel, migrations.MigrationUpSection(migs[rel]), vocabulary)
		schemaConstraints = append(schemaConstraints, cs...)
	}
	for _, c := range schemaConstraints {
		if extra := setDifferenceOf(c.Values, vocabulary); len(extra) != 0 {
			findings = append(findings, c.String()+" — имена вне словаря: "+strings.Join(extra, ", "))
		}
	}

	t.Logf("перепись: файлов прод-кода прочитано %d, строковых литералов %d, из них слов словаря %d; "+
		"объявлений перечня в доме %d, вне дома %d; файлов миграций %d, ограничений схемы, сверенных со словарём, %d",
		census.Files, census.Strings, census.VocabularyStrings,
		len(homeList), len(findings), schemaFiles, len(schemaConstraints))

	// Предпосылка: разбор ВИДИТ объявление в доме. Ноль означал бы, что
	// перечень записан формой, о которой разбор не знает, — и молчание вне дома
	// было бы сказано о разборе, а не о дереве.
	if len(homeList) != 1 {
		t.Fatalf("объявлений перечня словаря в доме %s — %d при требуемом ровно одном: %v",
			check.AssuranceHomeRel, len(homeList), homeList)
	}
	if len(findings) != 0 {
		t.Fatalf("словарь способов объявлен ВТОРОЙ раз — %d находок:\n  %s\n\n"+
			"Имена способов объявляются один раз, вместе с правилом (%s); прочие читают `assurance.Methods()`, "+
			"а ограничение схемы перечисляет только имена словаря.",
			len(findings), strings.Join(findings, "\n  "), check.AssuranceHomeRel)
	}
}
