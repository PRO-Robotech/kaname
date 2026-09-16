// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_level_sole_writer_test.go — ГЕЙТ КЛАССА: уровень уверенности сессии
// производит ТОЛЬКО правило, а как СОСТОЯНИЕ он лежит только в записи сессии
// (приёмка Ф11 `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р1, §7 инв. 4, §8 строка «гейт „правило одно“ — служба»; задача kacho#1280).
//
// # Предмет находки — уровень как СОСТОЯНИЕ вне записи сессии либо от писателя,
// кроме правила
//
// Половина по коду: значение уровня производит только правило (`LevelOf`), на
// любом пути выдачи. Константа оси, употреблённая как ЗНАЧЕНИЕ (присваивание,
// поле литерала, возврат, аргумент) вне дома правила, и преобразование строки
// в уровень мимо правила — находка с координатой; сравнение с константой и
// перечень case — чтение, гейт молчит. Судится по ТИПУ уровня, объявленному
// вместе с правилом, а не по имени поля. Поле этого типа в хранимой структуре,
// кроме записи сессии и четырёх названных копий, — находка: уровень в строке
// способа входа был бы неверен для каждого утверждения ключа без проверки
// пользователя (Р1, Н60).
//
// Половина по миграциям: объявление оси уровня в схеме — перечень значений
// ровно «1», «2», «3» — одно, при таблице сессии. Столбец с таким объявлением в
// любой другой таблице — находка. Половина нужна потому, что колонку с
// умолчанием пишет база, и писателя в коде у неё нет: половина по коду её не
// видит by construction.
//
// # Ведомости — самоистекают
//
// Держатели поля уровня и таблица оси названы поимённо ниже; запись, у которой
// больше нет предмета, — находка. Сегодня обе ведомости ПУСТЫ: записи сессии в
// дереве нет (Ф3, kacho#1269), и первый держатель входит сюда тем же изменением,
// что таблица сессии.
//
// # Граница названа
//
// Голый текстовый столбец без объявления оси половина по миграциям не видит;
// его писателя, если он есть, видит половина по коду. Уровень, собранный
// выражением из строки не через тип оси, разбор по типу не видит — это и есть
// довод держать значение типом, а не строкой.
//
// Способность упасть и смолчать доказана инъекцией —
// assurance_level_sole_writer_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// assuranceLevelHolders — структуры, которым поле типа уровня ЗАКОННО: запись
// сессии (состояние) и её чтения — ответ службы краю о сессии, ответ церемонии
// повышения, запись журнала повышения, токен из нашей сессии (приёмка Р1, §7
// инв. 4). Ключ — `<каталог от корня модуля>:<имя типа>`, значение — какая из
// пяти ролей. Перечень закрыт и самоистекает: запись без типа в дереве — находка.
//
// Сегодня пуст: ни записи сессии, ни её чтений в дереве нет (Ф3).
var assuranceLevelHolders = map[string]string{}

// assuranceAxisHomeTable — таблица, при которой объявлена ось уровня в схеме
// (запись сессии, Р1). Пусто, пока таблицы сессии нет: тогда ЛЮБОЕ объявление
// оси в схеме — находка. Заполняется тем же изменением, что таблица.
const assuranceAxisHomeTable = ""

func TestAssuranceLevelHasOneWriterAndOneHome(t *testing.T) {
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

	// ── половина по коду ────────────────────────────────────────────────────
	goCorpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	var (
		census    check.LevelUseCensus
		findings  []string
		holders   = map[string]check.LevelUse{}
		homeFiles int
	)
	for _, rel := range goCorpus.Rels() {
		if strings.HasPrefix(rel, check.AssuranceHomeRel+"/") {
			homeFiles++
			continue
		}
		uses, c, err := check.ScanAssuranceLevelUses(rel, []byte(goCorpus[rel]), check.AssuranceHomeImport)
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		census.Add(c)
		for _, u := range uses {
			switch u.Kind {
			case check.LevelUseProduction, check.LevelUseConversion:
				findings = append(findings, u.String())
			case check.LevelUseStructField:
				key := path.Dir(rel) + ":" + u.Holder
				holders[key] = u
				if _, ok := assuranceLevelHolders[key]; !ok {
					findings = append(findings, fmt.Sprintf("%s — поле уровня в структуре %q, которой нет в ведомости "+
						"держателей: уровень как состояние живёт только в записи сессии и её четырёх чтениях", u, u.Holder))
				}
			}
		}
	}
	for key, role := range assuranceLevelHolders {
		if _, ok := holders[key]; !ok {
			findings = append(findings, fmt.Sprintf("запись ведомости держателей %q (%s) больше нечего исключать: "+
				"структуры с полем уровня по этому ключу в дереве нет", key, role))
		}
	}
	if homeFiles == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дома правила %s в обходе нет — судить писателей не о чем", check.AssuranceHomeRel)
	}

	// ── половина по миграциям ───────────────────────────────────────────────
	migs, err := check.MigrationCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	files := migs.Rels()
	sort.Slice(files, func(i, j int) bool {
		return migrationOrdinal(path.Base(files[i])) < migrationOrdinal(path.Base(files[j]))
	})
	var (
		schemaFiles int
		axisColumns []check.AxisColumnSite
	)
	for _, rel := range files {
		schemaFiles++
		axisColumns = append(axisColumns, check.ScanAssuranceAxisColumns(rel, migrations.MigrationUpSection(migs[rel]))...)
	}
	homeSeen := false
	for _, c := range axisColumns {
		if assuranceAxisHomeTable != "" && c.Table == assuranceAxisHomeTable {
			homeSeen = true
			continue
		}
		findings = append(findings, fmt.Sprintf("%s — объявление оси уровня вне таблицы сессии (%q): уровень как "+
			"состояние лежит только в записи сессии", c, assuranceAxisHomeTable))
	}
	if assuranceAxisHomeTable != "" && !homeSeen {
		findings = append(findings, fmt.Sprintf("ведомость называет таблицу оси %q, а объявления оси при ней в схеме нет", assuranceAxisHomeTable))
	}

	t.Logf("перепись: файлов прод-кода прочитано %d (дом правила — %d), импортирующих дом %d; обращений к оси %d — "+
		"сравнений %d, производств %d, преобразований %d, вызовов правила %d; структур с полем уровня %d (в ведомости %d); "+
		"файлов миграций %d, столбцов оси %d",
		census.Files+homeFiles, homeFiles, census.ImportingHome, census.AxisReferences,
		census.Comparisons, census.Productions, census.Conversions, census.RuleCalls,
		len(holders), len(assuranceLevelHolders), schemaFiles, len(axisColumns))

	if len(findings) != 0 {
		t.Fatalf("у уровня уверенности появился ВТОРОЙ писатель либо второе место хранения — %d находок:\n  %s\n\n"+
			"Уровень производит только правило (`assurance.LevelOf`), хранится только в записи сессии; копии — "+
			"чтения записи, названные в ведомости держателей.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
