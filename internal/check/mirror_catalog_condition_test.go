// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mirror_catalog_condition_test.go — ГЕЙТ КЛАССА: в непроверочном коде каждый
// оператор, ВВОДЯЩИЙ строку зеркала ресурсов, спрашивает каталог тем же
// условием, каким его спрашивает эталонная полоса, либо назван исключением с
// причиной (задача #17, порт семейства `mirrorcatalogcondition`).
//
// Предмет, довод в пользу сверки полос между собой и границы разбора — в шапке
// `mirror_catalog_condition.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// mirror_catalog_condition_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// mirrorConditionLedger — ведомость исключений: писатель → ПРИЧИНА, по которой
// он вправе не спрашивать каталог.
//
// Сегодня она ПУСТА, и это цель, а не недосмотр. Пустая ведомость проходит —
// отказ на ней толкал бы держать запись ради зелёного.
//
// Запись, которой больше нечего исключать (писатель условие получил либо исчез
// из дерева), — НАХОДКА: послабление обязано истекать само, иначе оно переживает
// свой предмет, оставаясь на вид рабочим.
var mirrorConditionLedger = map[string]string{}

// TestMirrorRowCatalogConditionReachesEveryWriter — имя сохранено дословно с
// монорепо.
func TestMirrorRowCatalogConditionReachesEveryWriter(t *testing.T) {
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
		t.Fatalf("состав дерева не установлен: %v — «ноль находок» здесь означало бы "+
			"«ноль прочитанного»", err)
	}

	// Обход и его отказ на пустоте держит ОДНА функция — `MirrorCandidateCorpus`.
	// Прежде он строился здесь, в теле пробы, и премиса «осмотрено ноль файлов»
	// стояла НИЖЕ разбора: ветвь читалась глазами и не исполнялась ни разу —
	// корнем ей служил корень своего модуля, и подать ей пустое дерево было
	// нечем (задача #17).
	corpus, err := check.MirrorCandidateCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	var (
		filesRead = len(corpus)
		mentions  int
		writes    []check.MirrorWrite
	)
	for _, rel := range corpus.Rels() {
		body := corpus[rel]
		if !strings.Contains(body, check.ResourceMirrorTable) {
			continue
		}
		w, m, perr := check.MirrorWritesIn(rel, body)
		if perr != nil {
			t.Fatalf("разбор %s: %v — файл индекса не разобран, и его молчание ничего не значит",
				rel, perr)
		}
		mentions += m
		for _, one := range w {
			one.File = rel
			writes = append(writes, one)
		}
	}

	// Премиса ВТОРОЙ половины остаётся: она не про обход, а про то, что предмет
	// ещё встречается в прочитанном.
	if mentions == 0 {
		t.Fatalf("имя %q не встречается в непроверочном коде НИ РАЗУ — предмета у гейта нет: "+
			"либо таблица переименована (правь константу вместе с ней), либо её перестали и "+
			"читать, и писать", check.ResourceMirrorTable)
	}

	rep := check.MirrorConditionReport(writes, mirrorConditionLedger)

	// Перепись печатает ОБА числа. Одно скрывает ровно тот случай, ради которого
	// гейт заведён: «несут 1» без «полос 3» читается как исправность.
	t.Logf("осмотрено непроверочных файлов Go: %d; литералов, называющих %s: %d; "+
		"операторов записи найдено: %d; из них ВВОДЯЩИХ строку — полос: %d; "+
		"несут условие эталонной полосы: %d из %d; погашено ведомостью: %d; "+
		"записей в ведомости: %d",
		filesRead, check.ResourceMirrorTable, mentions, len(writes), rep.Lanes,
		rep.Carriers, rep.Lanes, rep.Exempt, len(mirrorConditionLedger))
	byVerb := map[string]int{}
	for _, w := range writes {
		byVerb[w.Verb]++
	}
	for _, v := range check.MirrorWriteVerbs {
		t.Logf("  операторов «%s»: %d (вводит строку: %t)", v.Verb, byVerb[v.Verb], v.Introduces)
	}
	for _, k := range rep.LaneKeys {
		t.Logf("  полоса: %s", k)
	}
	if len(rep.Required) == 0 {
		// Без этой строки «несут 3 из 3» читается как исполненность, тогда как
		// требовать сегодня нечего: условие ещё не написано. Число, которое
		// ничего не утверждает, обязано само об этом сказать.
		t.Logf("условие эталонной полосы ПУСТО: ни один оператор эталона не называет "+
			"kaname.catalog_* — требовать сегодня нечего, и «несут %d из %d» исполненностью НЕ "+
			"является. Сверка вооружена: в день, когда условие приедет в %s, гейт покраснеет "+
			"на остальных полосах поимённо",
			rep.Carriers, rep.Lanes, check.MirrorReferenceLane)
	} else {
		t.Logf("условие эталонной полосы: %v", rep.Required)
	}

	if rep.ReferenceMissing {
		t.Fatalf("эталонной полосы %q среди вводящих писателей НЕТ — сверять «тем же условием» "+
			"не с чем. Каталог переехал, а константа осталась: молчание здесь означало бы, "+
			"что гейт умер вместе с координатой", check.MirrorReferenceLane)
	}
	if rep.Lanes == 0 {
		t.Fatal("вводящих писателей зеркала ноль при непустой переписи упоминаний — предмет " +
			"сверки исчез, а гейт остался бы зелёным")
	}

	for _, f := range rep.Findings {
		t.Error(f)
	}
	for _, s := range rep.Stale {
		t.Error(s)
	}
}
