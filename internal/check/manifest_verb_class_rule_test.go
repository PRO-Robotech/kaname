// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// manifest_verb_class_rule_test.go — ДВА ГЕЙТА КЛАССА о свойствах дерева,
// которых проба пакета утверждать не может (задача #17, порт семейства
// `manifestverbclassrule`).
//
// Оба предмета и устройство распознавателей — в шапке
// `manifest_verb_class_rule.go`; здесь они не пересказываются.
//
// Способность обоих упасть и смолчать доказана инъекцией —
// manifest_verb_class_rule_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// verbClassProdGoFiles — не-тестовые исходники Go модуля, по одному разу
// прочитанные с диска.
//
// Общая для обоих гейтов: два обхода одного дерева разошлись бы по области
// молча, и вердикты стали бы о разных множествах файлов.
func verbClassTree(t *testing.T) (root string, tree *treecorpus.Tree) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err = platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err = treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	return root, tree
}

// TestVerbClassRuleIsDeclaredOnce — правило объявлено РОВНО ОДИН РАЗ.
//
// Ноль объявлений — тоже находка, и она о распознавателе: «объявлений ноль»
// означало бы, что гейт ослеп, а не что правило исчезло.
func TestVerbClassRuleIsDeclaredOnce(t *testing.T) {
	t.Parallel()
	_, tree := verbClassTree(t)

	// Обход и его отказ на пустоте держит ОДНА функция — `VerbClassRuleCorpus`
	// (задача #17).
	corpus, err := check.VerbClassRuleCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	var declarations []string
	scanned := 0
	for _, rel := range corpus.Rels() {
		found, err := check.ScanClassRuleDeclarations(rel, []byte(corpus[rel]))
		if err != nil {
			// Неразбираемый файл — не находка: он и собраться не может. Но и в
			// объём осмотренного он не засчитывается.
			t.Logf("не разобран (пропущен): %v", err)
			continue
		}
		scanned++
		declarations = append(declarations, found...)
	}

	if scanned == 0 {
		t.Fatal("ни один прочитанный файл Go не РАЗОБРАЛСЯ — вердикт был бы свойством " +
			"разбора, а не дерева")
	}
	switch {
	case len(declarations) == 0:
		t.Errorf("объявлений правила «класс действия из его имени» НОЛЬ при %d прочитанных "+
			"файлах — либо правило сняли, либо распознаватель ослеп; в обоих случаях "+
			"молчание про второе объявление не значит ничего", scanned)
	case len(declarations) > 1:
		t.Errorf("правило «класс действия из его имени» объявлено %d раза:\n  %s\n\n"+
			"Второе объявление разойдётся с первым МОЛЧА: обе стороны отвечают одинаково "+
			"на входе, где правило совпадает. Оставь одно — `manifest.ClassOfCanonicalVerb` — "+
			"и зови его; остальные снимай вместе с их вызывающими.",
			len(declarations), strings.Join(declarations, "\n  "))
	}
	t.Logf("перепись: прочитано не-тестовых файлов Go %d · объявлений правила %d (%s)",
		scanned, len(declarations), strings.Join(declarations, ", "))
}

// TestObjectTypeIsNeverDerivedFromTheResourceName — правило вывода снято, и
// возвращено тихо быть не может.
//
// Признак прямой: поле типа объекта в прод-коде загрузчика только ЧИТАЕТСЯ. Как
// только оно начнёт куда-то ПРИСВАИВАТЬСЯ, значит появился путь, который его
// восстанавливает, — а восстанавливать нечем: правило не действует у части
// записей закрытой таблицы, и автор всё равно обязан знать, попал ли его ресурс
// в исключение.
func TestObjectTypeIsNeverDerivedFromTheResourceName(t *testing.T) {
	t.Parallel()
	_, tree := verbClassTree(t)

	// Обход загрузчика и его отказ на пустоте держит ОДНА функция —
	// `ManifestLoaderCorpus` (задача #17): прежде премиса «прод-файлов
	// загрузчика не прочитано ни одного» стояла в теле пробы и не исполнялась.
	loader, err := check.ManifestLoaderCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: загрузчик %s: %v", check.ManifestLoaderDir, err)
	}

	parsed, reads := 0, 0
	var writes []string
	for _, rel := range loader.Rels() {
		r, w, err := check.ScanObjectTypeUses(rel, []byte(loader[rel]))
		if err != nil {
			t.Fatalf("%v", err)
		}
		parsed++
		reads += r
		writes = append(writes, w...)
	}

	if parsed == 0 {
		t.Fatalf("прод-файлов загрузчика по пути %s не прочитано ни одного — "+
			"«присваиваний ноль» было бы свойством обхода, а не дерева", check.ManifestLoaderDir)
	}
	// Положительный контроль: поле обязано хотя бы ЧИТАТЬСЯ. Ноль чтений означал
	// бы, что распознаватель не находит поля вовсе, и тогда «ноль присваиваний»
	// ничего не значит.
	if reads == 0 {
		t.Fatalf("поле типа объекта не читается ни в одном из %d прод-файлов — "+
			"распознаватель ослеп", parsed)
	}
	for _, w := range writes {
		t.Errorf("полю типа объекта ПРИСВАИВАЮТ в %s — значит завёлся путь, который его "+
			"восстанавливает. Правило вывода «тип = <модуль>_<ресурс>» снято замером, и "+
			"живёт такое правило сразу в ДВУХ местах — в генераторе (когда опускать ключ) "+
			"и здесь (как восстановить).", w)
	}
	t.Logf("перепись: прод-файлов загрузчика %d · чтений поля %d · присваиваний %d",
		parsed, reads, len(writes))
}
