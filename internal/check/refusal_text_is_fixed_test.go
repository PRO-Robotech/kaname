// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// refusal_text_is_fixed_test.go — гейт ДЕРЕВА: ни один переводчик службы не
// отдаёт вызывающему текст ПОЛУЧЕННОЙ ошибки на полосах, чья цепочка ведёт к
// чужому производителю (задача PRO-Robotech/kacho#2464).
//
// Предмет, устройство распознавателя и граница популяции — в шапке ядра
// (`refusal_text_is_fixed.go`); здесь они не пересказываются, чтобы два места
// об одном предмете не разошлись.
//
// Координата приводится к ПОСАДКЕ: в монорепо это `services/iam`, в
// самостоятельном клоне — корень модуля. Приведение не находит дерева —
// «условие не создано», а не находка о продукте.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// iamServiceTreeRel — поддерево, которое обходит гейт: прод-код службы целиком.
const iamServiceTreeRel = "services/iam"

func TestRefusalTextOnForeignCauseLanesIsFixed(t *testing.T) {
	dir := treePath(t, iamServiceTreeRel)

	files, ferr := treecorpus.UnderWithSuffix(dir, ".go")
	if ferr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не взят: %v", ferr)
	}

	census, findings, err := check.ScanFixedRefusalTexts(dir, files)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Перепись — ДО вердикта и независимо от него.
	t.Log(census.String())

	// Обход пуст ⇒ вердикт беспредметен.
	if census.Files == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО файла Go под %s — вердикт беспредметен: "+
			"«ноль находок» здесь неотличимо от «ноль прочитанного»", iamServiceTreeRel)
	}
	// Популяция пуста ⇒ судить нечего. Это НЕ достижение цели: цель гейта —
	// «текст фиксирован», а не «полос чужой причины в службе не осталось».
	// Ноль здесь означает, что распознаватель перестал узнавать конструкцию.
	if census.Population == 0 {
		t.Fatalf("в популяции НОЛЬ конструкций при %d разобранных файлах и %d "+
			"найденных конструкциях статуса — распознаватель перестал узнавать "+
			"полосы чужой причины, и его молчание неотличимо от чистого дерева",
			census.Files, census.Constructions)
	}

	if len(findings) == 0 {
		return
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "\n  %s:%d — codes.%s, текст: %s", f.File, f.Line, f.Code, f.Expr)
	}
	t.Errorf("текст отказа на полосе ЧУЖОЙ причины не доказан фиксированным (%d):%s\n\n"+
		"Признак недоступности и внутренний отказ ставят база, сосед и гейт прав; "+
		"незамапленная ошибка драйвера несёт в себе строку подключения, и подставленный "+
		"в текст статуса текст ПОЛУЧЕННОЙ ошибки уезжает вызывающему. "+
		"Умолчание обязано быть фиксированным: берите текст у канонического переводчика "+
		"(shared.UnavailableMessage) либо ставьте свой строковый литерал, "+
		"а подробность оставляйте цепочке и журналу.",
		len(findings), b.String())
}
