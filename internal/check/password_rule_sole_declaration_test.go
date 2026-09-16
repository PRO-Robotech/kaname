// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestPasswordRule_F3_32_IsDeclaredOnceAndEveryLaneCallsIt — Ф3-32: объявление
// правила пароля одно, и оно в своём доме; перепись печатает «объявлений 1 ·
// вызывающих M». Пустой обход и дом без объявления — отказ, а не идеал.
func TestPasswordRule_F3_32_IsDeclaredOnceAndEveryLaneCallsIt(t *testing.T) {
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
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	var census check.PasswordRuleCensus
	for _, rel := range corpus.Rels() {
		c, err := check.ScanPasswordRule(rel, []byte(corpus[rel]))
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		census.Add(c)
	}

	homes := census.HomeFiles()
	t.Logf("перепись: файлов прод-кода осмотрено %d · объявлений правила %d в файлах %d (%s) · вызывающих %d",
		census.Files, len(census.Declarations), len(homes), strings.Join(homes, ", "), len(census.Callers))

	if census.Files == 0 {
		t.Fatal("обход пуст — вердикт беспредметен")
	}
	if len(census.Declarations) == 0 {
		t.Fatalf("дом правила %s объявления не несёт: распознаватель мёртв либо правило снято — "+
			"«второго объявления нет» здесь означало бы «правила нет вовсе»", check.PasswordRuleHomeRel)
	}
	if foreign := census.Foreign(check.PasswordRuleHomeRel); len(foreign) > 0 {
		lines := make([]string, 0, len(foreign))
		for _, f := range foreign {
			lines = append(lines, "  "+f.String())
		}
		t.Errorf("правило пароля объявлено ВТОРОЙ раз вне дома %s:\n%s\n"+
			"Три полосы, меняющие материал, зовут ОДНО правило: второе разошлось бы с первым молча, "+
			"и пароль, принятый на одной полосе, отвергался бы на другой", check.PasswordRuleHomeRel,
			strings.Join(lines, "\n"))
	}
	if len(census.Callers) == 0 {
		t.Fatal("вызывающих правила ноль: полоса смены пароля обязана звать его — правило без вызывающего есть правило на бумаге")
	}
	for _, c := range census.Callers {
		if c.Rel == check.PasswordRuleHomeRel {
			t.Errorf("правило зовёт само себя: %s", c)
		}
	}
}
