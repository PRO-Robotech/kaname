// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_verifier_single_test.go — Ф13-31: сверка утверждения ключа в дереве
// ОДНА; полосы её зовут. Разбор — assertion_verifier_single.go; способность
// упасть и смолчать — assertion_verifier_single_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestAssertionVerificationIsDeclaredOnce(t *testing.T) {
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
	findings, c, err := check.JudgeAssertionVerifiers(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов осмотрено %d · объявлений сверки %d %v · вызывающих %d %v",
		c.Files, len(c.Declarations), c.Declarations, len(c.Callers), c.Callers)
	if len(c.Declarations) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявлений сверки подписи в %s ноль — предмета нет, и «находок ноль» "+
			"значило бы «прочитано ноль»", check.AssertionVerifierHomeRel)
	}
	if len(c.Callers) < 2 {
		t.Errorf("вызывающих проверяющего %d %v, ожидалось не меньше двух — полоса утверждения из сессии (Ф7) и "+
			"полоса входа (Ф13); полоса, переставшая звать проверяющего, сверяет утверждение чем-то другим",
			len(c.Callers), c.Callers)
	}
	if len(findings) > 0 {
		t.Fatalf("находок %d:\n  %s", len(findings), strings.Join(findings, "\n  "))
	}
}
