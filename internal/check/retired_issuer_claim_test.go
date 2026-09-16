// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestRetiredIssuerIsNamedAsActingOnlyInATombstone — перепись прозы дерева:
// утверждение «прежний OAuth-сервер остаётся подписантом/издателем» законно
// только как надгробие.
func TestRetiredIssuerIsNamedAsActingOnlyInATombstone(t *testing.T) {
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
	corpus, err := check.CorpusFrom(tree, check.RetiredIssuerProseFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	findings, census, err := check.JudgeRetiredIssuerClaims(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(census)
	if census.Mentions == 0 {
		t.Fatalf("строк с именем прежнего издателя прочитано 0 при %d файлах — либо "+
			"компонент снят целиком (тогда снимите и этот гейт вместе с предметом), "+
			"либо распознаватель ослеп", census.Files)
	}
	for _, f := range findings {
		t.Error(f)
	}
}
