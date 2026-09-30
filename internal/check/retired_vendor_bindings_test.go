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

// TestRetiredVendorBindingsDoNotGrow — дерево службы против ведомости привязок
// к снимаемому провайдеру личности: рост краснеет с координатой, убыль требует
// снизить запись тем же изменением, запись без предмета снимается. Перепись и
// перечень печатаются всегда.
func TestRetiredVendorBindingsDoNotGrow(t *testing.T) {
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
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не установлен: %v — «находок ноль» "+
			"здесь означало бы «прочитано ноль»", err)
	}
	corpus, err := check.CorpusFrom(tree, func(string) bool { return true })
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	verdict, err := check.JudgeRetiredVendorBindings(corpus, check.RetiredVendorLedger)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(verdict.Census)
	// Предпосылка законной формы: каталог истории схемы — там, где его ищет
	// судья. Переехавший каталог дал бы «миграций 0», и форма молча перестала
	// бы действовать — снятие столбца снова выглядело бы ростом.
	if verdict.Census.HistoryMigrations == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в %s не прочитано ни одной миграции — каталог истории "+
			"схемы переехал, а константа пути осталась", check.RetiredVendorSchemaHistoryDir)
	}
	t.Logf("сняты историей схемы, %d: %v", len(verdict.RemovedBySchemaHistory), verdict.RemovedBySchemaHistory)
	t.Logf("перечень (привязок · файл), файлов %d:\n%s", verdict.Census.Files, verdict.Roster())
	for _, f := range verdict.Findings {
		t.Error(f)
	}
}
