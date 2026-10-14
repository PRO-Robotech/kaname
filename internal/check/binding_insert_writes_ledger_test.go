// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_insert_writes_ledger_test.go — ГЕЙТ КЛАССА: каждая вставка привязки
// доступа в непроверочном коде пишет ведомость выпущенных кортежей той же
// функцией (kaname#670, класс kaname#665).
//
// Снятие выдачи симметрично ведомости; вставка без неё оставляет выпущенные
// кортежи фактами модели прав после снятия выдачи и её области. Разбор и его
// граница — binding_insert_writes_ledger.go; способность упасть и смолчать —
// binding_insert_writes_ledger_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestEveryAccessBindingInsertWritesItsLedger(t *testing.T) {
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

	var (
		census   check.BindingInsertCensus
		findings []string
	)
	for _, rel := range corpus.Rels() {
		sites, c, err := check.ScanBindingInsertLedger(rel, []byte(corpus[rel]))
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		census.Add(c)
		for _, s := range sites {
			if !s.WritesLedger {
				findings = append(findings, s.String())
			}
		}
	}
	t.Logf("перепись: файлов прод-кода прочитано %d; вставок привязки доступа %d, из них с записью ведомости %d",
		census.Files, census.Inserts, census.WithLedger)
	if census.Inserts == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: вставок привязки доступа в обходе 0 из %d файлов — "+
			"форма вызова сменилась, и «находок нет» значило бы «не прочитано ни одной»", census.Files)
	}
	if len(findings) != 0 {
		t.Fatalf("вставка привязки доступа без ведомости выпущенных кортежей — %d находок:\n  %s\n\n"+
			"Снятие выдачи (штатное и дренажом области) снимает ровно записанное в ведомости; выдача без неё "+
			"оставляет свои кортежи фактами модели прав после снятия (kaname#665, #670). Пишите ведомость "+
			"InsertEmittedTuples в той же транзакции из того же набора, что эмиссия.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
