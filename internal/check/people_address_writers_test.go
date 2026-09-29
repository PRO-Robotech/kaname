// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers_test.go — ГЕЙТ КЛАССА: непроверочный код службы не
// пишет адрес человека (`kaname.users.email`) в существующую строку — часть (б)
// условия 7 чек-листа поверхности подтверждения адреса (задача
// PRO-Robotech/kaname#464). Предмет, формы записи и границы — в шапке
// `people_address_writers.go`.
//
// # Молчание гейта об отсутствии обязано быть отличимо от слепоты
//
// Предмет гейта — ОТСУТСТВИЕ, поэтому рядом стоит положительная половина того
// же разбора по тому же дереву: списки SET обеих ветвей, которые в дереве есть
// (UPDATE и ON CONFLICT), прочитаны, и колонки, которые они пишут, названы. Ноль
// прочитанных списков ветви — «не исполнялось», а не «годно». Ветвь MERGE в
// дереве пуста: её держит инъекция.
//
// Способность упасть и смолчать доказана инъекцией —
// people_address_writers_injection_test.go: она подаёт в тот же вердикт
// настоящий файл дерева с одним изменённым фактом и синтетику по каждой
// законной форме записи.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// peopleAddressCorpus — непроверочный Go дерева по индексу git.
func peopleAddressCorpus(t *testing.T) check.TreeCorpus {
	t.Helper()
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
	return corpus
}

// TestPeopleAddressHasNoWriterInServiceCode — мест записи адреса человека в
// существующую строку в непроверочном коде службы ноль; существующие места
// судятся наравне с новыми, исключений по имени нет.
func TestPeopleAddressHasNoWriterInServiceCode(t *testing.T) {
	t.Parallel()

	findings, census, err := check.JudgePeopleAddressWriters(peopleAddressCorpus(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: %s", census)

	for _, branch := range []string{check.SetListUpdate, check.SetListConflict} {
		if census.SetLists[branch] == 0 {
			t.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: списков SET ветви %s над строками людей прочитано 0 — "+
				"распознаватель слеп к ветви либо её операторы сняты; молчание о писателях адреса в ней "+
				"сказано ни о чём (%s)", branch, census)
		}
	}
	if len(census.Columns) == 0 {
		t.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: прочитанные списки SET не назвали ни одной колонки строк людей (%s)", census)
	}

	if len(findings) != 0 {
		t.Fatalf("непроверочный код службы пишет адрес человека в существующую строку — %d находок:\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}
