// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers_test.go — ГЕЙТ КЛАССА: непроверочный код службы не
// пишет адрес человека (`kaname.users.email`) в существующую строку, а миграция
// службы не пишет ни адреса, ни отметки его подтверждения
// (`kaname.users.email_verified_at`) в строки, которых сама не заводит — часть
// (б) условия 7 чек-листа поверхности подтверждения адреса (задачи
// PRO-Robotech/kaname#464, #471). Предмет, формы записи и границы — в шапках
// `people_address_writers.go` и `people_address_writers_migrations.go`.
//
// # Молчание гейта об отсутствии обязано быть отличимо от слепоты
//
// Предмет гейта — ОТСУТСТВИЕ, поэтому рядом стоит положительная половина того
// же разбора по тому же дереву, по каждому виду входа: в Go — списки SET обеих
// ветвей, которые в дереве есть (UPDATE и ON CONFLICT), и колонки, которые они
// пишут; в миграциях — список SET, ALTER TABLE над строками людей, тела
// подпрограмм, триггер над строками людей и присваивание строке триггера. Ноль
// прочитанного у любой из них — «не исполнялось», а не «годно». Ветвь MERGE и
// формы определения схемы, пишущие предмет, в дереве пусты: их держит инъекция.
//
// Способность упасть и смолчать доказана инъекцией —
// people_address_writers_injection_test.go (Go) и
// people_address_writers_migration_injection_test.go (миграции и ведомость):
// они подают в тот же вердикт настоящие файлы дерева с одним изменённым фактом
// и синтетику по каждой законной форме записи.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// peopleAddressRoot — корень модуля.
func peopleAddressRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	return root
}

// peopleAddressCorpus — непроверочный Go и миграции дерева по индексу git.
func peopleAddressCorpus(t *testing.T) check.TreeCorpus {
	t.Helper()
	tree, err := treecorpus.NewTree(peopleAddressRoot(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	corpus, err := check.CorpusFrom(tree, check.PeopleAddressInput)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return corpus
}

// TestPeopleAddressHasNoWriterInServiceCode — мест записи адреса человека в
// существующую строку в непроверочном коде службы ноль, мест записи адреса и
// отметки в миграциях сверх названных ведомостью применённых ноль; места Go
// судятся наравне с новыми, исключений по имени у Go нет.
func TestPeopleAddressHasNoWriterInServiceCode(t *testing.T) {
	t.Parallel()

	findings, census, err := check.JudgePeopleAddressWriters(peopleAddressCorpus(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: %s", census)
	for _, a := range census.Applied {
		t.Logf("названо ведомостью: %s", a)
	}

	for _, branch := range []string{check.SetListUpdate, check.SetListConflict} {
		if census.Go.SetLists[branch] == 0 {
			t.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: списков SET ветви %s над строками людей в Go прочитано 0 — "+
				"распознаватель слеп к ветви либо её операторы сняты; молчание о писателях адреса в ней "+
				"сказано ни о чём (%s)", branch, census)
		}
	}
	if len(census.Go.Columns) == 0 {
		t.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: прочитанные списки SET Go не назвали ни одной колонки строк людей (%s)", census)
	}
	m := census.Migrations
	for _, c := range []struct {
		name string
		n    int
	}{
		{"списков SET над строками людей", m.SetLists[check.SetListUpdate]},
		{"колонок, которые пишут списки SET", len(m.Columns)},
		{"ALTER TABLE над строками людей", m.TableAlters},
		{"тел подпрограмм", m.Routines},
		{"триггеров над строками людей", m.TriggersOverPeople},
		{"присваиваний строке триггера", m.RowAssignments},
		{"возвратов из подпрограмм триггера", m.TriggerReturns},
		{"мест, названных ведомостью и сверенных", len(census.Applied)},
	} {
		if c.n == 0 {
			t.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: в миграциях %s — 0: распознаватель слеп к этой форме либо её предмет "+
				"снят; молчание о писателях адреса и отметки в миграциях сказано ни о чём (%s)", c.name, census)
		}
	}
	if census.LedgerOutOfCorpus != 0 || len(census.Applied) != census.LedgerEntries {
		t.Errorf("ведомость применённых миграций названа не по этому дереву: записей %d, сверено %d, о файлах вне корпуса %d (%s)",
			census.LedgerEntries, len(census.Applied), census.LedgerOutOfCorpus, census)
	}

	if len(findings) != 0 {
		t.Fatalf("код службы либо миграция пишет предмет мимо глагола — %d находок:\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// appliedLedgerPremise — предпосылка ведомости: каждый её файл ПРИМЕНЁН (лежит
// в стволе) и НЕ ТРОНУТ (у головы тот же, что в стволе). Проверки приходят
// параметром: инъекция подаёт их синтетикой.
func appliedLedgerPremise(rels []string, onTrunk, unchanged func(rel string) bool) []string {
	var out []string
	for _, rel := range rels {
		switch {
		case !onTrunk(rel):
			out = append(out, rel+" — ведомость называет миграцию, которой в стволе нет: новая миграция места "+
				"предмета не несёт, и ведомость её не прощает")
		case !unchanged(rel):
			out = append(out, rel+" — ведомость называет миграцию, изменённую относительно ствола: применённая "+
				"миграция не правится (ban #5)")
		}
	}
	return out
}

// TestPeopleAddressAppliedLedgerNamesOnlyAppliedMigrations — ведомость называет
// только применённые и нетронутые миграции: иначе запись в ней стала бы путём
// узаконить нового писателя.
func TestPeopleAddressAppliedLedgerNamesOnlyAppliedMigrations(t *testing.T) {
	t.Parallel()
	root := peopleAddressRoot(t)
	rels := check.PeopleAppliedMigrationRels()
	if len(rels) == 0 {
		t.Log("ведомость применённых миграций пуста — сверять нечего: это цель, а не отказ")
		return
	}
	base, ok := trunkRef(root)
	if !ok {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): ствол %s в этом клоне не разрешается — применённость %d файлов "+
			"ведомости установить нечем; вердикт гейта дерева от ствола не зависит и снят отдельно", trunkRefName, len(rels))
	}
	onTrunk := func(rel string) bool {
		return gitenv.Command(root, "cat-file", "-e", base+":"+rel).Run() == nil
	}
	unchanged := func(rel string) bool {
		return gitenv.Command(root, "diff", "--quiet", base, "HEAD", "--", rel).Run() == nil
	}
	t.Logf("файлов ведомости %d, сверено со стволом %s", len(rels), base)
	if findings := appliedLedgerPremise(rels, onTrunk, unchanged); len(findings) != 0 {
		t.Fatalf("предпосылка ведомости применённых миграций не держится — %d:\n  %s", len(findings), strings.Join(findings, "\n  "))
	}
}

// TestPeopleAddressAppliedLedgerPremiseInjection — предпосылка ведомости
// краснеет на файле вне ствола и на изменённом, молчит на применённом и
// нетронутом.
func TestPeopleAddressAppliedLedgerPremiseInjection(t *testing.T) {
	t.Parallel()
	applied := "internal/migrations/20000101000000_applied.sql"
	fresh := "internal/migrations/29991231235959_fresh.sql"
	edited := "internal/migrations/20000101000001_edited.sql"
	onTrunk := func(rel string) bool { return rel != fresh }
	unchanged := func(rel string) bool { return rel != edited }
	if got := appliedLedgerPremise([]string{applied}, onTrunk, unchanged); len(got) != 0 {
		t.Errorf("применённая и нетронутая миграция дала находки: %v", got)
	}
	got := appliedLedgerPremise([]string{applied, fresh, edited}, onTrunk, unchanged)
	if len(got) != 2 || !strings.HasPrefix(got[0], fresh) || !strings.HasPrefix(got[1], edited) {
		t.Errorf("новая и изменённая миграция в ведомости — ждали две находки с координатой: %v", got)
	}
}
