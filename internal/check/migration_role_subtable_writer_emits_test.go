// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_role_subtable_writer_emits_test.go — ГЕЙТ §3.2а приёмки
// `catalog-consequence-reaches-role-readers.md` (kaname#76): миграция, пишущая
// подтаблицы роли, зовёт функцию события «состав роли изменился» в том же
// разделе.
//
// Судит дерево целиком на каждом прогоне: популяция — миграции новее той, что
// заводит функцию, и её граница выводится обходом. Писатели вне популяции
// печатаются поимённо и сверяются с перечнем приёмки: их набор неподвижен
// (применённые миграции не правятся, новые попадают в популяцию), поэтому
// расхождение означает, что разбор перестал видеть форму записи, — то есть
// слепоту, а не находку.
//
// Способность упасть и смолчать — migration_role_subtable_writer_emits_injection_test.go.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// roleSubtableWritersOutsidePopulation — писатели подтаблиц роли, стоящие НИЖЕ
// границы популяции. Перечень закрыт: прибавиться ему неоткуда (новое попадает
// в популяцию), убыть тоже (применённые миграции не правятся).
//
// Приёмка §3.2а называет ДВА файла на ревизии своего измерения; третий —
// `20261018030000` (правка `role_rule_selectors.verbs_by_type`) — лёг в цепочку
// после той ревизии и стоит ниже границы: события о нём не требуется, а
// перепись обязана его назвать.
var roleSubtableWritersOutsidePopulation = []string{
	check.MigrationsDirRel + "/0001_initial.sql",
	check.MigrationsDirRel + "/20260914120000_role_read_relation_leaves_the_catalog.sql",
	check.MigrationsDirRel + "/20261018030000_rule_selector_carries_its_verbs.sql",
}

func TestRoleSubtableGate_EveryMigrationWritingRoleSubtablesEmitsTheEvent(t *testing.T) {
	migs := treeMigrationCorpus(t)
	findings, census, err := check.AuditRoleSubtableWriters(migs)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов цепочки осмотрено %d · разделов %d · граница популяции %s · "+
		"файлов в популяции %d · разделов, пишущих подтаблицы роли, в популяции %d · из них "+
		"зовущих функцию %d · пишущих ВНЕ популяции %d %v",
		census.Files, census.Sections, census.Floor, census.Population,
		census.Writers, census.Calling, len(census.Outside), census.Outside)

	if census.Files != len(migs) || census.Sections < census.Files {
		t.Fatalf("осмотрено файлов %d из %d, разделов %d — обход неполон, и молчание о "+
			"непрочитанном неотличимо от чистоты", census.Files, len(migs), census.Sections)
	}
	if strings.Join(census.Outside, ",") != strings.Join(roleSubtableWritersOutsidePopulation, ",") {
		t.Fatalf("писатели подтаблиц роли вне популяции %v, а приёмка §3.2а называет %v. Набор "+
			"неподвижен: расхождение — это разбор, переставший видеть форму записи, либо "+
			"граница популяции, сдвинутая без приёмки", census.Outside, roleSubtableWritersOutsidePopulation)
	}
	if len(findings) > 0 {
		lines := make([]string, 0, len(findings))
		for _, f := range findings {
			lines = append(lines, f.String())
		}
		t.Fatalf("миграции пишут подтаблицы роли без события — %d место(а):\n  %s\n\n"+
			"Подписчик роли не узнает об отзыве: состав сменился, строка роли — нет. "+
			"Снятие: позвать kaname.resource_journal_emit_role_composition(<роли>) в том же "+
			"разделе (§2.7, §3.2а).", len(findings), strings.Join(lines, "\n  "))
	}
}
