// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_export_procedure_test.go — ГЕЙТ КЛАССА: процедура выгрузки назначенных
// величин ЗАПИСАНА в инструкции обновления, и записана дословно той же, какую
// называет отказ наката (задача #17, порт семейства `limitexportprocedure`).
//
// Предмет и обе оси находки — в шапке `limit_export_procedure.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// limit_export_procedure_injection_test.go.
//
// # Почему координата здесь ЖЁСТКАЯ, а не выведена обходом
//
// Обход, судящий «те инструкции, где процедура уже есть», зеленел бы ровно
// тогда, когда её вычеркнули: ноль предметов — ноль находок. Требуемая пара
// «таблица → инструкция» названа явно, поэтому исчезновение процедуры —
// находка, а не тишина. Пропажу самой инструкции гейт тоже называет.
package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// requiredExportProcedures — таблицы, чья выгрузка обязана быть записана, и где.
//
// Сегодня запись одна, и это не заготовка на будущее: `kaname.limits` — таблица,
// которую снесёт снятие домена величин из службы доступа, и счёт её строк
// ненулевой у ЛЮБОЙ установки, потому что цепочка сама сеет умолчания. Снесёт
// другая версия другую таблицу с данными арендатора — запись добавится вместе с
// той миграцией.
var requiredExportProcedures = map[string]string{
	"kaname.limits": "INSTALL.md",
}

// TestUpgradeGuideCarriesTheExportProcedureVerbatim — сам гейт.
//
// Имя сохранено дословно с монорепо: семейство перенесено, а не заведено заново.
func TestUpgradeGuideCarriesTheExportProcedureVerbatim(t *testing.T) {
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

	// Обход и его отказ на пустоте держит ОДНА функция — `ExportProcedureGuides`.
	// Прежде он строился здесь, в теле пробы, и премиса «прочитано ноль» стояла
	// НИЖЕ разбора: ветвь читалась глазами и не исполнялась ни разу, потому что
	// корнем ей служил корень своего модуля и подать ей пустое дерево было нечем.
	guides, err := check.ExportProcedureGuides(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	census, findings := check.JudgeExportProcedure(guides, requiredExportProcedures)
	t.Log(census.String())

	if census.Lines == 0 {
		t.Fatalf("инструкции прочитаны, но строк в них ноль (%s) — судить нечего, и "+
			"«находок ноль» означало бы «прочитано ноль»", census.String())
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
