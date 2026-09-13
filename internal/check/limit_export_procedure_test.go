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
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// installGuideSuffix — по чему инструкции опознаются в составе дерева.
const installGuideSuffix = "INSTALL.md"

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

	tracked, err := treecorpus.Under(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}

	guides := map[string]string{}
	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, installGuideSuffix) {
			continue
		}
		body, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			t.Fatalf("чтение %s: %v — гейт не вправе судить документ, которого он не прочитал",
				rel, berr)
		}
		guides[rel] = string(body)
	}

	census, findings := check.JudgeExportProcedure(guides, requiredExportProcedures)
	t.Log(census.String())

	if census.Guides == 0 || census.Lines == 0 {
		t.Fatalf("обход пуст (%s): инструкций в дереве не прочитано ни одной, и «находок "+
			"ноль» здесь означало бы «прочитано ноль», а не «годно»", census.String())
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
