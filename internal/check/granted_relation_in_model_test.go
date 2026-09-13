// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// granted_relation_in_model_test.go — ГЕЙТ КЛАССА: отношение, которое выдаёт
// миграция, существует в применяемой модели (задача #17, порт семейства
// `grantedrelationinmodel`).
//
// Предмет, цена отравленной строки и граница «состав, а не порядок» — в шапке
// `granted_relation_in_model.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// granted_relation_in_model_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestEveryRelationGrantedByMigrationsExistsInTheAppliedModel — имя сохранено
// дословно с монорепо: семейство перенесено, а не заведено заново.
func TestEveryRelationGrantedByMigrationsExistsInTheAppliedModel(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	grants, migrationsRead, blocksSeen, err := check.GrantsFromMigrations(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	// Предпосылка гейта: он что-то ПРОЧИТАЛ. «Ноль находок» обязано быть отличимо
	// от «ноль осмотренного» — иначе сменившееся имя очереди или формы записи
	// выключит проверку, и она останется зелёной.
	if migrationsRead == 0 {
		t.Fatal("не прочитано НИ ОДНОЙ миграции, пишущей в очередь выдач — гейт объявил бы " +
			"«ноль находок», ничего не осмотрев")
	}
	if len(grants) == 0 {
		t.Fatalf("не найдено НИ ОДНОЙ выдачи в очередь: либо имя очереди сменилось, либо форма "+
			"записи перестала попадать под предикат. Осмотрено миграций: %d, блоков кортежа: %d",
			migrationsRead, blocksSeen)
	}

	modelRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.AppliedModelRelPath)))
	if err != nil {
		t.Fatalf("модель, по которой принимается решение, обязана быть в дереве по пути %s — "+
			"её отсутствие и есть тот дефект, ради которого этот гейт написан: %v",
			check.AppliedModelRelPath, err)
	}
	model := check.RelationsByType(string(modelRaw))
	if len(model) == 0 {
		t.Fatalf("в %s не разобрано НИ ОДНОГО типа — предикат разбора модели перестал её видеть; "+
			"без этого «все отношения на месте» означало бы «ничего не прочитано»",
			check.AppliedModelRelPath)
	}

	t.Logf("перепись: миграций осмотрено %d; блоков кортежа %d; пар «тип+отношение» выдано %d (%s); "+
		"в применяемой модели типов %d, отношений всего %d",
		migrationsRead, blocksSeen, len(grants), check.JoinGrants(grants),
		len(model), check.CountRelations(model))

	for _, m := range check.MissingGrantedRelations(grants, model) {
		t.Errorf("миграция выдаёт отношение, которого в применяемой модели нет: строка журнала "+
			"ляжет прямым фактом, но НИ ОДИН вопрос о доступе её не найдёт — план вывода "+
			"строится из модели, и отношения, которого в модели нет, он не спрашивает. Право не "+
			"выдастся, а отказ будет неотличим от честного.\n  %s", m)
	}
}
