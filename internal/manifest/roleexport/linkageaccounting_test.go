// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// linkageaccounting_test.go — СЧЁТ обратной стороны сверки: запись каталога,
// которую раздел `resources` не называет действием, обязана быть ОТНЕСЕНА к
// своему состоянию, а не отвергнута оптом (задача PRO-Robotech/kacho#1091).
//
// # Почему это отдельный предмет от «сверки в обе стороны»
//
// Прямая сторона биективна by construction: действие раздела рендерится в
// `define v_<действие>`, поэтому у каждого объявленного действия есть ровно одно
// отношение. Обратная — НЕ биективна, и это свойство каталога, а не упущение:
// одно отношение гейтит несколько записей (`AddCidrBlocks`, `RemoveCidrBlocks` и
// `Update` — все три `v_update` на `vpc_subnet`), а часть записей гейтится
// ЯРУСОМ ОБЛАСТИ (`editor` на `project`) либо не гейтится вовсе.
//
// Требовать от раздела действия на КАЖДУЮ запись значит требовать отношений,
// которых в каноне нет: добавленное действие рендерит новую строку `define v_…`,
// и побайтовая сверка с каноном её отвергает. То есть требование неисполнимо
// НИ ПРИ КАКОМ манифесте — оно противоречит второй проверке того же дерева.
//
// # Что проверяемо вместо
//
// Что записей БЕЗ СЧЁТА ноль: каждая запись каталога, чей ресурс раздел
// объявляет порождённым, либо названа действием, либо едет на отношении
// названного действия, либо гейтится ярусом области, либо гейта не имеет.
// Остаётся ровно один вид находки — гейт на отношении `v_*`, которого не
// порождает НИ ОДНО объявленное действие: право на него выдать нечем, и это
// настоящий дефект.
package roleexport_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest/roleexport"
)

// treeRootFromPackage — корень дерева относительно каталога пакета.
// Объявлен ОДИН раз: второе объявление разошлось бы с первым при переносе
// пакета, и неверное отвечало бы «манифестов ноль» — то есть зелёным.
const treeRootFromPackage = "../../../../.."

// realManifests — шесть манифестов дерева, прочитанных настоящим загрузчиком.
func realManifests(t *testing.T) []*manifest.Manifest {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(treeRootFromPackage, "services", "*", "manifest.yaml"))
	if err != nil {
		t.Fatalf("обход дерева отказал: %v", err)
	}
	var out []*manifest.Manifest
	for _, p := range paths {
		data, rerr := os.ReadFile(p) // #nosec G304 -- путь произведён обходом дерева пробы, подставить посторонний файл извне нечем
		if rerr != nil {
			t.Fatalf("манифест %s не прочитан: %v", p, rerr)
		}
		m, lerr := manifest.Load(data)
		if lerr != nil {
			t.Fatalf("манифест %s отвергнут загрузчиком: %v", p, lerr)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		t.Fatal("манифестов прочитано ноль: обход беспредметен, и «ноль находок» " +
			"стало бы неотличимо от «ноль прочитанного»")
	}
	return out
}

// TestEveryCatalogEntryOfADeclaredResourceIsAccounted — НОВЫЙ предикат #1091 по
// НАСТОЯЩЕМУ дереву: записей каталога без счёта ноль.
//
// Прежний предикат задачи требовал равенства двух популяций («сумма покрытых
// записей каталога равна числу записей в каталоге») и был неисполним: у vpc
// действий раздела 32 против 72 записей каталога тех же порождённых ресурсов.
func TestEveryCatalogEntryOfADeclaredResourceIsAccounted(t *testing.T) {
	actions := mustActions(t)
	total := 0
	for _, m := range realManifests(t) {
		faults, census := roleexport.CheckActionLinkage(m, actions)
		t.Logf("модуль %s: %s", m.Module, census.Summary())
		total += census.ManifestVerbs
		for _, f := range faults {
			t.Errorf("модуль %s: запись каталога без счёта: %v", m.Module, f)
		}
	}
	if total == 0 {
		t.Fatal("действий раздела осмотрено ноль: обход беспредметен")
	}
	t.Logf("перепись: действий раздела осмотрено %d", total)
}

// TestUnnamedCatalogEntryIsClassifiedNotRefusedWholesale — способность СЧЁТА
// различать, доказанная инъекцией по каждому состоянию, с законным близнецом.
func TestUnnamedCatalogEntryIsClassifiedNotRefusedWholesale(t *testing.T) {
	// Раздел объявляет ОДНО действие — `update`; оно рендерит `v_update`.
	const doc = "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: subnet\n    objectType: vpc_subnet\n    parents: [project]\n" +
		"    producer: derived\n    verbs:\n      - update\n"

	entry := func(method, relation, object string) roleexport.CatalogEntry {
		return roleexport.CatalogEntry{
			FQN:              "kacho.cloud.vpc.v1.SubnetService/" + method,
			RequiredRelation: relation,
			ScopeObjectType:  object,
		}
	}
	run := func(t *testing.T, entries ...roleexport.CatalogEntry) ([]error, roleexport.ActionLinkageCensus) {
		t.Helper()
		acts, faults := roleexport.Attribute(entries)
		if len(faults) > 0 {
			t.Fatalf("вход не произведён — каталог инъекции не привязался: %v", faults)
		}
		m, err := manifest.Load([]byte(doc))
		if err != nil {
			t.Fatalf("вход не произведён — манифест инъекции не грузится: %v", err)
		}
		return roleexport.CheckActionLinkage(m, acts)
	}

	t.Run("контроль: названное действие — молчание", func(t *testing.T) {
		faults, census := run(t, entry("Update", "v_update", "vpc_subnet"))
		if len(faults) > 0 {
			t.Fatalf("сошедшийся раздел отвергнут: %v", faults)
		}
		if census.Matched != 1 {
			t.Fatalf("перепись не подтверждает, что сверка читала: %s", census.Summary())
		}
	})

	t.Run("едет на отношении объявленного действия — молчание", func(t *testing.T) {
		faults, census := run(t,
			entry("Update", "v_update", "vpc_subnet"),
			entry("AddCidrBlocks", "v_update", "vpc_subnet"))
		if len(faults) > 0 {
			t.Fatalf("запись, едущая на объявленном v_update, отвергнута — требование "+
				"неисполнимо: назвать её действием значит породить `define v_addcidrblocks` "+
				"сверх канона: %v", faults)
		}
		if census.RidesDeclaredRelation != 1 {
			t.Errorf("состояние не названо числом: %s", census.Summary())
		}
	})

	t.Run("гейтится ярусом области — молчание", func(t *testing.T) {
		faults, census := run(t,
			entry("Update", "v_update", "vpc_subnet"),
			entry("Create", "editor", "project"))
		if len(faults) > 0 {
			t.Fatalf("запись, гейтящаяся ярусом области, отвергнута: %v", faults)
		}
		if census.GatedAtScopeTier != 1 {
			t.Errorf("состояние не названо числом: %s", census.Summary())
		}
	})

	t.Run("гейта нет вовсе — молчание", func(t *testing.T) {
		faults, census := run(t,
			entry("Update", "v_update", "vpc_subnet"),
			entry("List", "", ""))
		if len(faults) > 0 {
			t.Fatalf("освобождённая запись отвергнута: %v", faults)
		}
		if census.UnnamedExempt != 1 {
			t.Errorf("состояние не названо числом: %s", census.Summary())
		}
	})

	// ЕДИНСТВЕННЫЙ вид находки обратной стороны — и он обязан оставаться находкой.
	t.Run("гейт на отношении, которого не порождает ни одно действие — НАХОДКА", func(t *testing.T) {
		faults, census := run(t,
			entry("Update", "v_update", "vpc_subnet"),
			entry("Freeze", "v_freeze", "vpc_subnet"))
		if !containsKind(faults, roleexport.ErrActionMissingFromManifest) {
			t.Fatalf("гейт `v_freeze`, которого не порождает ни одно объявленное действие, "+
				"пропущен — право на него выдать нечем: %v (%s)", faults, census.Summary())
		}
		if census.WithoutManifestVerb != 1 {
			t.Errorf("находка не названа числом: %s", census.Summary())
		}
		if !strings.Contains(joinErrs(faults), "v_freeze") {
			t.Errorf("отказ не назвал отношение, которое некому породить: %v", faults)
		}
	})
}
