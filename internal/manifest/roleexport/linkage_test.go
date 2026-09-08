// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// linkage_test.go — способность сверки «действие манифеста ↔ запись каталога»
// УПАСТЬ, доказанная инъекцией по каждой оси (задача PRO-Robotech/kacho#1844).
//
// # Почему инъекция на СИНТЕТИКЕ, а не только перепись по дереву
//
// Перепись по дереву на здоровом дереве молчит — она и должна, — поэтому проба,
// стоящая только на ней, доказывала бы, что механизм жив, ничего не говоря о
// том, способен ли он отвергнуть. Вход производится здесь: по каждой оси
// отдельно, с законным близнецом рядом.
//
// Здесь стояло «манифестов в дереве продукта сегодня НОЛЬ, поэтому перепись по
// дереву не может покраснеть ни при каком входе». Утверждение ПЕРЕЖИЛО свой
// предмет: манифестов шесть (задача #1091, предикат — счёт путей, чьё базовое
// имя ровно `manifest.yaml`), и перепись по дереву с тех пор
// краснеть способна — что и доказано инъекцией провязки в задаче #1091. Довод в
// пользу синтетики от этого не отпал, а стал другим, и он записан выше.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
)

// linkageCatalog — две записи каталога одного ресурса: внешняя и внутренняя.
// Вторая нужна именно затем, чтобы ось плоскости имела вход.
func linkageCatalog() []roleexport.CatalogEntry {
	return []roleexport.CatalogEntry{
		{FQN: "kacho.cloud.vpc.v1.NetworkService/GetNetwork", RequiredRelation: "v_get", ScopeObjectType: "vpc_network"},
		{FQN: "kacho.cloud.vpc.v1.InternalNetworkService/GetNetwork", RequiredRelation: "v_get", ScopeObjectType: "vpc_network"},
	}
}

// linkageManifest — раздел, СХОДЯЩИЙСЯ с каталогом выше во всём.
const linkageManifest = "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
	"  - name: network\n    objectType: vpc_network\n    parents: [project]\n    producer: derived\n" +
	"    verbs:\n" +
	"      - {name: getNetwork, class: get}\n" +
	"      - {name: internalGetNetwork, class: get, internal: true}\n"

func mustLoad(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("вход не произведён — манифест инъекции не грузится: %v", err)
	}
	return m
}

func linkage(t *testing.T, doc string) ([]error, roleexport.ActionLinkageCensus) {
	t.Helper()
	actions, faults := roleexport.Attribute(linkageCatalog())
	if len(faults) > 0 {
		t.Fatalf("вход не произведён — каталог инъекции не привязался: %v", faults)
	}
	return roleexport.CheckActionLinkage(mustLoad(t, doc), actions)
}

// TestActionLinkageIsCheckedInBothDirections — четыре оси и законный близнец.
func TestActionLinkageIsCheckedInBothDirections(t *testing.T) {
	// Законный близнец ПЕРВЫМ: без него всякое отрицание ниже зеленело бы на
	// сверке, отвергающей любой вход, и не утверждало бы о ней ничего.
	t.Run("законный близнец: биекция — молчание", func(t *testing.T) {
		faults, census := linkage(t, linkageManifest)
		if len(faults) > 0 {
			t.Fatalf("сошедшийся раздел отвергнут: %v", faults)
		}
		if census.Matched != 2 || census.ManifestVerbs != 2 || census.CatalogActions != 2 {
			t.Fatalf("перепись не подтверждает, что сверка что-то читала: %s", census.Summary())
		}
		t.Logf("перепись законного близнеца: %s", census.Summary())
	})

	t.Run("действие манифеста без записи каталога", func(t *testing.T) {
		doc := strings.Replace(linkageManifest, "{name: getNetwork, class: get}",
			"{name: getNetworkTopology, class: get}", 1)
		faults, census := linkage(t, doc)
		if !containsKind(faults, roleexport.ErrActionUnknownToCatalog) {
			t.Fatalf("действие, которого каталог не знает, принято: %v (%s)", faults, census.Summary())
		}
		if census.WithoutCatalogEntry != 1 {
			t.Errorf("перепись не назвала находку числом: %s", census.Summary())
		}
		// Отказ обязан называть предмет и подсказывать близкое написание —
		// иначе читатель сверяет перечень каталога вручную.
		if !strings.Contains(joinErrs(faults), "getNetworkTopology") {
			t.Errorf("отказ не назвал действие: %v", faults)
		}
	})

	t.Run("запись каталога без действия манифеста", func(t *testing.T) {
		doc := strings.Replace(linkageManifest,
			"      - {name: internalGetNetwork, class: get, internal: true}\n", "", 1)
		faults, census := linkage(t, doc)
		if !containsKind(faults, roleexport.ErrActionMissingFromManifest) {
			t.Fatalf("гейт, которого раздел не описывает, пропущен: %v (%s)", faults, census.Summary())
		}
		if census.WithoutManifestVerb != 1 {
			t.Errorf("перепись не назвала находку числом: %s", census.Summary())
		}
		if !strings.Contains(joinErrs(faults), "InternalNetworkService/GetNetwork") {
			t.Errorf("отказ не назвал запись каталога: %v", faults)
		}
	})

	t.Run("плоскость расходится", func(t *testing.T) {
		doc := strings.Replace(linkageManifest,
			"{name: internalGetNetwork, class: get, internal: true}",
			"{name: internalGetNetwork, class: get}", 1)
		faults, census := linkage(t, doc)
		if !containsKind(faults, roleexport.ErrActionPlaneDisagrees) {
			t.Fatalf("расхождение о плоскости пропущено: %v (%s)", faults, census.Summary())
		}
		if census.PlaneDisagrees != 1 {
			t.Errorf("перепись не назвала находку числом: %s", census.Summary())
		}
	})

	t.Run("авторский ресурс из популяции ИСКЛЮЧЁН, а не отвергнут", func(t *testing.T) {
		doc := linkageManifest +
			"  - name: addressPool\n    objectType: vpc_address_pool\n    parents: [cluster]\n" +
			"    producer: authored\n    verbs: [get, list]\n"
		faults, census := linkage(t, doc)
		if len(faults) > 0 {
			t.Fatalf("авторский ресурс потребован к паре, которой у него нет by construction: %v", faults)
		}
		if census.ResourcesAuthored != 1 {
			t.Errorf("исключение не названо числом — «ноль находок» стало бы неотличимо "+
				"от «ноль осмотренного»: %s", census.Summary())
		}
	})
}

// TestActionLinkageCensusIsPrintedOverTheRealCatalog — перепись по НАСТОЯЩЕМУ
// каталогу и фикстуре раздела.
//
// Это НЕ гейт биекции, и биекции здесь не будет НИКОГДА: обратная сторона
// несимметрична by construction (разбор — в шапке `linkage.go`). Фикстура к тому
// же написана по черновику, который действия переименовывает осознанно, а
// генератор раздела (#1092) ещё не заведён. Проба утверждает ровно то, что может
// утверждать, — что популяция непуста и сверка её читала; величины печатаются,
// чтобы «ноль находок» было отличимо от «ноль прочитанного».
//
// Предикат по НАСТОЯЩЕМУ дереву — соседний файл,
// `TestEveryCatalogEntryOfADeclaredResourceIsAccounted`: он читает шесть
// манифестов дерева, а не фикстуру, и утверждает, что записей БЕЗ СЧЁТА ноль.
func TestActionLinkageCensusIsPrintedOverTheRealCatalog(t *testing.T) {
	actions, faults := roleexport.Attribute(mustCatalog(t))
	if len(actions) == 0 {
		t.Fatalf("каталог не дал ни одного действия — сверять нечего: %v", faults)
	}
	_, census := roleexport.CheckActionLinkage(mustFixture(t), actions)
	if census.ManifestVerbs == 0 || census.CatalogActions == 0 {
		t.Fatalf("перепись беспредметна: %s", census.Summary())
	}
	t.Logf("перепись по дереву: %s", census.Summary())
}

func containsKind(faults []error, kind error) bool {
	for _, f := range faults {
		if errors.Is(f, kind) {
			return true
		}
	}
	return false
}

func joinErrs(faults []error) string {
	parts := make([]string, 0, len(faults))
	for _, f := range faults {
		parts = append(parts, f.Error())
	}
	return strings.Join(parts, "\n")
}
