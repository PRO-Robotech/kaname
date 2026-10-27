// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seedgrantceiling_test.go — ПОТОЛОК выдач посева: посев модуля выдаёт только
// своё и только в пределах своего яруса (kaname#979).
//
// # Что было неверно
//
// Связность выдачи судила, ЧТО названо (роль объявлена, субъект заведён этим же
// посевом, якорь — кластер), и не судила, ЧЕГО выдача стоит. Манифест модуля
// мог наделить свою служебную запись администрированием всей установки
// (`system_admin` на кластере) либо ролью ЧУЖОГО модуля — загрузчик принимал
// оба документа, потому что ни одно из правил связности о цене выдачи не
// спрашивало.
//
// # Отрицания стоят В ПАРЕ с положительным
//
// Отказ без законного близнеца зеленеет на реализации, отвергающей всё. Поэтому
// у каждого отрицания здесь есть близнец, отличающийся от него ОДНИМ фактом, —
// и он принимается.
package manifest_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
)

// relationToServiceAccount — выдача отношением служебной записи своего модуля
// на якоре кластера; меняется ровно имя отношения.
func relationToServiceAccount(relation string) string {
	return `    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: ` + relation + `
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`
}

// roleToServiceAccount — выдача ролью служебной записи своего модуля на якоре
// кластера; меняется ровно идентификатор роли.
func roleToServiceAccount(roleID string) string {
	return `    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      roleId: ` + roleID + `
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`
}

// TestSeedGrantRelationOutsideTheClosedListIsRefused — отношение кластера вне
// закрытого перечня посева отвергается, и это не зависит от того, что канон
// такое отношение объявляет и получателя такого вида принимает.
//
// Отрицания ВЫВЕДЕНЫ из канона, а не выписаны: каждое прямое отношение типа
// `cluster`, принимающее служебную запись, кроме разрешённых посеву. Отношение,
// добавленное в модель завтра, попадёт сюда само — и обязано быть отвергнуто,
// пока его не внесли в перечень решением.
func TestSeedGrantRelationOutsideTheClosedListIsRefused(t *testing.T) {
	oracle, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон образа не разобран — судить об отношении нечем: %v", err)
	}
	objectType, ok := domain.ScopeTypeFromDotted(domain.ScopeTypeClusterDotted)
	if !ok {
		t.Fatalf("якорь %q не резолвится в тип объекта", domain.ScopeTypeClusterDotted)
	}
	allowed := manifest.SeedGrantableRelations()

	var refused []string
	for _, rel := range oracle.TypeRelations(objectType) {
		decl, declared := oracle.RelationDeclaration(objectType, rel)
		if !declared || !decl.IsDirect() || !decl.AcceptsKind("serviceAccount") || slices.Contains(allowed, rel) {
			continue
		}
		refused = append(refused, rel)
		t.Run(rel, func(t *testing.T) {
			doc := seedWithBinding(relationToServiceAccount(rel))
			mustRefuseGrant(t, doc, manifest.ErrSeedGrantBeyondTier,
				"seed.accessBindings[0].grantedRelation", rel, strings.Join(allowed, ", "))
		})
	}
	t.Logf("перепись: отношений типа %q %d; вне перечня посева, прямых и принимающих служебную запись — %d (%s); перечень посева — %s",
		objectType, len(oracle.TypeRelations(objectType)), len(refused), strings.Join(refused, ", "), strings.Join(allowed, ", "))
	if len(refused) == 0 {
		t.Fatalf("ни одного отношения вне перечня посева канон не объявляет — отрицание не исполнилось, вердикта нет")
	}

	// Законные близнецы: те же оболочки, отношение из перечня.
	mustLoadGrantOK(t, seedWithBinding(bindingRelationToServiceAccount), "system_viewer своей служебной записи")
	mustLoadGrantOK(t, seedWithGroupAndBinding(bindingRelationToGroup), "fga_writer своей группе")
}

// TestSeedGrantableRelationsAreDirectRelationsOfTheCluster — перечень посева
// называет только то, что канон у кластера объявляет прямым отношением.
//
// Запись перечня, чьего отношения в модели больше нет, истекла вместе с ним: она
// разрешает выдачу, которой нечем исполниться, и молчит об этом.
func TestSeedGrantableRelationsAreDirectRelationsOfTheCluster(t *testing.T) {
	oracle, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон образа не разобран: %v", err)
	}
	objectType, _ := domain.ScopeTypeFromDotted(domain.ScopeTypeClusterDotted)
	allowed := manifest.SeedGrantableRelations()
	if len(allowed) == 0 {
		t.Fatalf("перечень посева пуст — выдача отношением невыразима ни при каком входе")
	}
	for _, rel := range allowed {
		decl, declared := oracle.RelationDeclaration(objectType, rel)
		if !declared || !decl.IsDirect() {
			t.Errorf("перечень посева называет %q, а канон у типа %q прямым его не объявляет", rel, objectType)
		}
	}
}

// TestSeedGrantRoleOfAnotherModuleIsRefused — роль, чей идентификатор не
// называет СВОЙ модуль, посевом не выдаётся.
//
// Идентификатор роли — `<модуль>.<имя>` (контракт `roleId` опубликованной
// схемы); строка роли в хранилище (`rol…`) модуля-владельца не несёт вовсе, и
// выдать по ней можно роль любого модуля — в том числе администрирование чужого
// домена.
func TestSeedGrantRoleOfAnotherModuleIsRefused(t *testing.T) {
	for name, roleID := range map[string]string{
		"роль чужого модуля":             "compute.instance.admin",
		"системная роль установки":       "iam.account.admin",
		"идентификатор строки хранилища": "rol6307d201bf18e6763",
	} {
		t.Run(name, func(t *testing.T) {
			doc := seedWithBinding(roleToServiceAccount(roleID))
			mustRefuseGrant(t, doc, manifest.ErrSeedGrantForeignModule,
				"seed.accessBindings[0].roleId", roleID, `"vpc"`)
		})
	}

	// Законный близнец: та же оболочка, роль своего модуля.
	mustLoadGrantOK(t, seedWithBinding(roleToServiceAccount("vpc.network.admin")), "роль своего модуля")
}

// TestSeedGrantRoleBeyondItsTierIsRefused — роль, определённая ниже кластера,
// на якоре кластера посевом не выдаётся: выдача действовала бы на всю установку
// правом, которое роль объявила для одного аккаунта либо проекта.
func TestSeedGrantRoleBeyondItsTierIsRefused(t *testing.T) {
	legal := mustReadResourcesFixture(t)
	mustLoadGrantOK(t, []byte(legal), "фикстура: роль выдачи определена на кластере")

	const clusterTier = "tier: {tierType: iam.cluster, tierId: cluster_root}\n    rules:\n      - module: vpc\n        resources: [address, networkInterface, subnet]"
	projectTier := strings.Replace(clusterTier, "{tierType: iam.cluster, tierId: cluster_root}",
		"{tierType: iam.project, tierId: prj000000000000000}", 1)
	broken := replaceOnce(t, legal, clusterTier, projectTier)
	mustRefuseGrant(t, []byte(broken), manifest.ErrSeedGrantBeyondTier,
		"seed.accessBindings", "vpc.internal_consumer", domain.ScopeTypeProjectDotted)
}

// testdataRefusedByDesign — ЯВНЫЙ перечень фикстур `testdata`, которые
// загрузчик обязан ОТВЕРГАТЬ, с видом отказа. Запись без файла — находка
// (перечень истекает вместе со своим предметом); файл из перечня, принятый
// загрузчиком либо отвергнутый не тем отказом, — тоже.
var testdataRefusedByDesign = map[string]error{
	// Выдача посева на перечень объектов — вход отказа проб `object_refs_test.go`
	// (kaname#965): манифест модуля конкретных объектов не называет.
	"vpc.binding-resources-fixture.yaml": manifest.ErrObjectRefInManifest,
}

// TestEveryTestdataFixtureFacesTheLoaderWithTheSeedGrantCeiling — загрузчик
// вместе с потолком посева прогоняется по ВСЕМ фикстурам `testdata/*.yaml`.
//
// # Что было неверно
//
// Потолок посева (kaname#979) судили синтетические документы этого файла да
// одна фикстура (`vpc.resources-fixture.yaml`), которую kaname#979 и поправил.
// Фикстура мира Д (`vpc.delegation-fixture.yaml`, kaname#1009) была снята с
// прежней редакции той же фикстуры — роль `vpc.internal_consumer` на ярусе
// проекта и её выдача посевом на кластере — и новым запретом стала отвергаться.
// Ни одна проба пакета об этом не узнала: фикстуру грузит лишь интеграционный
// мир, и отказ пришёл шестьюдесятью шестью отказами шарда интеграции после
// сведения волны.
//
// # Что держит проба
//
// Каждая фикстура каталога грузится обоими путями, которыми её берут пробы:
// без оракула (так её грузят миры интеграции) и с каноном модели (так судят
// пробы потолка). Законная обязана пройти оба; намеренно плохая — только по
// перечню [testdataRefusedByDesign] и только названным отказом. Новый запрет
// загрузчика, ломающий фикстуру, краснеет здесь, в модульной пробе, с именем
// файла.
//
// Предпосылка обхода проверяется: обход, не нашедший ни одной фикстуры, —
// «не выполнилось», а не «нарушений нет».
func TestEveryTestdataFixtureFacesTheLoaderWithTheSeedGrantCeiling(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("каталог фикстур не прочитан — судить нечего: %v", err)
	}
	forms := []struct {
		name string
		opts []manifest.LoadOption
	}{
		{"без оракула", nil},
		{"с каноном модели", []manifest.LoadOption{canonOracle(t)}},
	}
	var files, lines, lawful, refused int
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if ext := filepath.Ext(name); e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("фикстура %s не прочитана: %v", name, err)
		}
		files++
		lines += bytes.Count(data, []byte("\n"))
		seen[name] = true

		want, refusedByDesign := testdataRefusedByDesign[name]
		for _, form := range forms {
			_, err := manifest.Load(data, form.opts...)
			switch {
			case refusedByDesign && err == nil:
				t.Errorf("%s (%s): фикстура из перечня намеренно плохих принята загрузчиком", name, form.name)
			case refusedByDesign && !errors.Is(err, want):
				t.Errorf("%s (%s): отказ не того вида — ждали %v: %v", name, form.name, want, err)
			case !refusedByDesign && err != nil:
				t.Errorf("%s (%s): законная фикстура отвергнута загрузчиком: %v", name, form.name, err)
			}
		}
		if refusedByDesign {
			refused++
		} else {
			lawful++
		}
	}
	if files == 0 {
		t.Fatalf("в testdata ни одной фикстуры *.yaml — обход пуст, это «не выполнилось», а не «нарушений нет»")
	}
	for name := range testdataRefusedByDesign {
		if !seen[name] {
			t.Errorf("перечень намеренно плохих называет %s, а файла в testdata нет — запись пережила свой предмет", name)
		}
	}
	t.Logf("осмотрено фикстур %d · строк %d · законных %d · намеренно плохих по перечню %d", files, lines, lawful, refused)
}
