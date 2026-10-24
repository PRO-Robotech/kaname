// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// object_refs_test.go — манифест модуля не ссылается на конкретные объекты
// (kaname#965, расширение по ревью приёмки kaname#963).
//
// Каждый отказ стоит в паре с законным близнецом, отличающимся одним фактом:
// тот же документ, где вместо объекта названы тип либо область, загружается.
// Без близнеца отказ зеленел бы и на загрузчике, отвергающем всё.

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// orRequireRefusal — загрузка отвергает документ находкой ErrObjectRefInManifest,
// и текст находки называет координату и причину.
func orRequireRefusal(t *testing.T, doc []byte, coord string) {
	t.Helper()
	_, err := manifest.Load(doc)
	if err == nil {
		t.Fatalf("загрузка приняла документ со ссылкой на конкретный объект; ждали отказ по %s", coord)
	}
	if !errors.Is(err, manifest.ErrObjectRefInManifest) {
		t.Fatalf("отказ не отнесён к ссылке на конкретный объект (ErrObjectRefInManifest): %v", err)
	}
	for _, want := range []string{coord + ":", "не допускается"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("находка не называет %q:\n%v", want, err)
		}
	}
}

// orRequireLoads — законный близнец загружается.
func orRequireLoads(t *testing.T, doc []byte, what string) {
	t.Helper()
	if _, err := manifest.Load(doc); err != nil {
		t.Fatalf("законный близнец (%s) отвергнут: %v", what, err)
	}
}

// orReplaceOnce — правка ровно одного вхождения; иное число — отказ пробы, а не
// молчаливая правка «где нашлось».
func orReplaceOnce(t *testing.T, doc, old, repl string) []byte {
	t.Helper()
	if n := strings.Count(doc, old); n != 1 {
		t.Fatalf("правка %q: ожидалось одно вхождение, найдено %d — проба судила бы не тот документ", old, n)
	}
	return []byte(strings.Replace(doc, old, repl, 1))
}

// ── (а) выдача посева на перечень объектов ──────────────────────────────────

const (
	orObjectListTarget = "      target: resources\n      resources:\n" +
		"        - {type: vpc.addressPool, id: apl000000000000001}\n" +
		"        - {type: vpc.addressPool, id: apl000000000000002}\n"
	orWholeScopeTarget = "      target: allInScope\n"
)

func orBindingFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/vpc.binding-resources-fixture.yaml")
	if err != nil {
		t.Fatalf("фикстура выдачи на перечень объектов не прочитана: %v", err)
	}
	return string(raw)
}

// Выдача посева с целью «перечень объектов» отвергается (MOD-RL-23b, ось Г
// MOD-RL-23).
func TestObjectRefs_SeedBindingToAnObjectListIsRefused(t *testing.T) {
	doc := orBindingFixture(t)
	orRequireRefusal(t, []byte(doc), "seed.accessBindings[0].target")

	// Тот же охват без перечня — тоже отказ по охвату, а не только «перечня нет».
	bare := orReplaceOnce(t, doc, orObjectListTarget, "      target: resources\n")
	orRequireRefusal(t, bare, "seed.accessBindings[0].target")

	// Тот же охват с ПУСТЫМ перечнем — отказ по охвату, а не только «перечень
	// назван и пуст» (ось Г MOD-RL-23).
	empty := orReplaceOnce(t, doc, orObjectListTarget, "      target: resources\n      resources: []\n")
	orRequireRefusal(t, empty, "seed.accessBindings[0].target")
}

// Выдача посева без цели: находка называет единственное годное в манифесте
// значение — allInScope, а не «ярус либо перечень» (ось В MOD-RL-23).
func TestObjectRefs_SeedBindingWithoutTargetNamesAllInScope(t *testing.T) {
	doc := orReplaceOnce(t, orBindingFixture(t), orObjectListTarget, "")
	_, err := manifest.Load(doc)
	if err == nil {
		t.Fatal("выдача посева без цели принята")
	}
	if !errors.Is(err, manifest.ErrBindingIncomplete) {
		t.Fatalf("отказ не отнесён к неполной выдаче (ErrBindingIncomplete): %v", err)
	}
	const want = "seed.accessBindings[0].target: ключ не назван — выдача посева в манифесте модуля " +
		"действует только на ярус целиком: напишите `target: allInScope`"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("находка не называет единственное годное значение\n ждали  %q\n получено %v", want, err)
	}
}

// Близнец: та же выдача на ярус целиком загружается.
func TestObjectRefs_SeedBindingToTheWholeScopeLoads(t *testing.T) {
	orRequireLoads(t, orReplaceOnce(t, orBindingFixture(t), orObjectListTarget, orWholeScopeTarget),
		"выдача на ярус целиком")
}

// ── (б) правило роли называет объекты ───────────────────────────────────────

const orRoleBase = "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
	"  - id: vpc.viewer\n    description: Читает топологию проекта.\n" +
	"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
	"    rules:\n      - module: vpc\n        resources: [network]\n        classes: [get]\n"

func TestObjectRefs_RoleRuleResourceNamesIsRefused(t *testing.T) {
	for name, extra := range map[string]string{
		"непустой перечень": "        resourceNames: [ntw000000000000001]\n",
		// Пустой перечень судится НАЛИЧИЕМ ключа: схема объявляет ключ
		// недопустимым, а не «допустимым пустым».
		"пустой перечень": "        resourceNames: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			orRequireRefusal(t, []byte(orRoleBase+extra), "roles[0].rules[0].resourceNames")
		})
	}
}

// Близнецы: правило над типом и правило, суженное метками, загружаются.
func TestObjectRefs_RoleRuleOverATypeLoads(t *testing.T) {
	orRequireLoads(t, []byte(orRoleBase), "правило над типом")
	orRequireLoads(t, []byte(orRoleBase+"        matchLabels: {env: prod}\n"), "сужение метками")
}

// ── (б) вложенное правило и правило-владелец называют объекты ──────────────

// orReaderOwner / orReaderChild — места блока роли registry.reader фикстуры П1
// (roles[1].rules[0]), в которые встаёт ссылка на объект.
const (
	orReaderOwner = "  - id: registry.reader\n" +
		"    description: >\n      Пробная роль: чтение реестра и каждого его репозитория, включая\n" +
		"      созданные позже.\n    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - module: registry\n        resources: [registries]\n" +
		"        classes: [get, list]\n        children:\n          - resources: [repositories]\n" +
		"            classes: [get, list]\n"
)

func orPublicReadFixture(t *testing.T) string {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	return string(doc)
}

// orObjectRefWhy — причина отказа дословно, как её называют MOD-RL-23b,
// MOD-MR-13а и ND-04 (з).
const orObjectRefWhy = "идентификатор объекта присваивает запись, и снимается он вместе с " +
	"регистрацией объекта, а манифест применяется на каждом старте и вернул бы ссылку снова"

// orNestedFinding — текст находки ND-04 (з) дословно.
const orNestedFinding = "roles[1].rules[0].children[0].resourceNames: сужение по идентификаторам объектов " +
	"в роли манифеста модуля не допускается — правило называет типы (resources) и вправе сузиться " +
	"метками (matchLabels); " + orObjectRefWhy

// Перечень судится НАЛИЧИЕМ ключа: пустой отвергается так же, как непустой.
func TestObjectRefs_NestedRuleResourceNamesIsRefused(t *testing.T) {
	for name, names := range map[string]string{"непустой перечень": "[app]", "пустой перечень": "[]"} {
		t.Run(name, func(t *testing.T) {
			doc := orPublicReadFixture(t)
			nested := orReplaceOnce(t, doc, orReaderOwner, orReaderOwner+"            resourceNames: "+names+"\n")
			orRequireRefusal(t, nested, "roles[1].rules[0].children[0].resourceNames")
			if _, err := manifest.Load(nested); !strings.Contains(err.Error(), orNestedFinding) {
				t.Fatalf("находка ND-04 (з) не дословна\n ждали  %q\n получено %v", orNestedFinding, err)
			}
		})
	}
}

// MOD-RL-23b: находка называет годный охват и причину.
func TestObjectRefs_SeedBindingFindingNamesAllInScopeAndTheReason(t *testing.T) {
	_, err := manifest.Load([]byte(orBindingFixture(t)))
	if err == nil {
		t.Fatal("выдача посева на перечень объектов принята")
	}
	for _, want := range []string{"(allInScope)", orObjectRefWhy} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("находка MOD-RL-23b не называет %q:\n%v", want, err)
		}
	}
}

func TestObjectRefs_OwnerRuleWithChildrenResourceNamesIsRefused(t *testing.T) {
	for name, names := range map[string]string{"непустой перечень": "[reg00000000000000001]", "пустой перечень": "[]"} {
		t.Run(name, func(t *testing.T) {
			doc := orPublicReadFixture(t)
			owner := orReplaceOnce(t, doc, orReaderOwner, strings.Replace(orReaderOwner,
				"        resources: [registries]\n",
				"        resources: [registries]\n        resourceNames: "+names+"\n", 1))
			orRequireRefusal(t, owner, "roles[1].rules[0].resourceNames")
		})
	}
}

// Близнец: та же фикстура без ссылок на объекты загружается, и роль
// registry.reader несёт вложенное правило над типом.
func TestObjectRefs_NestedRuleOverATypeLoads(t *testing.T) {
	doc := orPublicReadFixture(t)
	if strings.Count(doc, orReaderOwner) != 1 {
		t.Fatalf("блок registry.reader в фикстуре П1 не найден ровно один раз")
	}
	orRequireLoads(t, []byte(doc), "вложенное правило над типом")
	children, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	if err != nil {
		t.Fatalf("фикстура П3: %v", err)
	}
	orRequireLoads(t, children, "фикстура П3 трёх уровней")
}

// ── канон манифестов ────────────────────────────────────────────────────────

// Манифест модуля iam (тот, что встраивается в образ) загружается: ссылок на
// объекты в нём нет.
func TestObjectRefs_ServiceManifestStillLoads(t *testing.T) {
	if _, err := servicemanifest.Load(); err != nil {
		t.Fatalf("встроенный манифест iam отвергнут: %v", err)
	}
}

// Манифесты модулей платформы, названного снаружи дерева, загружаются.
// Перечень выводится обходом; пустой обход — не вердикт.
func TestObjectRefs_PlatformManifestsStillLoad(t *testing.T) {
	root := platformtree.RequireNamedPlatformTree(t)
	paths, err := filepath.Glob(filepath.Join(root, "services", "*", "manifest.yaml"))
	if err != nil {
		t.Fatalf("обход манифестов платформы: %v", err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("обход %s/services/*/manifest.yaml не нашёл ни одного манифеста — "+
			"«отказов 0» неотличимо от «прочитано 0»", root)
	}
	for _, p := range paths {
		body, err := os.ReadFile(p) // #nosec G304 -- путь собран обходом названного дерева
		if err != nil {
			t.Fatalf("прочитать %s: %v", p, err)
		}
		if _, err := manifest.Load(body); err != nil {
			t.Errorf("манифест %s отвергнут: %v", p, err)
		}
	}
	t.Logf("манифестов платформы загружено: %d", len(paths))
}
