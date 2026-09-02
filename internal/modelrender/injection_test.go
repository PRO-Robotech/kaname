// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// injection_test.go — доказательство, что сверка СПОСОБНА упасть, и что молчит она
// не потому, что мертва (приёмка §5).
//
// Прогонов по каждой оси ТРИ, а не два: контроль · инъекция нового свойства ·
// инъекция уже существующего. Без третьего молчание прежнего контроля неотличимо
// от молчания мёртвого.
//
// Инъекция подаёт вход САМА — синтетическим деревом, — и в этом её отличие от
// сценария: сценарий судит дерево продукта, инъекция — построенное ею.

// sixModules — дерево с каноном twoBlockCanon и манифестами всех шести модулей.
func sixModules(t *testing.T, canon string) string {
	t.Helper()
	root := helperTree(t, canon)
	for _, m := range domain.KnownModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}
	return root
}

// TestInjectionControlAnUntouchedTreeIsSilent — КОНТРОЛЬ: всё цело, обход молчит.
//
// Прогон первый из трёх. Без него краснота двух следующих ничего не доказывает:
// обход, краснеющий на любом дереве, красен и на сломанном.
func TestInjectionControlAnUntouchedTreeIsSilent(t *testing.T) {
	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, sixModules(t, twoBlockCanon), nil)
	if code != modelrender.SweepOK {
		t.Fatalf("контроль красен: исход %d, находки %v", code, findings)
	}
	if census.BlocksCompared == 0 {
		t.Fatalf("контроль зелен по пустому обходу — вердикт беспредметен: %s", census)
	}
}

// TestC02InjectionARelationRemovedFromTheCanonNamesTheSide — инъекция C-02: из
// КАНОНА снято одно объявление; сторона названа «порождено сверх канона».
//
// Прогон второй: инъекция НОВОГО свойства — побайтовой сверки блока.
func TestC02InjectionARelationRemovedFromTheCanonNamesTheSide(t *testing.T) {
	broken := strings.Replace(twoBlockCanon,
		"    define editor: [user, service_account, group#member] or admin\n", "", 1)
	if broken == twoBlockCanon {
		t.Fatalf("инъекция не изменила канон — доказательство беспредметно")
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, sixModules(t, broken), nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("снятое объявление канона не замечено: исход %d", code)
	}
	var named *modelrender.Finding
	for i := range findings {
		if findings[i].Type == "vpc_network" {
			named = &findings[i]
		}
	}
	if named == nil {
		t.Fatalf("находка не называет тип поимённо: %v", findings)
	}
	if named.Side != modelrender.SideRenderedBeyondCanon {
		t.Fatalf("сторона названа %q, ожидалось %q", named.Side, modelrender.SideRenderedBeyondCanon)
	}
	if !strings.Contains(named.Detail, "строка") {
		t.Fatalf("находка не называет первую расходящуюся строку: %q", named.Detail)
	}
	t.Logf("инъекция названа так: %s", named)
}

// TestC02InjectionARelationAddedToTheCanonNamesTheOtherSide — зеркало предыдущей:
// в КАНОН дописано объявление, которого манифест не порождает.
//
// Сторона обязана быть ДРУГОЙ: «канон сверх порождённого» ТЕРЯЕТ доступ, тогда как
// «порождено сверх канона» его РАСШИРЯЕТ. Гейт, называющий одну сторону на оба
// случая, посылает чинить не туда.
func TestC02InjectionARelationAddedToTheCanonNamesTheOtherSide(t *testing.T) {
	broken := strings.Replace(twoBlockCanon,
		"    define v_get: [user, service_account, group#member] or super_admin\n",
		"    define v_get: [user, service_account, group#member] or super_admin\n"+
			"    define v_smuggled: [user, service_account, group#member] or super_admin\n", 1)
	if broken == twoBlockCanon {
		t.Fatalf("инъекция не изменила канон — доказательство беспредметно")
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, sixModules(t, broken), nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("дописанное в канон объявление не замечено: исход %d", code)
	}
	for _, f := range findings {
		if f.Type == "vpc_network" {
			if f.Side != modelrender.SideCanonBeyondRendered {
				t.Fatalf("сторона названа %q, ожидалось %q", f.Side, modelrender.SideCanonBeyondRendered)
			}
			return
		}
	}
	t.Fatalf("находка не называет тип поимённо: %v", findings)
}

// TestC05InjectionReorderingTwoCanonBlocksIsCaught — инъекция C-05: переставлены
// два БЛОКА канона.
//
// Канон авторитетен по порядку, но сверка идёт ПО ИМЕНИ ТИПА, поэтому одна лишь
// перестановка блоков расхождения не даёт — и это надо утверждать, а не
// подразумевать: молчание здесь есть СВОЙСТВО, а не слепота. Слепоту исключает
// прогон выше, где та же сверка на снятом объявлении краснеет.
func TestC05InjectionReorderingTwoCanonBlocksIsCaught(t *testing.T) {
	i := strings.Index(twoBlockCanon, "type vpc_network")
	j := strings.Index(twoBlockCanon, "type vpc_subnet")
	if i < 0 || j < 0 || i >= j {
		t.Fatalf("инъекция не нашла обоих блоков — доказательство беспредметно")
	}
	head, first, second := twoBlockCanon[:i], twoBlockCanon[i:j], twoBlockCanon[j:]
	swapped := head + strings.TrimRight(second, "\n") + "\n\n" + strings.TrimRight(first, "\n") + "\n"

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, sixModules(t, swapped), nil)

	if code != modelrender.SweepOK {
		t.Fatalf("перестановка блоков объявлена расхождением: исход %d, находки %v", code, findings)
	}
}

// TestInjectionOfTheExistingPropertyRedsOnlyTheExistingOne — прогон третий:
// инъекция УЖЕ СУЩЕСТВУЮЩЕГО свойства (модуль набора без манифеста).
//
// Она обязана уронить ТОЛЬКО его: канон при этом цел, и ни одна сверка блока
// расхождения не даёт. Без этого прогона молчание сверки блоков на предыдущих
// инъекциях неотличимо от молчания мёртвой.
func TestInjectionOfTheExistingPropertyRedsOnlyTheExistingOne(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	modules := domain.KnownModules()
	for _, m := range modules[:len(modules)-1] {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидалась находка", code)
	}
	for _, f := range findings {
		if f.Type != "" {
			t.Fatalf("сверка блоков покраснела на целом каноне — находка не про модуль: %s", f)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("находок %d, ожидалась ровно одна (снятый манифест): %v", len(findings), findings)
	}
}

// TestC06InjectionALegalTwinStaysSilent — законный близнец: ресурс, чья проза
// выражена ПОЛНОСТЬЮ, расхождения не даёт.
//
// Без этой половины гейт ловил бы форму, а не существо, и первый же ложный
// срабат его отключил бы.
func TestC06InjectionALegalTwinStaysSilent(t *testing.T) {
	const docCanon = `model
  schema 1.1

type vpc_network
  relations
    # разбор, объявленный автором ресурса
    define project: [project]
    define super_admin: super_admin from project
    define admin: [user, service_account, group#member] or super_admin
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or super_admin
`
	root := helperTree(t, docCanon)
	for _, m := range domain.KnownModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - name: network\n    objectType: vpc_network\n    parent: project\n" +
				"    producer: authored\n    doc: \"# разбор, объявленный автором ресурса\"\n" +
				"    verbs:\n      - get\n"
		}
		writeManifest(t, root, m, body)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepOK {
		t.Fatalf("законный близнец объявлен расхождением: исход %d, находки %v", code, findings)
	}
	if census.BlocksCompared != 1 {
		t.Fatalf("сверено блоков %d, ожидался 1: %s", census.BlocksCompared, census)
	}
}
