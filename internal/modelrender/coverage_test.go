// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
	"github.com/PRO-Robotech/kacho-iam/internal/modelrender"
)

// coverage_test.go — блок канона, ПРИНАДЛЕЖАЩИЙ модулю по закрытой таблице, но
// манифестом не порождённый, есть находка «канон сверх порождённого».
//
// Третье состояние, которого не покрывают ни B-06, ни B-08:
//
//	B-06  блок не принадлежит НИ ОДНОМУ модулю          — законный остаток, счётся
//	B-08  модуль набора объявлен, манифеста НЕТ         — находка с именем модуля
//	здесь блок принадлежит модулю, манифест ЕСТЬ,
//	      а ресурса в нём нет                          — молчало
//
// Именно оно есть дословно ПРИЗНАК #1089: блок, дописанный в канон рукой у
// модуля, чей манифест приехал, не встречает НИ ОДНОЙ проверки — сверка обходит
// ресурсы манифеста и о том, чего в нём нет, не спрашивает.

// TestCanonBlockOwnedByAModuleButAbsentFromItsManifestIsAFinding — вход есть в
// закрытой таблице, а в манифесте его нет: находка, называющая ТИП и сторону.
func TestCanonBlockOwnedByAModuleButAbsentFromItsManifestIsAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range authzmap.CatalogSeedModules() {
		body := manifestFor(m)
		if m == "vpc" {
			// Ресурс `subnet` СНЯТ: его блок в каноне остаётся, а порождать его
			// стало нечему.
			body = manifestFor(m, "vpc_network")
		}
		writeManifest(t, root, m, body)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d (находка): блок vpc_subnet канона не порождён "+
			"ничем, и это ТЕРЯЕТ право. Перепись: %s", code, modelrender.SweepFinding, census)
	}
	named := false
	for _, f := range findings {
		if f.Module == "vpc" && f.Type == "vpc_subnet" && f.Side == modelrender.SideCanonBeyondRendered {
			named = true
		}
	}
	if !named {
		t.Fatalf("находка не называет тип и сторону «канон сверх порождённого»: %v", findings)
	}
}

// TestTheSameTreeWithTheResourceDeclaredIsSilent — законный близнец: тот же
// обход, ресурс на месте. Без него краснота выше неотличима от гейта,
// краснеющего на любом дереве.
func TestTheSameTreeWithTheResourceDeclaredIsSilent(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range authzmap.CatalogSeedModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = manifestFor(m, "vpc_network", "vpc_subnet")
		}
		writeManifest(t, root, m, body)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepOK {
		t.Fatalf("исход %d, ожидался %d: ресурсы на месте, находок быть не должно — %v",
			code, modelrender.SweepOK, findings)
	}
	if census.BlocksOwned != 2 {
		t.Fatalf("перепись не называет ожидаемого: блоков модулей %d, в каноне их 2 — %s",
			census.BlocksOwned, census)
	}
}

// TestAnUnparsableManifestIsNotReadAsAbsent — манифест, который не разбирается,
// НЕ является отсутствующим манифестом.
//
// Сегодня обход молча пропускает негодный документ, модуль попадает в «без
// манифеста», ведомость его прощает — и блоки модуля остаются непрочитанными при
// зелёном вердикте. Ведомость при этом НЕ самоистекает: манифест не засчитан,
// значит прощать ей на вид есть что, и запись переживёт свой предмет навсегда.
func TestAnUnparsableManifestIsNotReadAsAbsent(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range authzmap.CatalogSeedModules() {
		writeManifest(t, root, m, manifestFor(m))
	}
	broken := filepath.Join(root, "modules", "vpc", "manifest.yaml")
	if err := os.WriteFile(broken, []byte("apiVersion: iam/v1\nmodule: vpc\nresources: [\n"), 0o600); err != nil {
		t.Fatalf("порча манифеста: %v", err)
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, []modelrender.Waiver{{Module: "vpc", Issue: 1091}})

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: негодный манифест прощён ведомостью как отсутствующий",
			code, modelrender.SweepFinding)
	}
	named := false
	for _, f := range findings {
		if strings.Contains(f.Detail, "не разобран") && strings.Contains(f.Detail, broken) {
			named = true
		}
	}
	if !named {
		t.Fatalf("находка не называет путь негодного документа: %v", findings)
	}
}

// TestTheClosedTableSpeaksTheModuleVocabulary — ключ модуля закрытой таблицы и имя
// модуля закрытого набора суть ОДИН словарь, и сверяется это в ОБЕ стороны.
//
// Держит вывод ожидаемого выше. Разойдись словари — модуль потерял бы все свои
// типы из ожидаемого МОЛЧА: сверка перестала бы его видеть, оставаясь зелёной, и
// отличить это от «у модуля нечего сверять» было бы нечем.
//
// Обе стороны обязательны: одна сторона («ключ таблицы известен набору») зеленеет
// на пустой таблице, другая («у модуля набора есть типы») — на таблице, где
// модулей больше, чем в наборе.
func TestTheClosedTableSpeaksTheModuleVocabulary(t *testing.T) {
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}

	known := map[string]bool{}
	for _, m := range authzmap.CatalogSeedModules() {
		known[m] = true
	}
	for _, e := range authzmap.Catalog() {
		if !known[e.Module] {
			t.Errorf("ключ модуля таблицы %q закрытому набору неизвестен: типы этого модуля "+
				"выпали бы из ожидаемого молча", e.Module)
		}
	}

	total := 0
	for _, m := range authzmap.CatalogSeedModules() {
		owned := modelrender.OwnedTypes(seed.LiteralRows().Resources, dsl, m)
		if len(owned) == 0 {
			t.Errorf("у модуля %s набора нет НИ ОДНОГО типа в каноне: либо ключ таблицы "+
				"разошёлся с набором, либо блоки модуля исчезли из модели", m)
		}
		total += len(owned)
	}
	if total == 0 {
		t.Fatal("обход пуст: ожидаемое не выведено ни для одного модуля")
	}
	t.Logf("перепись: модулей набора %d · типов, принадлежащих модулям %d · вне модулей %d",
		len(authzmap.CatalogSeedModules()), total, len(modelrender.TypesOutsideModules(seed.LiteralRows().Resources, dsl)))
}

// TestASideIsNotClaimedWhenNeitherIsRicher — расхождение, у которого строк
// ПОРОВНУ, не вправе объявляться расширением доступа.
//
// Сторона — утверждение о правах арендатора, а не украшение отчёта: «порождено
// сверх канона» читается как РАСШИРЯЕТ доступ. Объявленная по числу строк, она
// лжёт на самом частом виде расхождения: имена определений те же, отличается
// правая часть одного из них — сужённые субъекты, переименованный ярус, другой
// якорь. Число строк при этом равно, и сторона выбиралась ветвью `default`.
//
// Здесь манифест СУЖАЕТ субъекты ярусов; порождённое беднее канона, а прежний
// вывод называл его богаче — то есть посылал чинить ровно в обратную сторону.
func TestASideIsNotClaimedWhenNeitherIsRicher(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	for _, m := range authzmap.CatalogSeedModules() {
		body := manifestFor(m)
		if m == "vpc" {
			body = "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - name: network\n    objectType: vpc_network\n    parents: [project]\n" +
				"    producer: derived\n    subjects:\n      - user\n    verbs:\n      - get\n" +
				"  - name: subnet\n    objectType: vpc_subnet\n    parents: [project]\n" +
				"    producer: derived\n    verbs:\n      - get\n"
		}
		writeManifest(t, root, m, body)
	}

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: сужённые субъекты — расхождение", code, modelrender.SweepFinding)
	}
	var got modelrender.Finding
	for _, f := range findings {
		if f.Type == "vpc_network" {
			got = f
		}
	}
	if got.Type == "" {
		t.Fatalf("расхождение блока vpc_network не найдено: %v", findings)
	}
	if got.Side == modelrender.SideRenderedBeyondCanon {
		t.Fatalf("сторона названа «%s» на порождённом, которое БЕДНЕЕ канона: "+
			"утверждение о расширении доступа ложно, и чинить оно посылает в обратную "+
			"сторону — %s", got.Side, got.Detail)
	}
	if !strings.Contains(got.Detail, "строка ") {
		t.Errorf("находка не называет первой расходящейся строки: %s", got.Detail)
	}
}
