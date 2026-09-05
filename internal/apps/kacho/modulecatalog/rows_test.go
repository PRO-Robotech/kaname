// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// rows_test.go — СОЕДИНЕНИЕ «манифест → строка каталога», доказанное обходом
// дерева, а не объявленное прозой.
//
// Здесь утверждается свойство, без которого применителя нельзя ни написать, ни
// посадить: множество строк, выведенное ИЗ ШЕСТИ доставляемых манифестов,
// совпадает со множеством, которое сегодня производит литерал
// (`authzmap.CatalogSeed*`) и которым посеяны таблицы.
//
// # Почему это гейт, а не проба одного модуля
//
// Свойство принадлежит ДЕРЕВУ: «манифесты описывают тот же каталог, что литерал».
// Проба одного манифеста о нём не утверждает ничего — она зелена при любом числе
// разошедшихся соседей. Поэтому обход, перепись и отказ на пустом обходе.
//
// # Перепись печатается ВСЕГДА
//
// «Ноль расхождений» обязано быть отличимо от «ноль прочитанного»: обход, не
// нашедший ни одного манифеста, молчит ровно так же уверенно, как сверивший все.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// manifestsRoot — каталог сервисов монорепо относительно этого пакета.
const manifestsRoot = "../../../../../../services"

// deliveredManifests — манифесты, ВЫВЕДЕННЫЕ обходом дерева.
//
// Перечень не выписывается: он растёт вместе с продуктом, и выписанный устарел бы
// молча — ровно тем классом, который корпус ловит в документах.
func deliveredManifests(t *testing.T) []*manifest.Manifest {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(manifestsRoot, "*", "manifest.yaml"))
	require.NoError(t, err)
	sort.Strings(paths)
	out := make([]*manifest.Manifest, 0, len(paths))
	for _, p := range paths {
		body, rerr := os.ReadFile(p) // #nosec G304 -- путь собран обходом дерева проб
		require.NoError(t, rerr, "прочитать %s", p)
		m, lerr := manifest.Load(body)
		require.NoError(t, lerr, "разобрать %s", p)
		out = append(out, m)
	}
	return out
}

// TestManifestRowsReproduceTheSeededCatalog — деривация манифеста даёт РОВНО тот
// каталог, которым посеяны таблицы.
func TestManifestRowsReproduceTheSeededCatalog(t *testing.T) {
	manifests := deliveredManifests(t)
	require.NotEmpty(t, manifests,
		"обход дерева не нашёл ни одного манифеста по %s: вердикт этой пробы беспредметен, "+
			"а «расхождений 0» неотличимо от «прочитано 0»", manifestsRoot)

	gotModules := map[string]bool{}
	gotResources := map[string]bool{}
	gotVerbs := map[string]bool{}
	internalExcluded := 0
	for _, m := range manifests {
		declared, err := modulecatalog.RowsOf(m)
		require.NoError(t, err, "вывести строки каталога модуля %s", m.Module)
		internalExcluded += declared.InternalExcluded
		gotModules[declared.Module] = true
		for _, r := range declared.Resources {
			gotResources[r.Module+"."+r.Resource] = true
		}
		for _, v := range declared.Verbs {
			gotVerbs[verbKey(v.Module, v.Resource, v.Verb, v.PerObject)] = true
		}
	}

	wantModules := map[string]bool{}
	for _, mod := range authzmap.CatalogSeedModules() {
		wantModules[mod] = true
	}
	wantResources := map[string]bool{}
	for _, r := range authzmap.CatalogSeedResources() {
		wantResources[r.Module+"."+r.Resource] = true
	}
	wantVerbs := map[string]bool{}
	for _, v := range authzmap.CatalogSeedVerbs() {
		wantVerbs[verbKey(v.Module, v.Resource, v.Verb, v.PerObject)] = true
	}

	// Перепись называет ОБЕ величины — выведенное и исключённое. Одно число
	// сделало бы «расхождений 0» неотличимым от «исключено всё, сравнивать было
	// нечего»: деривация вправе не давать строки внутреннему действию, и без
	// второго числа неверная ветвь исключения выглядела бы как согласие сторон.
	t.Logf("перепись: манифестов %d · модулей %d (литерал %d) · ресурсов %d (литерал %d) · "+
		"глаголов %d (литерал %d) · исключено действий внутренней плоскости %d",
		len(manifests), len(gotModules), len(wantModules),
		len(gotResources), len(wantResources), len(gotVerbs), len(wantVerbs),
		internalExcluded)

	// Исключение обязано иметь ПРЕДМЕТ: ноль исключённых при объявленных
	// внутренних действиях означал бы, что ветвь не исполняется, и сверка
	// сошлась бы по другой причине, чем думает читатель.
	require.NotZero(t, internalExcluded,
		"исключено ноль действий внутренней плоскости: либо манифесты дерева их больше не "+
			"объявляют (тогда предмет исключения исчез), либо ветвь исключения не исполняется "+
			"— в обоих случаях согласие сторон достигнуто не тем, чем объявлено")

	requireSameSets(t, "модуль", wantModules, gotModules)
	requireSameSets(t, "ресурс", wantResources, gotResources)
	requireSameSets(t, "глагол", wantVerbs, gotVerbs)
}

// verbKey несёт ПРИЗНАК СЛОВАРЯ: строка, выведенная с неверным признаком,
// существует в обоих множествах и по тройке прошла бы сверку молча — а разошлись
// бы ровно те две величины, ради которых словари и разделены.
func verbKey(module, resource, verb string, perObject bool) string {
	kind := " (ярусный)"
	if perObject {
		kind = " (пообъектный)"
	}
	return module + "." + resource + "." + verb + kind
}

// requireSameSets сверяет в ОБЕ стороны: одностороннее включение молчало бы о
// строке, которую манифест объявил сверх литерала, — а именно она и есть та,
// которую посев не заведёт, а ключ отвергнет.
func requireSameSets(t *testing.T, kind string, want, got map[string]bool) {
	t.Helper()
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, kind+" "+k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, kind+" "+k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	require.Emptyf(t, missing, "литерал называет, манифесты не выводят (%s): %v", kind, missing)
	require.Emptyf(t, extra, "манифесты выводят, литерал не называет (%s): %v", kind, extra)
}

// TestVerbTokenCollisionIsRefused — приведение к каноническому виду не вправе
// схлопнуть два объявленных действия в одно.
//
// Отрицание парно: рядом стоит законный близнец той же формы (два действия одного
// ресурса, чьи токены различны), и на нём деривация обязана МОЛЧАТЬ. Без пары
// проба зеленела бы и на деривации, отвергающей всё.
func TestVerbTokenCollisionIsRefused(t *testing.T) {
	collided, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{
			Name: "subnet", ObjectType: "vpc_subnet",
			Verbs: []manifest.Verb{{Name: "addCidrBlocks"}, {Name: "addcidrblocks"}},
		}},
	})
	require.ErrorIs(t, err, modulecatalog.ErrVerbTokenCollision)
	require.Contains(t, err.Error(), "addCidrBlocks",
		"отказ обязан назвать ОБА написания: без них автор ищет дубликат, которого в файле нет")
	require.Contains(t, err.Error(), "addcidrblocks")
	require.Empty(t, collided.Resources, "отказ обязан не оставлять полустроки")

	legal, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{
			Name: "subnet", ObjectType: "vpc_subnet",
			Verbs: []manifest.Verb{{Name: "addCidrBlocks"}, {Name: "removeCidrBlocks"}},
		}},
	})
	require.NoError(t, err, "законный близнец обязан пройти")
	require.Len(t, legal.Verbs, 3, "два объявленных действия плюс ярусное: %v", legal.Verbs)
}

// TestDeclaredCreateGetsNoSecondTierRow — тип, объявивший `create` пообъектно,
// второй строки не получает: первичный ключ у тройки один.
//
// Пара: рядом тот же ресурс БЕЗ объявленного `create` — он ярусную строку
// получает. Односторонняя проба не отличила бы «не дублирует» от «не кладёт».
func TestDeclaredCreateGetsNoSecondTierRow(t *testing.T) {
	withCreate, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "registry",
		Resources: []manifest.Resource{{
			Name: "registries", ObjectType: "registry_registry",
			Verbs: []manifest.Verb{{Name: "get"}, {Name: "create"}},
		}},
	})
	require.NoError(t, err)
	require.Len(t, withCreate.Verbs, 2)
	for _, v := range withCreate.Verbs {
		require.Truef(t, v.PerObject, "объявленное действие обязано быть пообъектным: %+v", v)
	}

	withoutCreate, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "registry",
		Resources: []manifest.Resource{{
			Name: "registries", ObjectType: "registry_registry",
			Verbs: []manifest.Verb{{Name: "get"}},
		}},
	})
	require.NoError(t, err)
	require.Len(t, withoutCreate.Verbs, 2, "ярусная строка не выведена: %v", withoutCreate.Verbs)
	require.False(t, withoutCreate.Verbs[1].PerObject)
	require.Equal(t, "create", withoutCreate.Verbs[1].Verb)
}

// TestResourceWithoutVerbsYieldsNoTierRow — ресурс, не объявивший ни одного
// действия, ярусной строки не получает: отношения `v_*` у него нет, правило на
// него не резолвится ничем, и ярусная строка обещала бы выдачу, которой не будет.
func TestResourceWithoutVerbsYieldsNoTierRow(t *testing.T) {
	out, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "network", ObjectType: "vpc_network"}},
	})
	require.NoError(t, err)
	require.Len(t, out.Resources, 1, "строка ресурса обязана остаться")
	require.Empty(t, out.Verbs)
}

// TestEmptyNamesAreRefused — пустое имя не превращается в строку каталога молча.
//
// Загрузчик такое отвергает, но деривация обязана быть годной и на манифесте,
// собранном в памяти: молча выброшенный ресурс есть каталог, которого никто не
// объявлял, а `catalog_*_nonempty` увидел бы его лишь как отказ без имени.
func TestEmptyNamesAreRefused(t *testing.T) {
	_, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "  ", ObjectType: "vpc_network", Verbs: []manifest.Verb{{Name: "get"}}}},
	})
	require.ErrorIs(t, err, modulecatalog.ErrResourceNameEmpty)

	_, err = modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "network", ObjectType: "vpc_network", Verbs: []manifest.Verb{{Name: " "}}}},
	})
	require.ErrorIs(t, err, modulecatalog.ErrVerbNameEmpty)
}

// TestResourceWithoutObjectTypeIsRefused — ресурс, не назвавший типа модели
// прав, строкой каталога не становится молча.
//
// Отрицание ПАРНОЕ: рядом законный близнец — тот же ресурс с именем типа, — и на
// нём деривация обязана молчать. Без пары проба зеленела бы на деривации,
// отвергающей всё.
//
// Предмет: без имени типа строка доехала бы до писателя и отверглась бы схемой
// (`catalog_resource_object_type_form`), то есть отказ пришёл бы ЧУЖОЙ полосой —
// фразой Postgres про имя ограничения, — и автор манифеста искал бы дефект в
// базе, а не в своём файле. Хуже того, до заведения колонки такой ресурс
// записывался БЕЗ отказа и молча не давал ни одной пары проекции (#1816).
func TestResourceWithoutObjectTypeIsRefused(t *testing.T) {
	_, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "network", Verbs: []manifest.Verb{{Name: "get"}}}},
	})
	require.ErrorIs(t, err, modulecatalog.ErrObjectTypeEmpty)
	require.Contains(t, err.Error(), "vpc.network",
		"отказ обязан назвать ресурс: без имени автор не знает, какую строку манифеста править")

	_, err = modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "network", ObjectType: "  ", Verbs: []manifest.Verb{{Name: "get"}}}},
	})
	require.ErrorIs(t, err, modulecatalog.ErrObjectTypeEmpty,
		"имя из одних пробелов — то же пустое имя: схема отвергла бы его грамматикой")

	legal, err := modulecatalog.RowsOf(&manifest.Manifest{
		APIVersion: "iam/v1", Module: "vpc",
		Resources: []manifest.Resource{{Name: "network", ObjectType: "vpc_network", Verbs: []manifest.Verb{{Name: "get"}}}},
	})
	require.NoError(t, err, "законный близнец обязан пройти")
	require.Len(t, legal.Resources, 1)
	require.Equal(t, "vpc_network", legal.Resources[0].ObjectType,
		"имя типа обязано доехать ДОСЛОВНО: правила вывода из пары не существует")
}
