// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_delivered_anchor_integration_test.go — предикат задачи #1861
// ПРОТИВ ЖИВОЙ БАЗЫ: модуль, которого образ не несёт, применяется, и следующий
// старт проходит.
//
// # Почему это не закрывается пробами над значениями
//
// Пробы стража и вердикта опоры судят СВЕРКУ. Они ничего не говорят о том, что
// применитель такую строку вообще запишет и что записанное переживёт чтение
// живого множества: строку пишет база, и её ключи (`catalog_*_live_uk`,
// `CHECK (live = (retired_at IS NULL))`) — часть предмета. Здесь весь путь идёт
// через настоящий Postgres.
//
// # Манифест строится В ПАМЯТИ, а не файлом доставки
//
// Загрузчик проверяет связность раздела с каноном модели прав, и синтетический
// модуль его не прошёл бы — по делу: канон о нём не знает. Предмет этой пробы
// лежит НИЖЕ загрузчика (деривация → запись → сверка), поэтому вход подаётся
// прямо туда. Что доставка такой манифест ДОНЕСЁТ — предмет соседней полосы.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// Модуль, которого образ не несёт. Имена заведомо вне словаря платформы.
const (
	tenantOnlyModule   = "tenantops"
	tenantOnlyResource = "runbook"
	tenantOnlyType     = "tenantops_runbook"
)

// tenantOnlyManifest — манифест арендатора: один ресурс, одно пообъектное
// действие. `withResource` ложен — тот же модуль БЕЗ ресурса, то есть отзыв.
func tenantOnlyManifest(withResource bool) *manifest.Manifest {
	m := &manifest.Manifest{APIVersion: "tenantops/v1", Module: tenantOnlyModule}
	if withResource {
		m.Resources = []manifest.Resource{{
			Name:       tenantOnlyResource,
			ObjectType: tenantOnlyType,
			Verbs:      []manifest.Verb{{Name: "get", Class: "get"}},
		}}
	}
	return m
}

// namesRowOf — называет ли перепись строку, содержащую подстроку.
func namesRowOf(rows []string, want string) bool {
	for _, r := range rows {
		if len(r) >= len(want) && containsRow(r, want) {
			return true
		}
	}
	return false
}

func containsRow(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestDeliveredModuleTheImageDoesNotCarryApplesAndTheNextBootPasses — три
// предиката задачи #1861 подряд, на одной живой базе.
func TestDeliveredModuleTheImageDoesNotCarryApplesAndTheNextBootPasses(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kachopg.NewCatalogRepo(pool)

	dir, shipped := deliveryOfShippedManifests(t)
	report, lerr := manifest.LoadDelivered(dir)
	require.NoError(t, lerr)
	require.Len(t, report.Manifests, len(shipped))

	// ПРЕДПОСЫЛКА: до применения каталог сходится с образом. Без неё всё
	// нижеследующее могло бы зеленеть на уже разошедшейся базе.
	base, berr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	require.NoErrorf(t, berr, "каталог разошёлся с образом ДО пробы — вердикт беспредметен: %v", berr)
	t.Logf("до применения: опора %d/%d/%d, живых строк %d/%d/%d",
		base.AnchorModules, base.AnchorResources, base.AnchorVerbs,
		base.RowModules, base.RowResources, base.RowVerbs)

	delivery := append(append([]*manifest.Manifest{}, report.Manifests...), tenantOnlyManifest(true))

	// ── предикат 1: манифест с НОВЫМ ресурсом применяется ───────────────────
	census, aerr := applier.ApplyAll(ctx, delivery)
	require.NoErrorf(t, aerr, "применение модуля, которого образ не несёт, отказало: %s", census)
	require.Truef(t, census.Changed(), "применение ничего не изменило — строка арендатора "+
		"не записана, и всё нижеследующее судило бы пустое место: %s", census)
	t.Logf("применение: %s", census)

	anchor, anerr := modulecatalog.AnchorOfDelivery(delivery)
	require.NoError(t, anerr, "опора «образ ∪ доставка» не собралась")
	require.NotEmpty(t, anchor.AddedRows(), "опора не расширилась: доставка объявила то же, "+
		"что образ, и проба беспредметна")
	t.Logf("опора расширена доставкой на %d строк: %v", len(anchor.AddedRows()), anchor.AddedRows())

	// ── предикат 1 (продолжение): СЛЕДУЮЩИЙ СТАРТ проходит ─────────────────
	after, perr := seed.AssertCatalogParity(ctx, repo, anchor)
	require.NoErrorf(t, perr, "страж отказал в пуске на строке, ОБЪЯВЛЕННОЙ доставкой: %v. "+
		"Нет строкой %v; нет в опоре %v", perr, after.MissingRows, after.ExtraRows)
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к утверждению об отзыве ниже: пока строка ЖИВА, она
	// снятой не называется. Без него «отзыв доехал» зеленело бы и без отзыва.
	require.Falsef(t, namesRowOf(after.WithdrawnRows, tenantOnlyModule+"."+tenantOnlyResource),
		"живая строка названа снятой: %v", after.WithdrawnRows)
	t.Logf("после применения: опора %d/%d/%d, живых строк %d/%d/%d",
		after.AnchorModules, after.AnchorResources, after.AnchorVerbs,
		after.RowModules, after.RowResources, after.RowVerbs)

	// ── предикат 3: та же база при опоре ОДНОГО ОБРАЗА — отказ ──────────────
	// Это одновременно КОНТРОЛЬ: он доказывает, что состояние действительно
	// вышло за образ, а не что страж перестал смотреть.
	drifted, derr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	require.Errorf(t, derr, "живая строка %s.%s не объявлена образом, а страж пустил: "+
		"расхождение доставки с применённым перестало быть отказом старта",
		tenantOnlyModule, tenantOnlyResource)
	require.Truef(t, namesRowOf(drifted.ExtraRows, tenantOnlyModule+"."+tenantOnlyResource),
		"отказ не назвал лишнюю строку поимённо: %v", drifted.ExtraRows)
	require.Contains(t, derr.Error(), "нет в опоре",
		"отказ не назвал предмет расхождения словами")

	// ── предикат 2: ОТЗЫВ ресурса доезжает и не молчит ─────────────────────
	withdrawn := append(append([]*manifest.Manifest{}, report.Manifests...), tenantOnlyManifest(false))
	wcensus, werr := applier.ApplyAll(ctx, withdrawn)
	require.NoErrorf(t, werr, "отзыв ресурса отказал: %s", wcensus)
	require.Truef(t, wcensus.Changed(), "отзыв ничего не изменил: %s", wcensus)
	t.Logf("отзыв: %s", wcensus)

	// Судится ПРЕЖНЕЙ опорой — той, что строку ещё называет. Это и есть
	// различающий вход: строка ушла из живого множества, а опора её ждёт.
	// Взять здесь суженную опору значило бы спросить про строку, которой ни одна
	// сторона не называет, — вердикт был бы зелен и при отзыве, и при том, что
	// строки не было НИКОГДА.
	gone, gerr := seed.AssertCatalogParity(ctx, repo, anchor)
	require.NoErrorf(t, gerr, "отзыв, объявленный манифестом, отказал в пуске: %v. "+
		"Нет строкой %v — снятая строка прочиталась как непроехавший посев",
		gerr, gone.MissingRows)
	require.Truef(t, namesRowOf(gone.WithdrawnRows, tenantOnlyModule+"."+tenantOnlyResource),
		"отзыв доехал МОЛЧА: снятых строк названо %v, а перепись обязана назвать %s.%s "+
			"поимённо — иначе отличить решение оператора от непроехавшего посева нечем",
		gone.WithdrawnRows, tenantOnlyModule, tenantOnlyResource)
	require.Emptyf(t, gone.MissingRows,
		"снятая строка попала в НЕДОСТАЮЩИЕ: два состояния чинятся противоположно, "+
			"и оператор пошёл бы применять миграции вместо того, чтобы ничего не делать: %v",
		gone.MissingRows)
	t.Logf("после отзыва: снятых %d/%d/%d, снято решением %d строк: %v",
		gone.RetiredModules, gone.RetiredResources, gone.RetiredVerbs,
		len(gone.WithdrawnRows), gone.WithdrawnRows)

	// И суженная опора (доставка больше строки не называет) тоже пускает: она
	// её не ждёт вовсе.
	wanchor, waerr := modulecatalog.AnchorOfDelivery(withdrawn)
	require.NoError(t, waerr)
	_, nerr := seed.AssertCatalogParity(ctx, repo, wanchor)
	require.NoError(t, nerr, "суженная опора отвергла каталог после отзыва")
}
