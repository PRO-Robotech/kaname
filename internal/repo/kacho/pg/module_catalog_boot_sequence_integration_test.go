// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_boot_sequence_integration_test.go — ПОСЛЕДОВАТЕЛЬНОСТЬ СТАРТА
// против живой Postgres: доставка прочитана → манифесты применены → страж
// паритета зелен (задача продукта #1034).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ СОСЕДНИХ ПРОБ ПРИМЕНИТЕЛЯ
//
// `module_catalog_applier_integration_test.go` судит ГЛАГОЛ: атомарность, замок,
// порядок ключа, идемпотентность, «файла нет». Он подаёт манифест, собранный В
// ПАМЯТИ, потому что ему нужны входы, которых загрузчик не пропускает.
//
// Здесь предмет другой — ЦЕПОЧКА, которую теперь исполняет композиционный корень.
// Манифесты приходят ТЕМ ЖЕ путём, каким их получает работающая служба: из
// каталога доставки, через `manifest.LoadDelivered`, с ключами в форме ключей
// ConfigMap (`<каталог службы>.manifest.yaml`, см. `pkg/modulemanifest/producer`).
// Собери я вход в памяти — проба утверждала бы о применителе, а не о старте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ, И ПОЧЕМУ КАЖДОЕ — ОТДЕЛЬНОЕ УТВЕРЖДЕНИЕ
//
//	цепочка      доставка → применение → страж проходит целиком, и каталог ПОСЛЕ
//	             применения совпадает с манифестами (предикат #1034)
//	второй старт применение повторно ничего не меняет: перезапуск пода —
//	             штатный режим, и он обязан быть тождественным
//	страж жив    сверка литерала со строками остаётся ЗЕЛЁНОЙ после применения —
//	             без этого провязка ломала бы старт, а не чинила его
//	ключ судит   пустое имя модуля отвергает КЛЮЧ, а не код: инвариант внутри
//	             одной БД держится конструкцией БД (запрет #10)
//
// «Страж зелен» — не украшение к «цепочка прошла». Страж стоит ПОСЛЕ применителя
// намеренно: он судит то, что применитель ТОЛЬКО ЧТО записал, и потому ConfigMap
// в одиночку не вправе расширить каталог за пределы того, что знает образ. Проба,
// утверждающая только «применение прошло», молчала бы ровно о том, ради чего
// порядок и выбран.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// deliveryOfShippedManifests раскладывает ПОСТАВЛЯЕМЫЕ манифесты дерева в
// каталог доставки — ровно в той форме, в какой их кладёт ConfigMap.
//
// Ключ — `<каталог службы>.manifest.yaml`, а не `<модуль>/manifest.yaml`: имя
// `manifest.yaml` в одном ConfigMap может быть только одно, а подкаталога в нём
// не бывает вовсе (замер — `manifest/delivery.go`, «почему имя судится иначе»).
// Возьми проба форму дерева — она читала бы вход, которого доставка не порождает.
func deliveryOfShippedManifests(t *testing.T) (dir string, modules []string) {
	t.Helper()
	// `../../../../..` от этого пакета — каталог `services` монорепо.
	paths, err := filepath.Glob(filepath.Join("../../../../..", "*", "manifest.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "обход дерева не нашёл манифестов: вердикт беспредметен")

	dir = t.TempDir()
	for _, p := range paths {
		body, rerr := os.ReadFile(p) // #nosec G304 -- путь собран обходом дерева проб
		require.NoError(t, rerr)
		svcDir := filepath.Base(filepath.Dir(p))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, svcDir+".manifest.yaml"), body, 0o600))
		modules = append(modules, svcDir)
	}
	return dir, modules
}

// catalogRowCensus — перепись ЖИВЫХ строк каталога. Три величины, а не одна:
// «модулей столько же, ресурсов меньше» — состояние, которое одна величина
// скрывает.
func catalogRowCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (mods, res, verbs int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kacho_iam.catalog_module   WHERE live),
		       (SELECT count(*) FROM kacho_iam.catalog_resource WHERE live),
		       (SELECT count(*) FROM kacho_iam.catalog_verb     WHERE live)`).
		Scan(&mods, &res, &verbs))
	return mods, res, verbs
}

// TestModuleCatalogBootSequenceConvergesTheCatalogAndKeepsTheParityGuardGreen —
// предикат задачи #1034 против живой базы.
func TestModuleCatalogBootSequenceConvergesTheCatalogAndKeepsTheParityGuardGreen(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kachopg.NewCatalogRepo(pool)

	// ── шаг 1: доставка читается ТЕМ ЖЕ читателем, что и на старте ──────────
	dir, shipped := deliveryOfShippedManifests(t)
	report, err := manifest.LoadDelivered(dir)
	require.NoError(t, err, "доставка поставляемых манифестов отвергнута читателем старта")
	require.Len(t, report.Manifests, len(shipped),
		"читатель доставки вернул не все манифесты: положено %v", shipped)
	t.Logf("доставка: осмотрено файлов %d · прочитано манифестов %d · модули %v",
		report.PathsSeen, report.ManifestsRead, report.Modules())

	before := stateFingerprint(t, ctx, pool)
	modsBefore, resBefore, verbsBefore := catalogRowCensus(t, ctx, pool)

	// ── шаг 2: применение ──────────────────────────────────────────────────
	census, err := applier.ApplyAll(ctx, report.Manifests)
	require.NoError(t, err, "применение доставленных манифестов отказало — старт службы "+
		"не состоялся бы: %s", census)
	require.Equal(t, len(report.Manifests), census.Applied,
		"применены не все доставленные манифесты: %s", census)
	t.Logf("применение: %s", census)

	// Каталог ПОСЛЕ применения совпадает с объявленным: применение поставляемых
	// манифестов к посеянному каталогу не двигает ни строки — это и есть условие,
	// при котором применителя можно было посадить, не сломав старт.
	require.False(t, census.Changed(),
		"применение доставленных манифестов СДВИНУЛО каталог — страж паритета ниже "+
			"отказал бы, и служба не поднялась бы: %s", census)
	require.Equal(t, before, stateFingerprint(t, ctx, pool),
		"отпечаток состояния изменился при переписи «изменений ноль» — перепись лжёт")

	modsAfter, resAfter, verbsAfter := catalogRowCensus(t, ctx, pool)
	require.Equal(t, [3]int{modsBefore, resBefore, verbsBefore}, [3]int{modsAfter, resAfter, verbsAfter},
		"мощности живых строк изменились: было модулей %d ресурсов %d глаголов %d, "+
			"стало %d/%d/%d", modsBefore, resBefore, verbsBefore, modsAfter, resAfter, verbsAfter)
	t.Logf("каталог после применения: модулей %d · ресурсов %d · глаголов %d",
		modsAfter, resAfter, verbsAfter)

	// ── шаг 3: страж паритета — ПОСЛЕ применителя, как в serve.go ───────────
	parity, perr := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	require.NoError(t, perr,
		"страж паритета отверг каталог ПОСЛЕ применения — провязка ломала бы старт, "+
			"а не чинила его (недостаёт %d, лишних %d)",
		len(parity.MissingRows), len(parity.ExtraRows))
	t.Logf("страж: литерал %d/%d/%d · строки %d/%d/%d · недостаёт %d · лишних %d",
		parity.AnchorModules, parity.AnchorResources, parity.AnchorVerbs,
		parity.RowModules, parity.RowResources, parity.RowVerbs,
		len(parity.MissingRows), len(parity.ExtraRows))

	// ── шаг 4: второй старт тождествен первому ─────────────────────────────
	// Перезапуск пода — штатный режим, а не исключение: применение обязано быть
	// тождественным, иначе каждый перезапуск двигал бы каталог.
	second, serr := applier.ApplyAll(ctx, report.Manifests)
	require.NoError(t, serr)
	require.False(t, second.Changed(),
		"ВТОРОЕ применение подряд объявило изменения — перезапуск пода двигал бы "+
			"каталог: %s", second)
	require.Equal(t, before, stateFingerprint(t, ctx, pool),
		"второе применение сдвинуло состояние")
	_, perr2 := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	require.NoError(t, perr2, "страж отверг каталог после ВТОРОГО применения")
}

// TestModuleCatalogApplyAllIsRefusedByTheKeyOnAnEmptyModuleName — пустое имя
// модуля отвергает КЛЮЧ, а не код.
//
// Проба стоит здесь, а не рядом с юнитами применителя, и это решение: подставной
// писатель снисходительнее настоящего by construction, и утверждение «пустое имя
// отвергнуто» на нём зеленело бы и при дублирующей проверке в коде, и без неё.
// Инвариант внутри одной БД держит конструкция БД (запрет #10), поэтому и
// утверждать его вправе только база — и она называет ограничение по имени.
func TestModuleCatalogApplyAllIsRefusedByTheKeyOnAnEmptyModuleName(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	before := stateFingerprint(t, ctx, pool)
	_, err := applier.ApplyAll(ctx, []*manifest.Manifest{{
		APIVersion: "iam/v1", Module: "",
		Resources: []manifest.Resource{{Name: "widgets", ObjectType: "bootmod_widgets", Verbs: []manifest.Verb{{Name: "get"}}}},
	}})
	require.Error(t, err, "манифест без имени модуля применён — строка каталога с пустым "+
		"модулем адресуема ничем")
	require.ErrorIs(t, err, modulecatalog.ErrWriteFailed,
		"отказ пришёл не от писателя — значит его выдумал код, а не ключ: %v", err)
	require.True(t, strings.Contains(err.Error(), "catalog_module_nonempty"),
		"отказ не назвал НАРУШЕННОЕ ОГРАНИЧЕНИЕ — оператору нечем чинить: %v", err)

	require.Equal(t, before, stateFingerprint(t, ctx, pool),
		"отвергнутое применение оставило след — транзакция не откатилась")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же манифест с непустым именем модуля проходит.
	// Без него отрицание выше зеленело бы на базе, отвергающей всякую запись.
	twin, terr := applier.ApplyAll(ctx, []*manifest.Manifest{{
		APIVersion: "iam/v1", Module: applierProbeModule,
		Resources: []manifest.Resource{{Name: "widgets", ObjectType: "bootmod_widgets", Verbs: []manifest.Verb{{Name: "get"}}}},
	}})
	require.NoError(t, terr, "законный близнец отвергнут — проба утверждала бы об отказе "+
		"всякой записи, а не о пустом имени")
	require.True(t, twin.Changed(), "законный близнец ничего не записал: %s", twin)
}
