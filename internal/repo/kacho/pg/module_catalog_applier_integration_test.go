// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_applier_integration_test.go — ПРИМЕНИТЕЛЬ КАТАЛОГА против живой
// Postgres (задача продукта #1034).
//
// # Что здесь утверждается
//
// Четыре свойства предиката готовности задачи плюс половина пятого:
//
//	атомарность     применение, отказавшее на ПОСЛЕДНЕМ элементе, не оставляет
//	                следа ни в одной таблице — сверяется хешем состояния
//	идемпотентность второе применение подряд не меняет ни строки
//	порядок         снятие, поставленное раньше переселения, отвергается КЛЮЧОМ
//	                (`23503`) — то есть порядок держит схема, а не память автора
//	замок           применение ЖДЁТ, пока каталог занят другим применением,
//	                а не переписывает его
//	«файла нет»     модуль, чей манифест не подан, строк не теряет
//
// # Чего здесь НЕТ, и это сказано прямо
//
// О транспорте, операции, правах и подтверждении эти пробы не говорят НИЧЕГО:
// глагол подаётся вызовом применителя — тем же путём, каким его будет исполнять
// RPC. Вторая половина сценария «файла нет» — «старт отказал с текстом,
// называющим файл» — принадлежит стражу паритета, чья опорная сторона переезжает
// с литерала на манифесты отдельным предметом (#1861): сегодня отсутствие файла
// литерал не меняет, и утверждать здесь отказ старта значило бы утверждать
// желаемое.
//
// # Почему синтетический модуль, а не поставляемый
//
// Поставляемые манифесты дают РОВНО тот каталог, который посеян миграцией (это
// утверждает гейт `modulecatalog.TestManifestRowsReproduceTheSeededCatalog`), и
// потому на них не построить ни одного сценария изменения: применение поставляемого
// манифеста — заведомый ноль. Синтетический модуль даёт обе стороны: и заведение,
// и снятие. Что заведомый ноль ДЕЙСТВИТЕЛЬНО ноль — утверждается отдельно, на
// поставляемом манифесте.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// applierProbeModule — модуль, на котором ставятся сценарии применителя.
//
// Синтетический и НЕ член платформенного набора намеренно: сценарии снятия на
// поставляемом модуле трогали бы строки, на которые ссылаются посеянные системные
// роли, и отвергались бы ЧУЖОЙ ссылкой — то есть зеленели бы, даже если бы
// применитель не записал ничего.
const applierProbeModule = "probemod"

// probeManifest — манифест синтетического модуля, собранный В ПАМЯТИ.
//
// Собран, а не разобран из файла: сценариям нужен вход, который загрузчик
// отвергает (действие с точкой в имени), и подавать его файлом значило бы
// заводить в дереве заведомо негодный манифест, который найдёт следующий обход.
func probeManifest(resources ...manifest.Resource) *manifest.Manifest {
	return &manifest.Manifest{APIVersion: "iam/v1", Module: applierProbeModule, Resources: resources}
}

// probeResource — ресурс синтетического модуля.
//
// `objectType` проставляется ВСЕГДА, потому что манифест без него негоден:
// загрузчик отвергает такой ресурс (`manifest.ErrObjectTypeRequired`), схема —
// грамматикой колонки, а деривация — `modulecatalog.ErrObjectTypeEmpty`.
// Фикстура, оставлявшая поле пустым, была СНИСХОДИТЕЛЬНЕЕ продукта: она подавала
// вход, которого в дереве не бывает, и делала невидимым ровно то, ради чего
// колонка заведена (#1816).
//
// Имя типа выводится из пары синтетического модуля — здесь это законно: имя
// принадлежит фикстуре, а не каталогу платформы, и правила вывода оно не
// объявляет.
func probeResource(name string, verbs ...string) manifest.Resource {
	r := manifest.Resource{Name: name, ObjectType: applierProbeModule + "_" + strings.ToLower(name)}
	for _, v := range verbs {
		r.Verbs = append(r.Verbs, manifest.Verb{Name: v})
	}
	return r
}

// stateFingerprint — отпечаток ВСЕХ таблиц, которых применитель касается.
//
// Шесть таблиц, а не три: применитель пишет каталог и переселяет проекции, и
// «ничего не изменилось» обязано покрывать обе половины. Отпечаток строится из
// содержимого строк, а не из их числа: мощности сошлись бы и при подмене одной
// строки другой — а это ровно тот исход, который атомарность обязана исключать.
func stateFingerprint(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var fp string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT md5(coalesce(string_agg(x, '|' ORDER BY x), '')) FROM (
		  SELECT 'm:' || module || ':' || live::text ||
		         ':' || coalesce(retired_reason, '') AS x
		    FROM kacho_iam.catalog_module
		  UNION ALL
		  SELECT 'r:' || dotted || ':' || live::text ||
		         ':' || coalesce(retired_reason, '')
		    FROM kacho_iam.catalog_resource
		  UNION ALL
		  SELECT 'v:' || module || '.' || resource || '.' || verb || ':' || live::text ||
		         ':' || per_object::text || ':' || coalesce(retired_reason, '')
		    FROM kacho_iam.catalog_verb
		  UNION ALL
		  SELECT 'rr:' || role_id || ':' || module || '.' || resource ||
		         ':' || coalesce(verb, '')
		    FROM kacho_iam.role_rule_ref
		  UNION ALL
		  SELECT 'rv:' || role_id || ':' || object_type || ':' || verb
		    FROM kacho_iam.role_verb
		  UNION ALL
		  SELECT 'or:' || role_id || ':' || object_type || ':' || verb || ':' || source
		    FROM kacho_iam.role_grant_orphan
		) s`).Scan(&fp))
	return fp
}

// applierOver — применитель над своим пулом.
func applierOver(t *testing.T, pool *pgxpool.Pool) *modulecatalog.Applier {
	t.Helper()
	return modulecatalog.NewApplier(kachopg.NewCatalogWriteRepo(pool))
}

// TestModuleCatalogApplierIsAtomic — отказ на ПОСЛЕДНЕМ элементе не оставляет
// следа ни в одной таблице.
//
// Отказ настоящий и приходит от СЕРВЕРА, а не подставлен обёрткой: действие
// `z.bad` каноническому виду не противоречит (оно уже строчное), но нарушает
// `catalog_verb_undotted`. Применитель об этом ограничении не знает — его держит
// схема, — поэтому проба утверждает откат транзакции, а не аккуратность кода.
func TestModuleCatalogApplierIsAtomic(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	before := stateFingerprint(t, ctx, pool)
	mods, res, verbs := liveCatalogCounts(t, ctx, pool)
	t.Logf("перепись ДО: живых модулей %d ресурсов %d глаголов %d, отпечаток %s",
		mods, res, verbs, before)

	// Ресурс `b` идёт вторым по имени, а `z.bad` — последним по токену внутри
	// него: значит отказ приходит на ПОСЛЕДНЕМ операторе применения, когда строка
	// модуля, оба ресурса и все прочие действия уже записаны.
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("aFirst", "get", "list"),
		probeResource("bSecond", "get", "z.bad"),
	))
	require.Error(t, err, "применение с негодным действием обязано отказать")
	code, constraint := pgCode(err)
	require.Equal(t, "23514", code, "отказ обязан прийти от схемы: %v", err)
	require.Equal(t, "catalog_verb_undotted", constraint, "отказ обязан назвать ограничение: %v", err)

	after := stateFingerprint(t, ctx, pool)
	require.Equal(t, before, after,
		"отказ на последнем элементе оставил след: применение не атомарно")

	// Положительный контроль: тот же манифест БЕЗ негодного действия проходит и
	// отпечаток МЕНЯЕТ. Без него равенство выше зеленело бы и на применителе,
	// который не пишет вовсе.
	rep, err := applier.Apply(ctx, probeManifest(
		probeResource("aFirst", "get", "list"),
		probeResource("bSecond", "get"),
	))
	require.NoError(t, err)
	require.True(t, rep.Changed(), "положительный контроль обязан изменить каталог: %s", rep)
	require.NotEqual(t, before, stateFingerprint(t, ctx, pool),
		"положительный контроль отпечаток не изменил — сверять было нечего")
	t.Logf("положительный контроль: %s", rep)
}

// TestModuleCatalogApplierIsIdempotent — второе применение подряд не меняет ни
// строки, и это утверждается ДВУМЯ независимыми величинами: перепись применителя
// и отпечаток состояния.
func TestModuleCatalogApplierIsIdempotent(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	m := probeManifest(
		probeResource("alpha", "get", "list", "update"),
		probeResource("beta", "get", "delete"),
	)

	first, err := applier.Apply(ctx, m)
	require.NoError(t, err)
	require.True(t, first.Changed(), "первое применение обязано изменить каталог: %s", first)
	t.Logf("первое применение: %s", first)

	settled := stateFingerprint(t, ctx, pool)

	second, err := applier.Apply(ctx, m)
	require.NoError(t, err)
	t.Logf("второе применение: %s", second)
	require.False(t, second.Changed(), "второе применение изменило каталог: %s", second)
	require.Zero(t, second.WrittenResources+second.WrittenVerbs+
		second.RetiredResources+second.RetiredVerbs, "второе применение записало строки: %s", second)
	require.False(t, second.ModuleWritten, "второе применение переписало строку модуля")
	require.Equal(t, first.DeclaredResources, second.UnchangedResources,
		"второе применение обязано признать ВСЕ ресурсы неизменными")
	require.Equal(t, first.DeclaredVerbs, second.UnchangedVerbs,
		"второе применение обязано признать ВСЕ действия неизменными")
	require.Equal(t, settled, stateFingerprint(t, ctx, pool),
		"второе применение изменило состояние при переписи «без изменений»")
}

// TestModuleCatalogApplierAgreesWithTheSeededCatalog — применение ПОСТАВЛЯЕМОГО
// манифеста к посеянному каталогу не меняет ни строки.
//
// Это и есть условие, при котором применителя можно посадить, не сломав старт:
// страж паритета сверяет живые строки с литералом, и применение, сдвинувшее хоть
// одну строку, сделало бы следующий старт невозможным. Гейт `rows_test.go`
// утверждает то же множествами В ПАМЯТИ; здесь — строками В БАЗЕ.
func TestModuleCatalogApplierAgreesWithTheSeededCatalog(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	// `../../../../..` от этого пакета — каталог `services` монорепо.
	paths, err := filepath.Glob(filepath.Join("../../../../..", "*", "manifest.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "обход дерева не нашёл манифестов: вердикт беспредметен")

	before := stateFingerprint(t, ctx, pool)
	applied := 0
	for _, p := range paths {
		body, rerr := os.ReadFile(p) // #nosec G304 -- путь собран обходом дерева проб
		require.NoError(t, rerr)
		m, lerr := manifest.Load(body)
		require.NoError(t, lerr, "разобрать %s", p)
		rep, aerr := applier.Apply(ctx, m)
		require.NoError(t, aerr, "применить %s", p)
		require.Falsef(t, rep.Changed(),
			"применение поставляемого манифеста %s сдвинуло каталог — следующий старт "+
				"отказал бы стражем паритета: %s", m.Module, rep)
		applied++
	}
	t.Logf("перепись: применено манифестов %d, изменений ноль", applied)
	require.Equal(t, before, stateFingerprint(t, ctx, pool),
		"поставляемые манифесты изменили посеянный каталог")
}

// TestModuleCatalogWithdrawalOrderIsHeldByTheKey — порядок «переселить, затем
// снять» держит КЛЮЧ, а не память автора.
//
// Утверждаются ОБЕ стороны: применитель со своим порядком проходит и переселяет,
// а перестановка тех же шагов отвергается сервером с `23503`. Односторонняя проба
// зеленела бы на применителе, который не снимает вовсе.
func TestModuleCatalogWithdrawalOrderIsHeldByTheKey(t *testing.T) {
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	full := probeManifest(probeResource("gamma", "get", "list"))
	_, err := applier.Apply(ctx, full)
	require.NoError(t, err)

	roleID := catalogRole(t, ctx, pool, "mcorder")
	require.NoError(t, writeRuleRefs(t, ctx, repo, roleID,
		[]domain.RoleRuleRef{{Module: applierProbeModule, Resource: "gamma", Verb: "get"}}))

	// ПЕРЕСТАНОВКА: снять раньше, чем переселить. Тот же оператор снятия, что и у
	// применителя, — но без предшествующего переселения.
	swapped := func() error {
		tx, berr := pool.Begin(ctx)
		require.NoError(t, berr)
		defer func() { _ = tx.Rollback(ctx) }()
		if _, eerr := tx.Exec(ctx, `
			UPDATE kacho_iam.catalog_verb SET retired_at = now(), live = false,
			       retired_reason = 'перестановка шагов'
			 WHERE module = $1 AND resource = $2 AND verb = $3 AND live`,
			applierProbeModule, "gamma", "get"); eerr != nil {
			return eerr
		}
		return tx.Commit(ctx)
	}()
	require.Error(t, swapped, "снятие при живой ссылке обязано быть отвергнуто")
	code, constraint := pgCode(swapped)
	require.Equal(t, "23503", code, "перестановка обязана быть отвергнута КЛЮЧОМ: %v", swapped)
	t.Logf("перестановка шагов отвергнута: SQLSTATE %s, ограничение %s", code, constraint)

	// ПОРЯДОК ПРИМЕНИТЕЛЯ: то же снятие проходит, потому что переселение стоит
	// раньше и снимает ссылку.
	rep, err := applier.Apply(ctx, probeManifest(probeResource("gamma", "list")))
	require.NoError(t, err, "применитель обязан снять действие в своём порядке")
	t.Logf("порядок применителя: %s", rep)
	require.Equal(t, 1, rep.RetiredVerbs, "ожидалось снятие ровно одного действия: %s", rep)
	require.Equal(t, 1, rep.Resettled.RuleRefs, "объявление правила не переселено: %s", rep)

	// Переселено, а не отобрано молча: строка обязана лежать в сиротах.
	var orphans int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_grant_orphan
		 WHERE role_id = $1 AND object_type = $2 AND verb = $3 AND source = 'rule_ref'`,
		string(roleID), applierProbeModule+".gamma", "get").Scan(&orphans))
	require.Equal(t, 1, orphans, "снятое объявление не записано в сироты — право отобрано молча")
}

// TestModuleCatalogApplierRefusesToStripASystemRole — проекция СИСТЕМНОЙ роли не
// переселяется: манифест, снимающий ресурс, который его же роль называет,
// противоречит сам себе, и это отвергает ключ.
//
// Отрицание парно к предыдущей пробе: там та же ссылка от АРЕНДАТОРСКОЙ роли
// переселяется и снятие проходит. Без пары «не переселяет системные» зеленело бы
// и на применителе, который не переселяет вовсе.
func TestModuleCatalogApplierRefusesToStripASystemRole(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	_, err := applier.Apply(ctx, probeManifest(probeResource("delta", "get", "list")))
	require.NoError(t, err)

	// Системная роль заводится напрямую: её путь — применитель ролей (#1824), а
	// предмет этой пробы — реакция каталога на её ссылку, не способ её завести.
	//
	// `is_system` НЕ перечислен: он вычисляемый (`cluster_id IS NOT NULL`), и
	// присвоение ему значения отвергается сервером. Системность здесь ставится
	// якорем кластера — тем же способом, каким её ставит платформа.
	roleID := "role_mc_sys_" + strings.ReplaceAll(applierProbeModule, "-", "")
	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, cluster_id, name, description, permissions)
		VALUES ($1, (SELECT id FROM kacho_iam.clusters LIMIT 1), $2, $3, '["iam.users.*.read"]'::jsonb)`,
		roleID, applierProbeModule+".probe", "probe system role")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		VALUES ($1, $2, $3, $4)`, roleID, applierProbeModule, "delta", "get")
	require.NoError(t, err)

	before := stateFingerprint(t, ctx, pool)
	_, err = applier.Apply(ctx, probeManifest(probeResource("delta", "list")))
	require.Error(t, err, "снятие ресурса, названного СИСТЕМНОЙ ролью, обязано быть отвергнуто")
	code, constraint := pgCode(err)
	require.Equal(t, "23503", code, "отказ обязан прийти ключом: %v", err)
	t.Logf("системная ссылка отвергнута: SQLSTATE %s, ограничение %s", code, constraint)
	require.Equal(t, before, stateFingerprint(t, ctx, pool),
		"отказ оставил след: применение не атомарно")
}

// TestModuleCatalogApplierWaitsForTheCatalogLock — применение ЖДЁТ, пока каталог
// занят, а не переписывает его.
//
// Ожидание утверждается СОСТОЯНИЕМ, а не паузой: проба ждёт появления
// неудовлетворённого консультативного замка в `pg_locks`. Пауза измеряла бы
// скорость машины, а не свойство применителя.
func TestModuleCatalogApplierWaitsForTheCatalogLock(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	// Первый применитель — не имитация: замок берётся ТЕМ ЖЕ ключом и тем же
	// оператором, каким его берёт применитель. Ключ спрашивается у писателя, а не
	// выписывается: второй литерал разошёлся бы с первым молча, и проба на чужом
	// ключе не дождалась бы блокировки вовсе.
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, kachopg.CatalogLockKey)
	require.NoError(t, err)

	var (
		wg       sync.WaitGroup
		applyErr error
		done     = make(chan struct{})
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		_, applyErr = applier.Apply(ctx, probeManifest(probeResource("epsilon", "get")))
	}()

	require.Eventually(t, func() bool {
		var waiting int
		if qerr := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
		).Scan(&waiting); qerr != nil {
			return false
		}
		return waiting == 1
	}, 30*time.Second, 50*time.Millisecond,
		"второе применение не встало в ожидание замка — значит замок не берётся")

	select {
	case <-done:
		t.Fatal("применение прошло, пока каталог занят: замок не держит")
	default:
	}

	require.NoError(t, holder.Commit(ctx))
	wg.Wait()
	require.NoError(t, applyErr, "применение обязано пройти, как только замок отпущен")

	// Положительный контроль: без удерживаемого замка то же применение проходит
	// сразу. Без него «встало в ожидание» неотличимо от «висит всегда».
	free := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, probeManifest(probeResource("epsilon", "get"), probeResource("zeta", "get")))
		free <- aerr
	}()
	select {
	case aerr := <-free:
		require.NoError(t, aerr)
	case <-time.After(30 * time.Second):
		t.Fatal("применение на свободном каталоге не завершилось: ждёт не того")
	}
}

// TestModuleCatalogApplierLeavesUnappliedModulesAlone — модуль, чей манифест не
// подан, строк не теряет.
//
// Половина сценария «файла нет»: отсутствие манифеста снятием НЕ является.
// Вторая половина — отказ старта — принадлежит стражу паритета (#1861), см. шапку.
func TestModuleCatalogApplierLeavesUnappliedModulesAlone(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	before := readCatalogCensus(t, ctx, pool)
	_, err := applier.Apply(ctx, probeManifest(probeResource("eta", "get")))
	require.NoError(t, err)
	after := readCatalogCensus(t, ctx, pool)

	// Каждая строка КАЖДОГО прочего модуля обязана пережить применение чужого
	// манифеста. Сравнение множествами, а не мощностями: мощности сошлись бы и
	// при подмене одной строки другой.
	for _, other := range []struct {
		kind string
		was  map[string]bool
		now  map[string]bool
	}{
		{"модуль", before.modules, after.modules},
		{"ресурс", before.resources, after.resources},
		{"глагол", before.verbs, after.verbs},
	} {
		for key := range other.was {
			if strings.HasPrefix(key, applierProbeModule) {
				continue
			}
			require.Truef(t, other.now[key],
				"применение манифеста %s унесло чужую строку (%s %s)", applierProbeModule, other.kind, key)
		}
	}

	var orphans int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_grant_orphan`).Scan(&orphans))
	require.Zero(t, orphans, "применение чужого манифеста переселило чьи-то права")
	t.Logf("перепись: до — модулей %d ресурсов %d глаголов %d; после — %d/%d/%d",
		len(before.modules), len(before.resources), len(before.verbs),
		len(after.modules), len(after.resources), len(after.verbs))
}

// TestModuleCatalogApplierRoundTripsAModule — установка → снятие → установка
// возвращает ТЕ ЖЕ строки живыми.
//
// Обратимость — предмет пометки снятия: удалённая строка вернулась бы новой, и
// выдачи на неё пришлось бы заводить заново.
func TestModuleCatalogApplierRoundTripsAModule(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	full := probeManifest(probeResource("theta", "get", "list"), probeResource("iota", "get"))

	_, err := applier.Apply(ctx, full)
	require.NoError(t, err)
	installed := moduleCensus(t, ctx, pool, applierProbeModule)

	shrunk, err := applier.Apply(ctx, probeManifest(probeResource("theta", "get")))
	require.NoError(t, err)
	t.Logf("сужение: %s", shrunk)
	require.Positive(t, shrunk.RetiredResources+shrunk.RetiredVerbs,
		"сужение не сняло ни строки: сравнивать нечего")
	require.NotEqual(t, installed, moduleCensus(t, ctx, pool, applierProbeModule))

	restored, err := applier.Apply(ctx, full)
	require.NoError(t, err)
	t.Logf("восстановление: %s", restored)
	require.Equal(t, installed, moduleCensus(t, ctx, pool, applierProbeModule),
		"повторная установка вернула не то множество, которое было снято")

	// Оживление, а не вставка: строк с этим модулем ровно столько, сколько было.
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_resource WHERE module = $1`,
		applierProbeModule).Scan(&rows))
	require.Equal(t, 2, rows, "снятая строка не ожила, а завелась второй")
}

// moduleCensus — живые строки одного модуля множествами.
func moduleCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT 'r:' || resource FROM kacho_iam.catalog_resource WHERE module = $1 AND live
		UNION ALL
		SELECT 'v:' || resource || '.' || verb || ':' || per_object::text
		  FROM kacho_iam.catalog_verb WHERE module = $1 AND live
		ORDER BY 1`, module)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}
