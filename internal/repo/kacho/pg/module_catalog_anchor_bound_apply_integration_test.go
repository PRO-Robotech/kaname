// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_catalog_anchor_bound_apply_integration_test.go — ПРИМЕНЕНИЕ НЕ ВЫХОДИТ
// ЗА ОПОРУ СТРАЖА ПАРИТЕТА, и опора эта АСИММЕТРИЧНА.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.4; сценарии `IAM-MA-1-10`, `-11`, `-11а`, `-12`.
// Задача продукта #1034.
//
// # Что здесь утверждается
//
// Обе стороны опоры, и они РАЗНЫЕ:
//
//	расширение   манифест объявил строку, которой опора не знает → применение
//	             ОТВЕРГАЕТСЯ внутри транзакции, до коммита (`-11`)
//	сужение      манифест перестал объявлять строку, которую опора называет →
//	             применение ПРОХОДИТ, снятая строка остаётся свидетельством,
//	             и следующий пуск СОСТОИТСЯ (`-11а`, `-12`)
//	починка      лишняя живая строка вне опоры сходит применением, и паритет
//	             становится целым в ОБЕ стороны (`-10`)
//
// Асимметрия — не выбор автора набора, а форма стража: его вердикт
// `Diverged() = len(MissingRows) > 0 || len(ExtraRows) > 0`, и третья корзина
// `WithdrawnRows` в него НЕ входит. Утверждать одну сторону без другой нельзя:
// круги 1–3 приёмки требовали отказа на ОБЕИХ, и это было запретом без
// производителя вреда.
//
// # Что здесь КРАСНО, а что ЗЕЛЕНО
//
//	красно   `-11`: применение за опору сегодня ПРОХОДИТ — свойства нет вовсе
//	зелено   `-10`, `-11а`, `-12`: положительный контроль отрицания. Без них
//	         «применение отвергается» зеленело бы на применителе, отвергающем
//	         всё, а «опора асимметрична» осталось бы утверждением о чужом коде
//
// # Чего здесь НЕТ, и это сказано прямо
//
// О транспорте, правах, операции, подтверждении и потолках — ничего: глагол
// подаётся вызовом применителя, тем же путём, каким его будет исполнять RPC.
// Вред от расширения (пуск отказан) здесь не воспроизводится: его держат пробы
// самого стража (`seed/catalog_parity_test.go`), и второе место об одном
// предмете разошлось бы с первым молча.

import (
	"context"
	"crypto/md5" // #nosec G501 -- отпечаток наблюдения пробы, не криптография
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

const (
	// anchoredModule — модуль, на котором ставятся состояния. Поставляемый, а не
	// синтетический: опора стража — литерал платформы, и строка синтетического
	// модуля лежала бы вне опоры при ЛЮБОМ состоянии.
	anchoredModule = "vpc"
	// spareResource — ресурс, на снятии которого ставится сужающая сторона.
	//
	// Выбран НЕ произвольно, и предпосылка проверяется пробой: он единственный из
	// ресурсов `vpc`, на который не ссылается ни одна проекция посеянной
	// СИСТЕМНОЙ роли. Проекции системных ролей применитель не переселяет
	// намеренно (`apply.go`, п. 3 шапки), поэтому снятие ресурса, который они
	// называют, отвергается КЛЮЧОМ — и проба читала бы чужой отказ как свойство
	// опоры.
	spareResource = "addressPool"
	// beyondAnchorResource — строка, которой опора не знает.
	beyondAnchorResource   = "probeBeyondAnchor"
	beyondAnchorObjectType = "vpc_probe_beyond_anchor"
	// driftResource — лишняя живая строка, заведённая ВНЕ продукта (§5.1: дрейф
	// продуктом не производится, поэтому заводится прямым SQL).
	driftResource   = "probeDrift"
	driftObjectType = "vpc_probe_drift"
)

// TestApplyBeyondTheParityAnchorIsRefused — `IAM-MA-1-11`: применение, которое
// вывело бы каталог ЗА опору, отвергается, и состояние остаётся нетронутым.
//
// КРАСНАЯ проба: сегодня применитель опоры не спрашивает вовсе и такое
// применение проходит, заводя живую строку, которой литерал не знает, — то есть
// делая следующий пуск невозможным.
func TestApplyBeyondTheParityAnchorIsRefused(t *testing.T) {
	ctx, pool := catalogPool(t)
	// Путь ГЛАГОЛА идёт под проверенной личностью (§2.7): фикстура, зовущая его
	// анонимно, была бы снисходительнее продукта.
	ctx = verbCallerCtx(ctx)
	applier := verbApplierOver(t, pool)

	// ПРЕДПОСЫЛКА: посеянный каталог сошёлся с опорой. Без неё отказ ниже
	// приезжал бы неизвестно откуда, а «состояние не изменилось» утверждалось бы
	// о состоянии, которое уже было неверным.
	census, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	logParityCensus(t, "предпосылка", census)

	before := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)

	m := shippedManifest(t, anchoredModule, "")
	m.Resources = append(m.Resources, manifest.Resource{
		Name:       beyondAnchorResource,
		ObjectType: beyondAnchorObjectType,
		Verbs:      []manifest.Verb{{Name: "get"}},
	})

	rep, err := applier.Apply(ctx, verbRequest(t, ctx, pool, m))
	t.Logf("перепись применения: %s", rep)
	require.Error(t, err,
		"применение, объявляющее строку вне опоры, ПРОШЛО: каталог выведен за пределы того, "+
			"что знает образ, и следующий пуск отказан стражем паритета — глагол стал кирпичом")

	require.Equal(t, before, moduleCatalogSnapshot(t, ctx, pool, anchoredModule),
		"отказ оставил след: применение обязано быть отвергнуто ВНУТРИ транзакции, до коммита")

	after, perr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	logParityCensus(t, "после отказа", after)
	require.NoError(t, perr,
		"после отказа каталог обязан оставаться сошедшимся с опорой: лишние живые строки %v",
		after.ExtraRows)
}

// TestApplyNarrowingTheCatalogPassesAndTheNextBootStands — `IAM-MA-1-11а` и
// `-12`: сужение каталога ПРОХОДИТ, снятая строка остаётся свидетельством, а
// путь старта после него поднимается.
//
// ЗЕЛЁНАЯ проба, и она положительный контроль к `-11`: без неё отрицание выше
// зеленело бы на применителе, отвергающем всё. Она же — вторая сторона
// асимметрии: снятие даёт `WithdrawnRows`, а не `MissingRows`, и в вердикт
// стража эта корзина не входит.
func TestApplyNarrowingTheCatalogPassesAndTheNextBootStands(t *testing.T) {
	ctx, pool := catalogPool(t)
	// Путь ГЛАГОЛА идёт под проверенной личностью (§2.7): фикстура, зовущая его
	// анонимно, была бы снисходительнее продукта.
	ctx = verbCallerCtx(ctx)
	applier := verbApplierOver(t, pool)

	census, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	logParityCensus(t, "предпосылка", census)

	// ПРЕДПОСЫЛКА ФИКСТУРЫ: снимаемую строку не называет ни одна проекция
	// СИСТЕМНОЙ роли. Иначе отказ пришёл бы ключом, и проба утверждала бы о
	// системных ролях, а не об опоре.
	rules, verbs, selectors := systemProjectionsNaming(t, ctx, pool, anchoredModule, spareResource)
	t.Logf("перепись фикстуры: системных проекций на %s.%s — правил %d, выдач %d, селекторов %d",
		anchoredModule, spareResource, rules, verbs, selectors)
	require.Zerof(t, rules+verbs+selectors,
		"строку %s.%s называют проекции системных ролей: снятие отвергнет КЛЮЧ, "+
			"и проба прочитала бы чужой отказ как свойство опоры", anchoredModule, spareResource)

	declaredVerbs := verbsDeclaredFor(shippedManifest(t, anchoredModule, ""), spareResource)
	require.NotEmpty(t, declaredVerbs, "у снимаемого ресурса нет объявленных действий: снимать нечего")
	m := shippedManifest(t, anchoredModule, spareResource)

	rep, err := applier.Apply(ctx, verbRequest(t, ctx, pool, m))
	t.Logf("перепись применения: %s", rep)
	require.NoError(t, err,
		"сужение каталога отвергнуто: страж принимает снятие третьей корзиной, "+
			"и отказ здесь был бы правилом строже стража")
	require.Equal(t, 1, rep.RetiredResources, "ожидалось снятие ровно одной строки ресурса: %s", rep)

	// Снятие — ПОМЕТКА, а не удаление: обратимость стоит на том, что снятая
	// строка занимает первичный ключ.
	exists, live, retiredAt, reason := catalogResourceState(t, ctx, pool, anchoredModule, spareResource)
	require.True(t, exists, "снятая строка УДАЛЕНА: свидетельства о снятии не осталось")
	require.False(t, live, "снятая строка осталась живой")
	require.NotNil(t, retiredAt, "у снятой строки не проставлен момент снятия")
	require.NotEmpty(t, reason, "у снятой строки нет причины: за неё никто не отвечает")

	// Пуск СОСТОИТСЯ — вердикт стража, а не мнение пробы.
	after, perr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	logParityCensus(t, "после сужения", after)
	require.NoError(t, perr, "после законного сужения путь старта отказан: %v", perr)
	require.NotEmpty(t, after.WithdrawnRows, "снятие не попало в третью корзину стража")
	require.Truef(t, namesRow(after.WithdrawnRows, "ресурс "+anchoredModule+"."+spareResource),
		"третья корзина не называет снятую строку поимённо: %v", after.WithdrawnRows)
	require.Empty(t, after.MissingRows, "законное снятие приехало НЕДОСТАЮЩЕЙ строкой")
	require.Empty(t, after.ExtraRows, "сужение завело лишнюю живую строку")
	require.False(t, after.Diverged(), "вердикт стража учёл третью корзину: опора перестала быть асимметричной")
}

// TestApplyFixingDriftPassesAndLeavesParityWhole — `IAM-MA-1-10`: применение,
// сходящее дрейф, проходит и оставляет паритет целым в ОБЕ стороны.
//
// ЗЕЛЁНАЯ проба. Дрейф заводится ПРЯМЫМ SQL: продуктом он не производится (§5.1
// приёмки, Н10), и завести его иначе нечем. Отказ стража ДО применения
// утверждается отдельно — это положительный контроль того, что страж не спит, и
// без него «паритет цел после применения» зеленело бы на страже, молчащем всегда.
func TestApplyFixingDriftPassesAndLeavesParityWhole(t *testing.T) {
	ctx, pool := catalogPool(t)
	// Путь ГЛАГОЛА идёт под проверенной личностью (§2.7): фикстура, зовущая его
	// анонимно, была бы снисходительнее продукта.
	ctx = verbCallerCtx(ctx)
	applier := verbApplierOver(t, pool)

	_, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")

	insertDriftResource(t, ctx, pool, anchoredModule, driftResource, driftObjectType)

	drifted, derr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	logParityCensus(t, "дрейф заведён", drifted)
	require.Error(t, derr, "лишняя живая строка вне опоры обязана ронять пуск — иначе чинить нечего")
	require.Truef(t, namesRow(drifted.ExtraRows, "ресурс "+anchoredModule+"."+driftResource),
		"страж не назвал лишнюю строку поимённо: %v", drifted.ExtraRows)

	rep, err := applier.Apply(ctx, verbRequest(t, ctx, pool, shippedManifest(t, anchoredModule, "")))
	t.Logf("перепись применения: %s", rep)
	require.NoError(t, err, "применение, сходящее дрейф, отвергнуто")
	require.Equal(t, 1, rep.RetiredResources, "дрейфовая строка не снята: %s", rep)

	exists, live, retiredAt, reason := catalogResourceState(t, ctx, pool, anchoredModule, driftResource)
	require.True(t, exists, "дрейфовая строка УДАЛЕНА: снятие обязано быть пометкой, а не удалением")
	require.False(t, live, "дрейфовая строка осталась живой")
	require.NotNil(t, retiredAt, "у снятой строки не проставлен момент снятия")
	require.NotEmpty(t, reason, "у снятой строки нет причины")

	fixed, ferr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	logParityCensus(t, "после починки", fixed)
	require.NoError(t, ferr, "после починки путь старта по-прежнему отказан: %v", ferr)
	require.Empty(t, fixed.ExtraRows, "лишняя строка пережила применение")
	require.Empty(t, fixed.MissingRows, "починка унесла строку, которую опора называет")
	require.NotContains(t, liveResourceNames(t, ctx, pool, anchoredModule), driftResource,
		"дрейфовая строка осталась среди живых")
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники набора

// verbApplierOver — применитель ПУТИ ГЛАГОЛА над своим пулом.
//
// Не `applierOver`, и это предмет набора, а не оформление: полос применения две,
// и сверку опоры внутри транзакции несёт ТОЛЬКО глагол. На пути старта её делает
// страж сразу после применения, и его отказ есть отказ пуска — второй рубеж,
// которого у глагола нет вовсе (`modulecatalog.applyLane`). Позови этот набор
// применителем старта — он утверждал бы о полосе, у которой этой обязанности
// нет, и краснел бы на верном коде.
func verbApplierOver(t *testing.T, pool *pgxpool.Pool) *modulecatalog.VerbApplier {
	t.Helper()
	return modulecatalog.NewVerbApplier(kachopg.NewCatalogWriteRepo(pool))
}

// moduleCatalogSnapshot — НАБЛЮДЕНИЕ пробы: изменилось ли хоть что-нибудь в трёх
// каталожных таблицах ОДНОГО модуля.
//
// Это НЕ подтверждающий отпечаток §2.5 и не его черновик: там предмет — «сделает
// ли применение что-то иное, чем показал план», и алгоритм принадлежит
// реализации. Здесь предмет один — «осталось ли состояние прежним», — и он
// свойством контракта не является. Сведя их в один помощник, набор объявил бы
// продукту алгоритм, который приёмка оставляет свободным.
//
// Отпечаток строится из СОДЕРЖИМОГО строк, а не из их числа: мощности сошлись бы
// и при подмене одной строки другой — а это ровно тот исход, который откат
// обязан исключать.
func moduleCatalogSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string) string {
	t.Helper()
	var payload string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT coalesce(string_agg(x, '|' ORDER BY x), '') FROM (
		  SELECT 'm:' || module || ':' || live::text AS x
		    FROM kacho_iam.catalog_module WHERE module = $1
		  UNION ALL
		  SELECT 'r:' || resource || ':' || object_type || ':' || live::text ||
		         ':' || coalesce(retired_reason, '')
		    FROM kacho_iam.catalog_resource WHERE module = $1
		  UNION ALL
		  SELECT 'v:' || resource || '.' || verb || ':' || live::text ||
		         ':' || per_object::text || ':' || coalesce(retired_reason, '')
		    FROM kacho_iam.catalog_verb WHERE module = $1
		) s`, module).Scan(&payload))
	require.NotEmptyf(t, payload, "каталог модуля %s пуст: сверять нечего", module)
	sum := md5.Sum([]byte(payload)) // #nosec G401 -- наблюдение пробы, не криптография
	return hex.EncodeToString(sum[:])
}

// verbsDeclaredFor — действия, объявленные манифестом для названного ресурса.
func verbsDeclaredFor(m *manifest.Manifest, name string) []string {
	var out []string
	for _, r := range m.Resources {
		if r.Name != name {
			continue
		}
		for _, v := range r.Verbs {
			out = append(out, v.Name)
		}
	}
	return out
}

// systemProjectionsNaming — сколько проекций СИСТЕМНЫХ ролей называют строку.
//
// Системность читается якорем кластера (`cluster_id IS NOT NULL`) — тем же
// способом, каким её ставит платформа: колонка `is_system` вычисляемая.
func systemProjectionsNaming(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, resource string) (rules, verbs, selectors int) {
	t.Helper()
	dotted := module + "." + resource
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kacho_iam.role_rule_ref rr
		          JOIN kacho_iam.roles ro ON ro.id = rr.role_id
		         WHERE rr.module = $1 AND rr.resource = $2 AND ro.cluster_id IS NOT NULL),
		       (SELECT count(*) FROM kacho_iam.role_verb rv
		          JOIN kacho_iam.roles ro ON ro.id = rv.role_id
		         WHERE rv.object_type = $3 AND ro.cluster_id IS NOT NULL),
		       (SELECT count(*) FROM kacho_iam.role_rule_selectors rs
		          JOIN kacho_iam.roles ro ON ro.id = rs.role_id
		         WHERE $3 = ANY(rs.object_types) AND ro.cluster_id IS NOT NULL)`,
		module, resource, dotted).Scan(&rules, &verbs, &selectors))
	return rules, verbs, selectors
}

// catalogResourceState — состояние строки ресурса: есть ли она вовсе, жива ли,
// когда снята и по какой причине.
func catalogResourceState(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, resource string) (exists, live bool, retiredAt *time.Time, reason string) {
	t.Helper()
	var reasonValue *string
	err := pool.QueryRow(ctx, `
		SELECT live, retired_at, retired_reason FROM kacho_iam.catalog_resource
		 WHERE module = $1 AND resource = $2`, module, resource).Scan(&live, &retiredAt, &reasonValue)
	if err != nil {
		return false, false, nil, ""
	}
	if reasonValue != nil {
		reason = *reasonValue
	}
	return true, live, retiredAt, reason
}

// insertDriftResource — дрейф ВНЕ продукта: живая строка, которой не знает ни
// манифест, ни опора. `module_live` не перечисляется — колонка вычисляемая.
func insertDriftResource(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, resource, objectType string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type, live)
		VALUES ($1, $2, $1 || '.' || $2, $3, true)`, module, resource, objectType)
	require.NoError(t, err, "завести дрейфовую строку прямым SQL")
}

// liveResourceNames — имена живых ресурсов модуля.
func liveResourceNames(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT resource FROM kacho_iam.catalog_resource WHERE module = $1 AND live ORDER BY resource`, module)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out = append(out, name)
	}
	require.NoError(t, rows.Err())
	return out
}

// namesRow — перечень стража называет строку с этой идентичностью.
//
// Сверяется ПРЕФИКС, а не строка целиком: ключ сверки несёт ещё и ФОРМУ строки
// (имя типа модели прав у ресурса, признак словаря у действия), и она свойством
// этого сценария не является. Проба, выписавшая ключ дословно, краснела бы на
// переименовании типа, ничего не менявшем в предмете.
func namesRow(rows []string, identity string) bool {
	for _, r := range rows {
		if r == identity || strings.HasPrefix(r, identity+" ") {
			return true
		}
	}
	return false
}

// logParityCensus — перепись стража печатается ВСЕГДА: «ноль расхождений»
// обязано быть отличимо от «ноль прочитанного».
func logParityCensus(t *testing.T, when string, c seed.CatalogParityCensus) {
	t.Helper()
	t.Logf("паритет (%s): литерал %d/%d/%d, живыми %d/%d/%d, снятыми %d/%d/%d; "+
		"нет строкой %v, нет в литерале %v, снято решением %d",
		when, c.LiteralModules, c.LiteralResources, c.LiteralVerbs,
		c.RowModules, c.RowResources, c.RowVerbs,
		c.RetiredModules, c.RetiredResources, c.RetiredVerbs,
		c.MissingRows, c.ExtraRows, len(c.WithdrawnRows))
}
