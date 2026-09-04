// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_catalog_confirmation_and_ceilings_integration_test.go — ГЛАГОЛ ДЕЛАЕТ
// ТО, ЧТО ПОКАЗАЛ ПЛАН, и не больше, чем оператор разрешил.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.5 и §2.6; сценарии `IAM-MA-1-13`, `-14`, `-18`, `-19`,
// `-20`. Задача продукта #1034.
//
// # Что здесь утверждается
//
//	`-13`  подтверждение, снятое до применения, ПРОПУСКАЕТ применение
//	`-14`  сдвинувшийся каталог отвергает применение ДО коммита
//	`-16`  движение арендаторских ролей подтверждения НЕ обесценивает —
//	       утверждение о ПРОДУКТЕ, а не о выражении, выписанном пробой
//	`-18`  подтверждение обязательно: пустое отвергается по имени поля
//	`-19`  превышение ЛЮБОГО из двух потолков отвергает применение до коммита
//	`-20`  отсутствие потолка отличимо от нуля: `nil` — отказ, ноль — законное
//	       значение, которое ПРОХОДИТ
//
// # Пары, а не половины
//
// `-13` и `-14` стоят вместе: «сдвинувшееся отвергнуто» зеленело бы на
// применителе, отвергающем всё, а «совпавшее прошло» — на применителе, не
// сверяющем ничего. То же у `-19`/`-20`: отказ по потолку без прохода в пределах
// потолка означал бы «потолок запрещает всегда», а проход без отказа — «потолка
// нет».
//
// # Отпечаток читается ТЕМ ЖЕ выражением, каким его читает CAS
//
// `kachopg.ModuleStateExpr` экспортирован ради этого — тот же довод, что у
// `CatalogLockKey`. Выписанная здесь копия разошлась бы с прод-выражением
// МОЛЧА: на несдвинутом каталоге обе копии отвечают «совпало», и расхождение
// стало бы видно ровно там, где его уже нечем заметить.
//
// # Чего здесь НЕТ
//
// О транспорте, конверте операции и правах вызывающего — ничего: вход подаётся
// вызовом применителя глагола, тем же путём, каким его будет исполнять RPC.
// Числа третьей популяции здесь не утверждаются — их предмет у
// `TestApplyMovesThreePopulationsOfConsequenceNotTwo` и у следа аудита.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// verbCallerPrincipal — ПРОВЕРЕННАЯ личность, под которой набор зовёт глагол.
//
// Глагол без неё отказывает (§2.7), поэтому всякая проба пути ГЛАГОЛА обязана
// её назвать: фикстура, зовущая применитель анонимно, была бы снисходительнее
// продукта. Значение отличимо от настоящего намеренно — правдоподобный
// крокфордов идентификатор совпал бы с чужим.
var verbCallerPrincipal = operations.Principal{
	Type:        "user",
	ID:          "usr-probe-module-catalog-verb",
	DisplayName: "проба глагола применения каталога",
}

// verbCallerCtx — контекст с проверенной личностью вызывающего глагол.
func verbCallerCtx(ctx context.Context) context.Context {
	return operations.WithPrincipal(ctx, verbCallerPrincipal)
}

// generousCeiling — потолок, заведомо не задевающий пробу, чей предмет НЕ
// потолок.
//
// Назван константой, а не выписан числом по месту: проба, случайно упёршаяся в
// потолок, отказала бы по причине, о которой ничего не утверждает, и разбирали
// бы её как дефект применения.
const generousCeiling = 1000

// moduleStateOf — отпечаток состояния каталога модуля, снятый ПРОД-выражением.
//
// Своего выражения проба не держит: у состава подтверждения один автор
// (`kachopg.ModuleStateExpr`), и вторая копия разошлась бы с ним молча.
func moduleStateOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string) string {
	t.Helper()
	var state string
	require.NoError(t, pool.QueryRow(ctx, `SELECT `+kachopg.ModuleStateExpr, module).Scan(&state))
	require.NotEmptyf(t, state, "отпечаток модуля %s пуст: подтверждать нечем", module)
	return state
}

// verbRequest — вход глагола: подтверждение по ТЕКУЩЕМУ состоянию и потолки,
// заведомо не задевающие предмет пробы.
func verbRequest(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	m *manifest.Manifest) modulecatalog.Request {
	t.Helper()
	return modulecatalog.Request{
		Manifest:              m,
		ExpectedState:         moduleStateOf(t, ctx, pool, m.Module),
		MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
		MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
	}
}

// TestApplyConfirmsTheStateItWasPlannedAgainst — `-13`, `-14` и `-16`: обе
// стороны подтверждения плюс его слепота к движению арендатора.
func TestApplyConfirmsTheStateItWasPlannedAgainst(t *testing.T) {
	t.Run("совпавшее подтверждение пропускает применение", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		ctx = verbCallerCtx(ctx)
		applier := verbApplierOver(t, pool)

		census, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
		logParityCensus(t, "предпосылка", census)

		state := moduleStateOf(t, ctx, pool, anchoredModule)
		t.Logf("подтверждение снято до применения: %s", shortHash(state))

		rep, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              shippedManifest(t, anchoredModule, spareResource),
			ExpectedState:         state,
			MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		t.Logf("перепись применения: %s", rep)
		require.NoError(t, aerr, "применение с совпавшим подтверждением отвергнуто")
		require.Equal(t, 1, rep.RetiredResources, "применение ничего не сняло: половина беспредметна: %s", rep)

		// Подтверждение ОДНОРАЗОВО by construction: состояние сдвинулось тем же
		// применением, и повтор с прежним отпечатком обязан быть отвергнут.
		_, rerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              shippedManifest(t, anchoredModule, spareResource),
			ExpectedState:         state,
			MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		require.ErrorIs(t, rerr, modulecatalog.ErrStateMoved,
			"повтор с ПРЕЖНИМ подтверждением прошёл: значит подтверждение не читается вовсе")
	})

	t.Run("сдвинувшийся каталог отвергает применение до коммита", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		ctx = verbCallerCtx(ctx)
		applier := verbApplierOver(t, pool)

		_, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")

		stale := moduleStateOf(t, ctx, pool, anchoredModule)

		// СДВИГ — прямым SQL: форма живой строки продуктом в это состояние не
		// приводится (§5.1, Н10), и завести его иначе нечем. Правится ровно та
		// колонка, которую читает `WHERE` писателя.
		tag, uerr := pool.Exec(ctx, `
			UPDATE kacho_iam.catalog_resource SET object_type = $3
			 WHERE module = $1 AND resource = $2 AND live`,
			anchoredModule, spareResource, "vpc_probe_moved")
		require.NoError(t, uerr, "сдвинуть форму живой строки")
		require.EqualValues(t, 1, tag.RowsAffected(), "сдвиг не задел ни одной живой строки")

		moved := moduleStateOf(t, ctx, pool, anchoredModule)
		require.NotEqual(t, stale, moved,
			"сдвиг формы строки отпечатка не изменил: отрицание ниже стало бы вакуумным")
		t.Logf("состояние сдвинуто: %s → %s", shortHash(stale), shortHash(moved))

		before := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
		rep, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              shippedManifest(t, anchoredModule, spareResource),
			ExpectedState:         stale,
			MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		t.Logf("перепись применения: %s", rep)
		require.ErrorIs(t, aerr, modulecatalog.ErrStateMoved,
			"применение по УСТАРЕВШЕМУ подтверждению прошло: глагол сделал не то, что показал план")
		require.Equal(t, before, moduleCatalogSnapshot(t, ctx, pool, anchoredModule),
			"отказ подтверждения оставил след: сверка обязана ронять транзакцию ДО коммита")
	})

	t.Run("движение арендаторских ролей подтверждения не обесценивает", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		ctx = verbCallerCtx(ctx)
		catRepo := kachopg.NewCatalogRepo(pool)
		repo := kachopg.New(pool, nil)
		applier := verbApplierOver(t, pool)

		census, err := seed.AssertCatalogParity(ctx, catRepo)
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
		snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
		require.NoError(t, err, "снимок каталога")

		state := moduleStateOf(t, ctx, pool, anchoredModule)

		// ДВИЖЕНИЕ АРЕНДАТОРА между планом и применением — ровно тот вход, от
		// которого подтверждение обязано быть слепо: к каталогу оно отношения не
		// имеет, а обесценив план, запретило бы применение всякому, у кого есть
		// хоть один активный арендатор.
		tn := seedVerdictTenant(t, ctx, pool)
		_, pairs := declareRole(t, ctx, pool, repo, snap,
			tn.accountID, tn.userID, anchoredModule, spareResource)
		require.NotEmpty(t, pairs, "проекция роли пуста: движения не произошло, и сверять нечего")

		// КОНТРОЛЬ НЕВАКУУМНОСТИ: движение действительно произошло — иначе
		// «подтверждение уцелело» выполнялось бы потому, что не изменилось ничего.
		require.NotEqual(t, moduleCatalogSnapshotWide(t, ctx, pool), "",
			"наблюдение пробы пусто")
		require.Positivef(t, tenantSelectorRowsOf(t, ctx, pool, tn.accountID),
			"арендаторская роль не завела ни одного селектора: движения не было")

		rep, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              shippedManifest(t, anchoredModule, spareResource),
			ExpectedState:         state,
			MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		t.Logf("перепись применения: %s", rep)
		require.NoError(t, aerr,
			"подтверждение, снятое ДО заведения арендаторской роли, протухло: план "+
				"обесценивался бы чужим циклом создания и удаления роли (`-16`)")
	})
}

// TestApplyByVerbRequiresConfirmationAndBothCeilings — `-18` и `-20`:
// обязательные части входа названы ПОИМЁННО, а ноль потолка — законное значение.
func TestApplyByVerbRequiresConfirmationAndBothCeilings(t *testing.T) {
	ctx, pool := catalogPool(t)
	ctx = verbCallerCtx(ctx)
	applier := verbApplierOver(t, pool)

	_, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")

	before := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
	state := moduleStateOf(t, ctx, pool, anchoredModule)
	m := func() *manifest.Manifest { return shippedManifest(t, anchoredModule, spareResource) }

	t.Run("без подтверждения — отказ по имени поля", func(t *testing.T) {
		_, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              m(),
			MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		require.ErrorIs(t, aerr, modulecatalog.ErrExpectedStateRequired,
			"глагол без подтверждения прошёл: применение перестало быть связано с планом")
		require.Contains(t, aerr.Error(), "expected_state",
			"отказ не называет поле: вызывающему нечем починить вход")
	})

	t.Run("без потолка первой популяции — отказ по имени поля", func(t *testing.T) {
		_, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:              m(),
			ExpectedState:         state,
			MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
		})
		require.ErrorIs(t, aerr, modulecatalog.ErrLimitRequired, "неназванный потолок принят")
		require.Contains(t, aerr.Error(), "max_resettled_rule_refs", "отказ не называет поле")
	})

	t.Run("без потолка второй популяции — отказ по имени поля", func(t *testing.T) {
		_, aerr := applier.Apply(ctx, modulecatalog.Request{
			Manifest:             m(),
			ExpectedState:        state,
			MaxResettledRuleRefs: modulecatalog.Limit(generousCeiling),
		})
		require.ErrorIs(t, aerr, modulecatalog.ErrLimitRequired, "неназванный потолок принят")
		require.Contains(t, aerr.Error(), "max_resettled_role_verbs", "отказ не называет поле")
	})

	// Ни один из трёх отказов не тронул каталог: они приходят ДО транзакции.
	require.Equal(t, before, moduleCatalogSnapshot(t, ctx, pool, anchoredModule),
		"отказ по неполному входу оставил след в каталоге")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к трём отрицаниям, и он же `-20`: НОЛЬ — законное
	// значение потолка, а не «не задано». Арендаторов в этой базе нет, значит
	// переселять нечего, и нулевой потолок обязан ПРОПУСТИТЬ применение.
	rep, aerr := applier.Apply(ctx, modulecatalog.Request{
		Manifest:              m(),
		ExpectedState:         state,
		MaxResettledRuleRefs:  modulecatalog.Limit(0),
		MaxResettledRoleVerbs: modulecatalog.Limit(0),
	})
	t.Logf("перепись применения с НУЛЕВЫМИ потолками: %s", rep)
	require.NoError(t, aerr,
		"нулевой потолок отверг применение, которое не переселяет ничего: "+
			"ноль стал означать «не задано», а «не задано» означает «не сужаем»")
	require.Equal(t, 1, rep.RetiredResources, "применение ничего не сняло: контроль беспредметен: %s", rep)
	require.Zero(t, rep.Resettled.RuleRefs+rep.Resettled.RoleVerbs,
		"переселение всё-таки было: ноль потолка утверждался о входе, которого проба не ставила")
}

// TestApplyRefusesWhenAResettleCeilingIsExceeded — `-19`: превышение потолка
// отвергает применение ДО коммита, по КАЖДОЙ популяции отдельно.
func TestApplyRefusesWhenAResettleCeilingIsExceeded(t *testing.T) {
	ctx, pool := catalogPool(t)
	ctx = verbCallerCtx(ctx)
	catRepo := kachopg.NewCatalogRepo(pool)
	repo := kachopg.New(pool, nil)
	applier := verbApplierOver(t, pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo)
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	// АРЕНДАТОРСКАЯ роль, чьё правило называет снимаемый ресурс: без неё
	// переселять нечего, и потолок никогда не был бы превышен — отрицание
	// зеленело бы на пустом входе.
	tn := seedVerdictTenant(t, ctx, pool)
	_, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, anchoredModule, spareResource)
	require.NotEmpty(t, pairs, "проекция роли пуста: переселять нечего, и потолок беспредметен")

	rules, verbs, selectors := tenantProjectionsNaming(t, ctx, pool, anchoredModule, spareResource)
	t.Logf("перепись фикстуры: правил %d, выдач %d, селекторов %d", rules, verbs, selectors)
	require.Positive(t, rules, "первая популяция беспредметна")
	require.Positive(t, verbs, "вторая популяция беспредметна")

	before := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
	state := moduleStateOf(t, ctx, pool, anchoredModule)

	// ПЕРВАЯ популяция: потолок объявлений правила ноль при непустом переселении.
	_, aerr := applier.Apply(ctx, modulecatalog.Request{
		Manifest:              shippedManifest(t, anchoredModule, spareResource),
		ExpectedState:         state,
		MaxResettledRuleRefs:  modulecatalog.Limit(0),
		MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
	})
	require.ErrorIs(t, aerr, modulecatalog.ErrResettleCeilingExceeded,
		"превышение потолка объявлений правила прошло: право отобрано молча")
	require.Contains(t, aerr.Error(), "max_resettled_rule_refs",
		"отказ не назвал ПОПУЛЯЦИЮ: оператору нечем понять, какой из двух потолков поднять")
	t.Logf("отказ по первой популяции: %v", aerr)

	// ВТОРАЯ популяция: потолок выдач ноль при щедром первом. Отдельным вызовом,
	// потому что сумма их не различает — а различие и есть предмет пары.
	_, verr := applier.Apply(ctx, modulecatalog.Request{
		Manifest:              shippedManifest(t, anchoredModule, spareResource),
		ExpectedState:         state,
		MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
		MaxResettledRoleVerbs: modulecatalog.Limit(0),
	})
	require.ErrorIs(t, verr, modulecatalog.ErrResettleCeilingExceeded,
		"превышение потолка выдач прошло")
	require.Contains(t, verr.Error(), "max_resettled_role_verbs", "отказ не назвал ПОПУЛЯЦИЮ")
	t.Logf("отказ по второй популяции: %v", verr)

	require.Equal(t, before, moduleCatalogSnapshot(t, ctx, pool, anchoredModule),
		"отказ по потолку оставил след: сверка обязана ронять транзакцию ДО коммита")
	require.Zero(t, orphanRowsOf(t, ctx, pool, tn.accountID),
		"отказ по потолку переселил проекции: право отобрано применением, которое отвергнуто")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же вход с потолками, покрывающими факт,
	// ПРОХОДИТ. Без него оба отрицания зеленели бы на глаголе, отвергающем всё.
	rep, oerr := applier.Apply(ctx, modulecatalog.Request{
		Manifest:              shippedManifest(t, anchoredModule, spareResource),
		ExpectedState:         state,
		MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
		MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
	})
	t.Logf("перепись применения в пределах потолков: %s", rep)
	require.NoError(t, oerr, "применение в пределах потолков отвергнуто")
	require.Positive(t, rep.Resettled.RuleRefs+rep.Resettled.RoleVerbs,
		"переселения не было: оба отрицания выше утверждали о числе, которого не бывает: %s", rep)
}

// moduleCatalogSnapshotWide — наблюдение пробы: шеститабличный отпечаток.
//
// Обёртка над `stateFingerprint` заведена ради ЧИТАЕМОСТИ контроля
// невакуумности: он утверждает «движение произошло», и имя обязано это говорить.
func moduleCatalogSnapshotWide(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	return stateFingerprint(t, ctx, pool)
}
