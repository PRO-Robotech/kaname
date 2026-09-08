// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_plan_state_integration_test.go — ПЛАН СЧИТАЕТ ТО, ЧТО СДЕЛАЕТ
// ПРИМЕНЕНИЕ, И НЕ ПИШЕТ НИЧЕГО.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 5), §2.5 (отпечаток), §2.6 (третья популяция), §2.11 (что
// производит `Plan`). Задача продукта #1034, объём О6 + О8.
//
// # Что здесь утверждается — четыре предмета, и порознь каждый вакуумен
//
//	(1) план НЕ ПИШЕТ: отпечаток и четыре счётчика строк не двигаются
//	(2) отпечаток — ТОТ ЖЕ, каким его читает CAS применителя
//	(3) оценки последствий НЕНУЛЕВЫ на фикстуре, где снимать есть что
//	(4) применение делает РОВНО столько, сколько показал план — по каждой из
//	    ТРЁХ популяций отдельно, а не по сумме
//
// Порознь они выполнимы производителем, который лжёт: (1) зелено у того, кто не
// считает ничего; (3) — у того, кто отдаёт константу; (4) — у того, кто отдаёт
// нули, если и применение ничего не сделало. Поэтому они стоят вместе и в этом
// порядке, а (3) отделён от (4) отрицательным контролем ниже: на модуле, у
// которого снимать нечего, ТОТ ЖЕ производитель обязан отдать нули.
//
// # Отпечаток читается ТЕМ ЖЕ выражением, каким его сверяет CAS
//
// `moduleStateOf` зовёт `kanamepg.ModuleStateExpr` — то самое выражение, а не
// выписанную копию. Копия разошлась бы с прод-выражением МОЛЧА: на несдвинутом
// каталоге обе отвечают «совпало», и расхождение стало бы видно ровно там, где
// его уже нечем заметить.
//
// # Чего здесь НЕТ
//
// О транспорте, конверте операции и правах вызывающего — ничего: и план, и
// применение зовутся тем же путём, каким их исполнит RPC.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// consequenceRows — счётчики ЧЕТЫРЁХ таблиц, которых план не вправе тронуть.
//
// Четыре, а не одна: три популяции последствий живут в трёх разных таблицах, а
// четвёртая — сироты — есть то, КУДА переселение пишет. Считай мы одну, план,
// пишущий в остальные три, был бы неотличим от читающего.
type consequenceRows struct {
	RuleRefs  int
	RoleVerbs int
	Selectors int
	Orphans   int
}

// consequenceRowsOf — перепись четырёх таблиц последствий ОДНИМ оператором, то
// есть одним снимком: собранная из четырёх моментов, она показала бы состояние,
// которого не было ни в один из них.
func consequenceRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool) consequenceRows {
	t.Helper()
	var out consequenceRows
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kaname.role_rule_ref),
		       (SELECT count(*) FROM kaname.role_verb),
		       (SELECT count(*) FROM kaname.role_rule_selectors),
		       (SELECT count(*) FROM kaname.role_grant_orphan)`).
		Scan(&out.RuleRefs, &out.RoleVerbs, &out.Selectors, &out.Orphans))
	return out
}

// liveRowsOfModule — живые строки ОДНОГО модуля.
//
// Отбор снимаемого судит модуль, а не каталог целиком: подай ему все модули, и
// строки соседних приехали бы снимаемыми — то есть оценка была бы о применении,
// которого никто не заказывал.
func liveRowsOfModule(live catalog.Rows, module string) catalog.Rows {
	out := catalog.Rows{}
	for _, m := range live.Modules {
		if m == module {
			out.Modules = append(out.Modules, m)
		}
	}
	for _, r := range live.Resources {
		if r.Module == module {
			out.Resources = append(out.Resources, r)
		}
	}
	for _, v := range live.Verbs {
		if v.Module == module {
			out.Verbs = append(out.Verbs, v)
		}
	}
	return out
}

// TestPlanStateCountsWhatApplyWithdrawsAndWritesNothing — четыре предмета шапки.
func TestPlanStateCountsWhatApplyWithdrawsAndWritesNothing(t *testing.T) {
	ctx, pool := catalogPool(t)
	ctx = verbCallerCtx(ctx)
	catRepo := kanamepg.NewCatalogRepo(pool)
	repo := kanamepg.New(pool, nil)
	applier := verbApplierOver(t, pool)
	planner := kanamepg.NewCatalogPlanRepo(pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	// АРЕНДАТОРСКАЯ роль, чьё правило называет снимаемый ресурс: системную сюда
	// брать нельзя — её проекции применитель не переселяет намеренно, и снятие
	// отвергнул бы КЛЮЧ.
	tn := seedVerdictTenant(t, ctx, pool)
	_, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, anchoredModule, spareResource)
	require.NotEmptyf(t, pairs,
		"проекция по %s.%s пуста ещё до плана: оценивать нечего, и перепись была бы вакуумной",
		anchoredModule, spareResource)

	m := shippedManifest(t, anchoredModule, spareResource)
	declared, derr := modulecatalog.RowsOf(m)
	require.NoError(t, derr, "вывести строки каталога из манифеста")
	live, lerr := catRepo.ReadLiveCatalog(ctx)
	require.NoError(t, lerr, "прочитать живой каталог")
	staleRes, staleVerbs := modulecatalog.Withdrawn(liveRowsOfModule(live, anchoredModule), declared)
	require.NotEmptyf(t, staleRes,
		"манифест не снимает ни одного ресурса модуля %s: оценка последствий беспредметна",
		anchoredModule)

	before := consequenceRowsOf(t, ctx, pool)
	fpBefore := moduleStateOf(t, ctx, pool, anchoredModule)
	t.Logf("до плана: отпечаток %s, правил %d, выдач %d, селекторов %d, сирот %d",
		shortHash(fpBefore), before.RuleRefs, before.RoleVerbs, before.Selectors, before.Orphans)

	ps, perr := planner.PlanState(ctx, anchoredModule, staleRes, staleVerbs)
	require.NoError(t, perr, "плановая сторона не прочитана")

	// (1) ПЛАН НЕ ПИШЕТ — ни строки, ни при каком входе.
	require.Equal(t, fpBefore, moduleStateOf(t, ctx, pool, anchoredModule),
		"план сдвинул отпечаток состояния: оценка сделана записью, а не чтением")
	require.Equal(t, before, consequenceRowsOf(t, ctx, pool),
		"план тронул строки последствий: оценка сделана сухим прогоном записи, а не счётом")

	// (2) Отпечаток — ТОТ ЖЕ, каким его сверяет CAS.
	require.Equal(t, fpBefore, ps.ExpectedState,
		"план вернул отпечаток, отличный от читаемого `ModuleStateExpr`: подтверждение "+
			"не сойдётся ни при каком состоянии, и `Apply` недостижим")

	// (3) Оценки НЕНУЛЕВЫ: иначе (4) зеленело бы на нулях с обеих сторон.
	require.Positive(t, ps.Resettled.RuleRefs,
		"план не насчитал переселения объявлений правила: первая популяция не оценена")
	require.Positive(t, ps.Resettled.RoleVerbs,
		"план не насчитал переселения выдач: вторая популяция не оценена")
	require.Positive(t, ps.Pruned.Rows+ps.Pruned.Dropped,
		"план не насчитал приведения третьей проекции: у неё нет ни потолка, ни ведомости, "+
			"и числа плана — единственное, что оператор узнаёт заранее")
	require.Positive(t, ps.Pruned.Elements,
		"план не насчитал вырезаемых элементов массива типов")
	t.Logf("план: переселит правил %d, выдач %d; селекторов укоротит %d снимет %d "+
		"элементов вырежет %d; отпечаток %s",
		ps.Resettled.RuleRefs, ps.Resettled.RoleVerbs,
		ps.Pruned.Rows, ps.Pruned.Dropped, ps.Pruned.Elements, shortHash(ps.ExpectedState))

	// (4) ПРИМЕНЕНИЕ ДЕЛАЕТ РОВНО СТОЛЬКО — сквозь: план → подтверждение →
	// применение. Подтверждение берётся у ПЛАНА, а не читается заново: читая
	// заново, проба обошла бы ровно то звено, ради которого написана.
	rep, aerr := applier.Apply(ctx, modulecatalog.Request{
		Manifest:              shippedManifest(t, anchoredModule, spareResource),
		ExpectedState:         ps.ExpectedState,
		MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
		MaxResettledRoleVerbs: modulecatalog.Limit(generousCeiling),
	})
	require.NoError(t, aerr, "применение по подтверждению ПЛАНА отвергнуто: %s", rep)
	t.Logf("перепись применения: %s", rep)

	require.Equal(t, ps.Resettled.RuleRefs, rep.Resettled.RuleRefs,
		"план обещал переселить объявлений правила не столько, сколько применение переселило")
	require.Equal(t, ps.Resettled.RoleVerbs, rep.Resettled.RoleVerbs,
		"план обещал переселить выдач не столько, сколько применение переселило")
	require.Equal(t, ps.Pruned.Rows, rep.PrunedSelectorRows,
		"план обещал укоротить селекторов не столько, сколько применение укоротило")
	require.Equal(t, ps.Pruned.Dropped, rep.PrunedSelectorRowsDropped,
		"план обещал снять селекторов не столько, сколько применение сняло")
	require.Equal(t, ps.Pruned.Elements, rep.PrunedSelectorTypes,
		"план обещал вырезать элементов не столько, сколько применение вырезало")

	// Отпечаток ОДНОРАЗОВ by construction: применение его сдвинуло. Пара к (2):
	// без неё «отпечаток совпал» выполнялось бы у производителя, отдающего
	// константу.
	require.NotEqual(t, ps.ExpectedState, moduleStateOf(t, ctx, pool, anchoredModule),
		"применение не сдвинуло отпечаток: подтверждение не различает состояний")
}

// TestPlanStateReportsZeroWhenNothingIsWithdrawn — ОТРИЦАТЕЛЬНЫЙ контроль к (3).
//
// Тот же производитель на манифесте, ничего не снимающем, обязан отдать нули по
// всем пяти величинам. Без этой пары «ненулевые оценки» выполнялись бы у
// производителя, считающего популяцию целиком вместо её снимаемой части, — и
// проба выше зеленела бы на нём.
func TestPlanStateReportsZeroWhenNothingIsWithdrawn(t *testing.T) {
	ctx, pool := catalogPool(t)
	catRepo := kanamepg.NewCatalogRepo(pool)
	repo := kanamepg.New(pool, nil)
	planner := kanamepg.NewCatalogPlanRepo(pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "предпосылка не создана")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	// Фикстура ТА ЖЕ, что у положительной пробы: популяции непусты. Различается
	// РОВНО ОДИН факт — манифест ничего не снимает.
	tn := seedVerdictTenant(t, ctx, pool)
	_, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, anchoredModule, spareResource)
	require.NotEmpty(t, pairs, "проекция пуста: отрицание зеленело бы на пустой таблице")

	rows := consequenceRowsOf(t, ctx, pool)
	require.Positive(t, rows.RuleRefs, "таблица правил пуста: отрицание вакуумно")
	require.Positive(t, rows.Selectors, "таблица селекторов пуста: отрицание вакуумно")

	m := shippedManifest(t, anchoredModule, "")
	declared, derr := modulecatalog.RowsOf(m)
	require.NoError(t, derr, "вывести строки каталога из манифеста")
	live, lerr := catRepo.ReadLiveCatalog(ctx)
	require.NoError(t, lerr, "прочитать живой каталог")
	staleRes, staleVerbs := modulecatalog.Withdrawn(liveRowsOfModule(live, anchoredModule), declared)
	require.Empty(t, staleRes, "манифест как доставлен снимает ресурс: предпосылка отрицания неверна")
	require.Empty(t, staleVerbs, "манифест как доставлен снимает действие: предпосылка отрицания неверна")

	ps, perr := planner.PlanState(ctx, anchoredModule, staleRes, staleVerbs)
	require.NoError(t, perr, "плановая сторона не прочитана")

	require.Zero(t, ps.Resettled.RuleRefs, "снимать нечего, а переселение насчитано")
	require.Zero(t, ps.Resettled.RoleVerbs, "снимать нечего, а переселение насчитано")
	require.Zero(t, ps.Pruned.Rows, "снимать нечего, а укорачивание насчитано")
	require.Zero(t, ps.Pruned.Dropped, "снимать нечего, а снятие селекторов насчитано")
	require.Zero(t, ps.Pruned.Elements, "снимать нечего, а вырезание элементов насчитано")
	require.NotEmpty(t, ps.ExpectedState,
		"отпечаток пуст при пустом снятии: подтверждать было бы нечем, и `Apply` недостижим")
	t.Logf("отрицание: снимаемых строк 0 ⇒ все пять оценок нули, отпечаток %s "+
		"(правил в таблице %d, селекторов %d)",
		shortHash(ps.ExpectedState), rows.RuleRefs, rows.Selectors)
}
