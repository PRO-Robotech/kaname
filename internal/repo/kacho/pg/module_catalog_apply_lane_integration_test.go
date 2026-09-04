// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_catalog_apply_lane_integration_test.go — ПОЛОС ПРИМЕНЕНИЯ ДВЕ, и
// обязанности у них РАЗНЫЕ.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.4; задача продукта #1034.
//
// # Что здесь утверждается — и почему ОБЕ стороны, а не одна
//
//	путь ГЛАГОЛА   состояние вне опоры ⇒ применение ОТВЕРГНУТО внутри транзакции
//	путь СТАРТА    ТОТ ЖЕ вход ⇒ применение ПРОХОДИТ, а вред ловит СТРАЖ следом
//
// Утверждать одну сторону нельзя. «Глагол отвергает» зеленело бы на применителе,
// отвергающем всё; «старт проходит» — на применителе, не проверяющем ничего.
// Вместе они утверждают РАЗЛИЧИЕ полос, а различие и есть предмет.
//
// # Почему у старта эта обязанность ОТСУТСТВУЕТ, а не «снята»
//
// На пути старта сверка стоит СРАЗУ ПОСЛЕ применения (`serve.go`), и её отказ
// есть отказ пуска: вред пойман тем самым механизмом, ради которого §2.4
// написана, и пойман ДО приёма запросов. Проба это и утверждает — вторая
// половина не просто «прошло», а «прошло, и страж следом отказал». Без второго
// утверждения половина читалась бы как дыра.
//
// У глагола второго рубежа нет: он работает в обслуживающем процессе, отказ не
// приходит никому, а вред приезжает в другой процесс и другому человеку — на
// следующем перезапуске.
//
// # Почему вход у обеих половин ОДИН
//
// Разные входы дали бы разные исходы и на применителе, полос не различающем:
// «отвергнуто» объяснялось бы входом, а не полосой. Один вход делает полосу
// ЕДИНСТВЕННЫМ различием между половинами.
//
// # Чего здесь НЕТ
//
// О транспорте, правах и подтверждении — ничего: обе полосы подаются вызовом
// применителя, тем же путём, каким их исполняют композиционный корень и (в свой
// срез) RPC.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// beyondAnchorManifest — доставленный манифест `vpc`, объявляющий ОДНУ строку,
// которой опора не знает.
//
// Тот же вход, что у `-11`, и собран он тем же помощником: половины полос
// обязаны отличаться ТОЛЬКО полосой.
func beyondAnchorManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m := shippedManifest(t, anchoredModule, "")
	m.Resources = append(m.Resources, manifest.Resource{
		Name:       beyondAnchorResource,
		ObjectType: beyondAnchorObjectType,
		Verbs:      []manifest.Verb{{Name: "get"}},
	})
	return m
}

// TestApplyLaneDecidesWhoChecksTheAnchor — полоса решает, КТО сверяет опору.
func TestApplyLaneDecidesWhoChecksTheAnchor(t *testing.T) {
	t.Run("глагол сверяет сам", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		// Путь ГЛАГОЛА идёт под проверенной личностью: без неё он отказывает
		// раньше сверки опоры (§2.7), и проба читала бы чужой отказ как свойство
		// полосы.
		ctx = verbCallerCtx(ctx)

		census, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
		logParityCensus(t, "предпосылка", census)
		before := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)

		rep, aerr := verbApplierOver(t, pool).Apply(ctx, verbRequest(t, ctx, pool, beyondAnchorManifest(t)))
		t.Logf("перепись применения (глагол): %s", rep)
		require.Error(t, aerr,
			"глагол вывел каталог за опору и не заметил: у этой полосы второго рубежа нет, "+
				"отказ не приходит никому, а следующий пуск отказан")
		require.Equal(t, before, moduleCatalogSnapshot(t, ctx, pool, anchoredModule),
			"отказ глагола оставил след: сверка обязана ронять транзакцию ДО коммита")

		after, perr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		logParityCensus(t, "после отказа глагола", after)
		require.NoError(t, perr, "после отказа каталог обязан оставаться сошедшимся с опорой")
	})

	t.Run("старт оставляет опору стражу", func(t *testing.T) {
		ctx, pool := catalogPool(t)

		census, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
		logParityCensus(t, "предпосылка", census)

		// ТОТ ЖЕ вход, что и у половины выше. Отличается только полоса.
		rep, aerr := applierOver(t, pool).Apply(ctx, beyondAnchorManifest(t))
		t.Logf("перепись применения (старт): %s", rep)
		require.NoError(t, aerr,
			"путь старта отверг применение сам: это обязанность ГЛАГОЛА, а на старте "+
				"она означала бы правило строже стража и меняла бы поведение подъёма")
		require.Positive(t, rep.WrittenResources, "применение ничего не записало: половина беспредметна")

		// ВТОРОЙ РУБЕЖ — он и есть причина, по которой первой половине здесь не
		// место. Без этого утверждения «старт проходит» читалось бы как дыра.
		guard, gerr := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		logParityCensus(t, "страж после применения на старте", guard)
		require.Error(t, gerr,
			"страж пропустил строку вне опоры: тогда у пути старта нет ВТОРОГО рубежа, "+
				"и обязанность сверки обязана переехать в применитель")
		require.Truef(t, namesRow(guard.ExtraRows, "ресурс "+anchoredModule+"."+beyondAnchorResource),
			"страж отказал, но лишнюю строку поимённо не назвал: %v", guard.ExtraRows)
	})
}
