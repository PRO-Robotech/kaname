// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_catalog_apply_consequence_populations_integration_test.go — СКОЛЬКО
// ПОПУЛЯЦИЙ ПОСЛЕДСТВИЙ двигает ОДНО применение.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.6; сценарии `IAM-MA-1-19`, `-20` — их предпосылка.
// Задача продукта #1034.
//
// # Зачем эта проба, если потолков ещё нет
//
// §2.6 объявляет ПАРУ потолков — «по одному на популяцию», — и довод её таков:
// `ResettleTenantProjections` отдаёт `Resettled{RuleRefs, RoleVerbs}`, а один
// потолок на сумму позволил бы обменять одно последствие на другое молча.
//
// Довод верен, а число — нет: популяций у одного применения ТРИ. Третью двигает
// `PruneRetiredSelectorTypes` (`apply.go`, шаг 7), она отдаёт
// `Pruned{Rows, Dropped, Elements}`, и для арендатора она столь же необратима:
// строка селектора, у которой не осталось ни одного живого типа, СНИМАЕТСЯ
// целиком. Пара потолков её не покрывает, то есть последствие, ради ограничения
// которого потолки и заведены, проходит мимо них.
//
// Проба это ИЗМЕРЯЕТ, а не утверждает прозой: она заводит арендаторскую роль,
// чьё правило называет снимаемый ресурс, применяет сужающий манифест и читает
// перепись применителя по каждой популяции отдельно.
//
// # Что здесь ЗЕЛЕНО, и почему это не «ничего не проверяет»
//
// Проба зелена и до работы, и после — она характеризующая. Её предмет —
// ПРЕДПОСЫЛКА сценариев `-19`/`-20`: сколько потолков обязан принимать глагол.
// Предпосылка, взятая из прозы, разошлась бы с деревом молча; взятая прогоном —
// нет.
//
// # Чего здесь НЕТ
//
// Самих потолков: у них нет входной поверхности — `Apply` их не принимает, и
// подать их нечем. Сценарии `-19` (превышение отвергается по каждой популяции) и
// `-20` (отсутствие отличимо от нуля) этой пробой НЕ покрыты и покрыты быть не
// могут, пока поверхности нет.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestApplyMovesThreePopulationsOfConsequenceNotTwo — одно применение двигает ТРИ
// популяции последствий, и каждая считается отдельно.
//
// Отрицательный контроль стоит здесь же: до применения ни одна популяция не
// двинута, поэтому «три ненулевых» не может быть свойством фикстуры.
func TestApplyMovesThreePopulationsOfConsequenceNotTwo(t *testing.T) {
	ctx, pool := catalogPool(t)
	catRepo := kachopg.NewCatalogRepo(pool)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo)
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	// АРЕНДАТОРСКАЯ роль (`is_system` ложно by construction: якоря кластера у неё
	// нет), чьё правило называет снимаемый ресурс. Системную роль сюда брать
	// нельзя: её проекции применитель не переселяет намеренно, и снятие отвергнул
	// бы КЛЮЧ — проба читала бы чужой отказ как перепись последствий.
	tn := seedVerdictTenant(t, ctx, pool)
	// Роль заводится ТЕМ ЖЕ путём, что у арендатора (use-case создания, #1999);
	// id чеканит он, а этой пробе он не нужен — её предмет перепись последствий.
	_, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, anchoredModule, spareResource)
	require.NotEmptyf(t, pairs,
		"проекция по %s.%s пуста ещё до применения: двигать нечего, и перепись была бы вакуумной",
		anchoredModule, spareResource)

	rules, verbs, selectors := tenantProjectionsNaming(t, ctx, pool, anchoredModule, spareResource)
	t.Logf("перепись фикстуры ДО: правил %d, выдач %d, селекторов %d, пар проекции %d",
		rules, verbs, selectors, len(pairs))
	require.Positive(t, rules, "правило роли не записано: первая популяция беспредметна")
	require.Positive(t, verbs, "проекция глаголов не записана: вторая популяция беспредметна")
	require.Positive(t, selectors, "селектор правила не записан: ТРЕТЬЯ популяция беспредметна")
	require.Zero(t, orphanRowsOf(t, ctx, pool, tn.accountID),
		"сироты появились до применения: отрицательный контроль нарушен")

	rep, err := applier.Apply(ctx, shippedManifest(t, anchoredModule, spareResource))
	require.NoError(t, err, "сужающее применение отвергнуто: %s", rep)
	t.Logf("перепись применения: %s", rep)

	// ПЕРВАЯ и ВТОРАЯ популяции — те, что называет §2.6.
	require.Positive(t, rep.Resettled.RuleRefs, "объявления правила не переселены: %s", rep)
	require.Positive(t, rep.Resettled.RoleVerbs, "выдачи не переселены: %s", rep)

	// ТРЕТЬЯ популяция — та, которой пара потолков не покрывает.
	thirdPopulation := rep.PrunedSelectorRows + rep.PrunedSelectorRowsDropped
	require.Positivef(t, thirdPopulation,
		"третья проекция правила не тронута: либо применитель её не приводит, либо фикстура "+
			"её не задела — в обоих случаях предпосылка §2.6 не измерена")
	require.Positive(t, rep.PrunedSelectorTypes, "элементы массива типов не вырезаны: %s", rep)

	t.Logf("популяций последствий у ОДНОГО применения: 3 — "+
		"переселено правил %d, выдач %d; селекторов укорочено %d снято %d элементов вырезано %d. "+
		"Пара потолков §2.6 покрывает ДВЕ из трёх",
		rep.Resettled.RuleRefs, rep.Resettled.RoleVerbs,
		rep.PrunedSelectorRows, rep.PrunedSelectorRowsDropped, rep.PrunedSelectorTypes)

	// Последствие ЗАПИСАНО, а не отобрано молча: переселённое лежит в сиротах.
	require.Positive(t, orphanRowsOf(t, ctx, pool, tn.accountID),
		"переселённое не записано в сироты — право отобрано молча")

	// Третья популяция необратима для арендатора наравне с первыми двумя: строка
	// селектора, оставшаяся без живых типов, снята целиком.
	after := tenantSelectorRowsOf(t, ctx, pool, tn.accountID)
	t.Logf("селекторов правил арендатора после применения: %d (было %d)", after, selectors)
	require.Less(t, after, selectors,
		"строка селектора без единого живого типа пережила применение: "+
			"третья популяция не двинулась, и измерять было нечего")
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники набора

// tenantProjectionsNaming — сколько проекций АРЕНДАТОРСКИХ ролей называют строку.
//
// Зеркало `systemProjectionsNaming` соседнего файла, и различие несущее:
// системные применитель не переселяет намеренно, арендаторские переселяет. Один
// помощник на оба вопроса скрыл бы ровно это различие.
func tenantProjectionsNaming(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, resource string) (rules, verbs, selectors int) {
	t.Helper()
	dotted := module + "." + resource
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kacho_iam.role_rule_ref rr
		          JOIN kacho_iam.roles ro ON ro.id = rr.role_id
		         WHERE rr.module = $1 AND rr.resource = $2 AND ro.cluster_id IS NULL),
		       (SELECT count(*) FROM kacho_iam.role_verb rv
		          JOIN kacho_iam.roles ro ON ro.id = rv.role_id
		         WHERE rv.object_type = $3 AND ro.cluster_id IS NULL),
		       (SELECT count(*) FROM kacho_iam.role_rule_selectors rs
		          JOIN kacho_iam.roles ro ON ro.id = rs.role_id
		         WHERE $3 = ANY(rs.object_types) AND ro.cluster_id IS NULL)`,
		module, resource, dotted).Scan(&rules, &verbs, &selectors))
	return rules, verbs, selectors
}

// orphanRowsOf — сколько строк переселено в сироты у ролей этого аккаунта.
func orphanRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accountID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_grant_orphan o
		  JOIN kacho_iam.roles ro ON ro.id = o.role_id
		 WHERE ro.account_id = $1`, accountID).Scan(&n))
	return n
}

// tenantSelectorRowsOf — сколько строк селекторов правил у ролей этого аккаунта.
func tenantSelectorRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accountID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_selectors rs
		  JOIN kacho_iam.roles ro ON ro.id = rs.role_id
		 WHERE ro.account_id = $1`, accountID).Scan(&n))
	return n
}
