// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// verb_liveness_key_integration_test.go — УРОВЕНЬ ГЛАГОЛОВ: живость ресурса
// держит КЛЮЧ, а не рассуждение о потребителях.
//
// Задача продукта #1878, решение — #1868, записано в
// `services/iam/docs/engineering/architecture/catalog-liveness-key-per-level.md`.
// Приёмка `module-withdrawal-is-described.md` §2.2 и §9.2.
//
// # Что здесь утверждается
//
// Что состояние «ресурс снят, его глаголы живы» ПЕРЕСТАЛО быть представимым, и
// перестало by construction — ключом `catalog_verb_resource_live_fk`, а не тем,
// что до такой строки «дело не доходит». Прежний довод был верен и оставался
// верным ровно пока верен его перечень потребителей: правило отвергается ключом
// РЕСУРСА раньше, чем дело дойдёт до глагола. Перечень потребителей меняется, и
// меняется молча, — это ban #10 буквально.
//
// # Порядок держится в ОБЕ стороны, и обе половины стоят здесь
//
//	вниз   снять ресурс, пока жив хоть один его глагол   → 23503
//	вниз   снять ресурс, все глаголы которого сняты      → проходит
//	вверх  оживить глагол при снятом ресурсе             → 23503
//	вверх  оживить ресурс, затем его глаголы             → проходит
//
// Половина «вниз, проходит» — не украшение: без неё отрицание не отличает «ключ
// работает» от «ресурс нельзя снять НИКОГДА», а именно этим исходом зеленела бы
// форма ключа с константной колонкой `true` (разбор — уровнем выше,
// `20260902065414`, и близнец IAM-MW-1-08).
//
// # Ресурс сценария ВЫВОДИТСЯ, а не выписан
//
// Литерал связал бы пробу с посевом: посев растёт (27 → 28 ресурсов за две
// задачи), и выписанное имя устарело бы молча — либо, хуже, указало бы на
// ресурс, у которого появились выдачи, и тогда снятие отвергалось бы ЧУЖИМ
// ключом, а проба зеленела бы, не проверив своего.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// retireVerbsOf — снятие ВСЕХ живых глаголов ресурса одним оператором.
//
// `retired_at` и `live` одним оператором — то же требование Т3, что у
// `retireResource`: согласие двух колонок держит проверка `catalog_verb_live_
// matches_retired`, а не писатель.
func retireVerbsOf(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, module, resource, reason string) error {
	_, err := q.Exec(ctx, `
		UPDATE kacho_iam.catalog_verb
		   SET retired_at = now(), live = false, retired_reason = $3
		 WHERE module = $1 AND resource = $2 AND live`, module, resource, reason)
	return err
}

// retireResourceRowOnly — снятие ТОЛЬКО строки ресурса, без его глаголов.
//
// Отдельный от `retireResource` оператор нужен именно потому, что тот теперь
// снимает глаголы первым: подать вход «ресурс снимают, глаголы живы» через
// административный путь стало нельзя, а сценарий обязан подать ровно его. Это не
// обход дисциплины, а её предмет — проба утверждает, что такой вход ОТВЕРГАЕТСЯ.
func retireResourceRowOnly(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, module, resource, reason string) error {
	_, err := q.Exec(ctx, `
		UPDATE kacho_iam.catalog_resource
		   SET retired_at = now(), live = false, retired_reason = $3
		 WHERE module = $1 AND resource = $2`, module, resource, reason)
	return err
}

// freeLiveResource — живой ресурс, у которого есть живые глаголы и НЕТ ни одной
// строки выдачи или объявления.
//
// Предпосылка проверяется запросом, а не предполагается: обратное заполнение
// миграций кладёт строки проекции за каждую системную роль, поэтому у
// большинства типов каталога ссылки есть уже на чистой базе. Сценарий, взявший
// занятый ресурс, отвергался бы ключом `role_verb_type_fk` либо
// `role_rule_ref_res_fk` — то есть зеленел бы, не проверив своего ключа.
func freeLiveResource(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (module, resource string) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT cr.module, cr.resource
		  FROM kacho_iam.catalog_resource cr
		 WHERE cr.live
		   AND EXISTS (SELECT 1 FROM kacho_iam.catalog_verb cv
		                WHERE cv.module = cr.module AND cv.resource = cr.resource AND cv.live)
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.role_rule_ref rr
		                    WHERE rr.module = cr.module AND rr.resource = cr.resource)
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.role_verb rv
		                    WHERE rv.object_type = cr.dotted)
		 ORDER BY cr.dotted
		 LIMIT 1`).Scan(&module, &resource)
	require.NoError(t, err,
		"свободного живого ресурса с живыми глаголами не нашлось — сценарий вакуумен, "+
			"а не пройден: снятие отвергалось бы чужим ключом")
	return module, resource
}

// liveVerbsOf — сколько живых глаголов у ресурса. Печатается каждым сценарием:
// «отказ получен» при нуле живых глаголов не утверждало бы ничего.
func liveVerbsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_verb
		 WHERE module = $1 AND resource = $2 AND live`, module, resource).Scan(&n))
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// ВЫПОЛНИМОСТЬ КЛЮЧА — измеряется, а не предполагается.
//
// `ADD CONSTRAINT … FOREIGN KEY` проверяет КАЖДУЮ существующую строку. Если под
// снятым ресурсом живёт хоть один глагол, миграция не применится вовсе, и
// прогон упрётся в неё, а не в сценарий. Проба остаётся и после применения: она
// утверждает то же самое СВОЙСТВО каталога, которое держит ключ, и на дереве,
// куда завезли бы такую пару посевом, покраснела бы раньше миграции.

func TestVerbsUnderARetiredResourceAreAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	var retiredRes, verbRows, contradicted int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_resource WHERE NOT live`).Scan(&retiredRes))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_verb`).Scan(&verbRows))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*)
		  FROM kacho_iam.catalog_verb cv
		  JOIN kacho_iam.catalog_resource cr
		    ON cr.module = cv.module AND cr.resource = cv.resource
		 WHERE cv.live AND NOT cr.live`).Scan(&contradicted))

	// Перепись печатается ВСЕГДА: «строк под снятым ресурсом ноль» обязано быть
	// отличимо от «строк не читали».
	t.Logf("перепись: снятых ресурсов %d, строк каталога глаголов %d, "+
		"живых глаголов под снятым ресурсом %d", retiredRes, verbRows, contradicted)

	require.Positive(t, retiredRes,
		"снятых ресурсов ноль — тогда утверждение ниже вакуумно: пересечение пусто "+
			"потому, что пуста одна из сторон")
	require.Positive(t, verbRows, "строк каталога глаголов ноль — каталог не посеян")
	require.Zero(t, contradicted,
		"живой глагол под снятым ресурсом — ключ живости такую строку не примет, "+
			"и миграция #1878 не применится, пока строка жива")
}

// ─────────────────────────────────────────────────────────────────────────────
// ВНИЗ: снять ресурс, пока жив хоть один его глагол — отвергается КЛЮЧОМ.

func TestRetiringAResourceWithLiveVerbsIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	module, resource := freeLiveResource(t, ctx, pool)
	verbs := liveVerbsOf(t, ctx, pool, module, resource)
	require.Positivef(t, verbs,
		"предпосылка сценария: у %s.%s есть живые глаголы", module, resource)

	err := retireResourceRowOnly(ctx, pool, module, resource, "проба #1878 вниз")
	require.Errorf(t, err,
		"снятие ресурса %s.%s при %d живых глаголах обязано отвергаться КЛЮЧОМ",
		module, resource, verbs)
	code, constraint := pgCode(err)
	t.Logf("снятие ресурса %s.%s отвергнуто: SQLSTATE %s, ограничение %q (живых глаголов %d)",
		module, resource, code, constraint, verbs)
	require.Equal(t, "23503", code)
	require.Equal(t, "catalog_verb_resource_live_fk", constraint,
		"имя ограничения — часть сценария: под другим именем отвечал бы другой ключ, "+
			"и проба зеленела бы на чужом отказе")

	var live bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live FROM kacho_iam.catalog_resource WHERE module = $1 AND resource = $2`,
		module, resource).Scan(&live))
	require.True(t, live, "отвергнутое снятие оставляет строку ресурса живой")
}

// ─────────────────────────────────────────────────────────────────────────────
// ВНИЗ, ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — близнец IAM-MW-1-08 уровнем ниже.
//
// Без него отрицание выше не отличает «ключ держит порядок» от «ресурс снять
// нельзя никогда»: обе гипотезы дают один и тот же отказ.

func TestResourceWithAllVerbsRetiredIsRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	module, resource := freeLiveResource(t, ctx, pool)
	before := liveVerbsOf(t, ctx, pool, module, resource)
	require.Positive(t, before)

	require.NoError(t, retireVerbsOf(ctx, pool, module, resource, "проба #1878 контроль"),
		"снятие глаголов ресурса ключом не запрещено")
	require.Zero(t, liveVerbsOf(t, ctx, pool, module, resource))

	require.NoError(t,
		retireResourceRowOnly(ctx, pool, module, resource, "проба #1878 контроль"),
		"ресурс, ВСЕ глаголы которого сняты, ОБЯЗАН сниматься")

	var live bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live FROM kacho_iam.catalog_resource WHERE module = $1 AND resource = $2`,
		module, resource).Scan(&live))
	require.False(t, live)

	// Соседний ресурс не задет: ключ судит СВОЙ ресурс, а не каталог целиком.
	var neighbours int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_resource
		 WHERE live AND NOT (module = $1 AND resource = $2)`, module, resource).Scan(&neighbours))
	t.Logf("снят %s.%s (глаголов было %d); живых соседних ресурсов %d",
		module, resource, before, neighbours)
	require.Positive(t, neighbours, "снятие одного ресурса не снимает остальные")
}

// ─────────────────────────────────────────────────────────────────────────────
// ВВЕРХ: оживить глагол при снятом ресурсе — отвергается; «ресурс, затем
// глаголы» — проходит.
//
// Половина «вверх» — не побочный эффект: без неё повторная установка модуля
// упиралась бы в отказ, и причину искали бы в форме оживления строки, а не в
// порядке.

func TestRevivingAVerbUnderARetiredResourceIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	module, resource := freeLiveResource(t, ctx, pool)
	require.NoError(t, retireVerbsOf(ctx, pool, module, resource, "проба #1878 вверх"))
	require.NoError(t, retireResourceRowOnly(ctx, pool, module, resource, "проба #1878 вверх"))

	var verb string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT verb FROM kacho_iam.catalog_verb
		 WHERE module = $1 AND resource = $2 ORDER BY verb LIMIT 1`,
		module, resource).Scan(&verb))

	reviveVerb := `
		UPDATE kacho_iam.catalog_verb
		   SET live = true, retired_at = NULL, retired_reason = NULL
		 WHERE module = $1 AND resource = $2 AND verb = $3`

	_, err := pool.Exec(ctx, reviveVerb, module, resource, verb)
	require.Error(t, err,
		"оживление глагола при снятом ресурсе обязано отвергаться: установка идёт "+
			"«ресурс → глаголы», а не наоборот")
	code, constraint := pgCode(err)
	t.Logf("оживление глагола %s.%s.%s отвергнуто: SQLSTATE %s, ограничение %q",
		module, resource, verb, code, constraint)
	require.Equal(t, "23503", code)
	require.Equal(t, "catalog_verb_resource_live_fk", constraint)

	// Законный близнец: сперва ресурс, затем глагол — проходит. Без него
	// отрицание выше зеленело бы на схеме, где оживления не бывает вовсе.
	_, err = pool.Exec(ctx, `
		UPDATE kacho_iam.catalog_resource
		   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
		 WHERE module = $1 AND resource = $2`, module, resource)
	require.NoError(t, err, "оживление ресурса")
	_, err = pool.Exec(ctx, reviveVerb, module, resource, verb)
	require.NoError(t, err, "после оживления ресурса глагол оживает")
}

// ─────────────────────────────────────────────────────────────────────────────
// ЧАСТИЧНОЕ СОВПАДЕНИЕ: `MATCH SIMPLE` пропускает проверку ЦЕЛИКОМ — и это
// намеренно, но существование при этом держит ВТОРОЙ ключ.
//
// Составляющая `resource_live` у снятой строки пуста, и `MATCH SIMPLE` считает
// ключ с пустой составляющей выполненным — то есть у снятой строки глагола ключ
// живости не проверяется ВООБЩЕ, а не проверяется «частично». Ровно на этом
// стоит снимаемость ресурса, и ровно здесь заводится вопрос: не открывает ли
// пустая составляющая дорогу строке, ссылающейся в никуда.
//
// Не открывает, и держит это НЕ новый ключ, а прежний —
// `catalog_verb_resource_fk (module, resource)` на первичный ключ ресурса.
// Поэтому прежний ключ и НЕ снимается: он отвечает за СУЩЕСТВОВАНИЕ, новый — за
// ЖИВОСТЬ. Проба утверждает оба ответа поимённо, иначе «строка отвергнута»
// неотличимо от «отвергнута тем ключом, о котором мы думали».

func TestVerbLivenessKeyIsVacuousOnlyForRetiredRowsAndExistenceStaysHeld(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	module, resource := freeLiveResource(t, ctx, pool)

	// Рассуждение «у живой строки ключ проверяется всегда» стоит на том, что
	// пустой у неё не бывает НИ ОДНА составляющая: живость у живой строки —
	// `true` by construction (генерируемая колонка), а `module` и `resource`
	// объявлены `NOT NULL`. Второе здесь ПРОВЕРЯЕТСЯ, а не читается: сними
	// кто-нибудь `NOT NULL`, и `MATCH SIMPLE` начал бы пропускать живые строки
	// целиком, не сказав об этом ничем.
	t.Run("составляющие ключа, кроме живости, пусты не бывают", func(t *testing.T) {
		for _, col := range []string{"module", "resource"} {
			var notNull bool
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT attnotnull FROM pg_attribute
				 WHERE attrelid = 'kacho_iam.catalog_verb'::regclass AND attname = $1`,
				col).Scan(&notNull))
			require.Truef(t, notNull,
				"колонка %s обязана быть NOT NULL: пустая составляющая снимает проверку "+
					"ключа живости ЦЕЛИКОМ (MATCH SIMPLE), и живая строка прошла бы под "+
					"снятым ресурсом", col)
		}
		var generated string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT attgenerated::text FROM pg_attribute
			 WHERE attrelid = 'kacho_iam.catalog_verb'::regclass AND attname = 'resource_live'`).
			Scan(&generated))
		require.Equal(t, "s", generated,
			"resource_live обязана быть ГЕНЕРИРУЕМОЙ: значение, которое пишет писатель, "+
				"разошлось бы с живостью строки молча")
	})

	t.Run("снятый глагол под снятым ресурсом ПРЕДСТАВИМ", func(t *testing.T) {
		require.NoError(t, retireVerbsOf(ctx, pool, module, resource, "частичное совпадение"))
		require.NoError(t, retireResourceRowOnly(ctx, pool, module, resource, "частичное совпадение"))

		var retiredVerbs int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kacho_iam.catalog_verb
			 WHERE module = $1 AND resource = $2 AND NOT live`, module, resource).Scan(&retiredVerbs))
		t.Logf("снятых глаголов под снятым %s.%s: %d — ключ живости их не судит "+
			"(составляющая пуста, MATCH SIMPLE)", module, resource, retiredVerbs)
		require.Positive(t, retiredVerbs)
	})

	t.Run("СУЩЕСТВОВАНИЕ держит прежний ключ — и у живой строки, и у снятой", func(t *testing.T) {
		const ghost = "нетакогомодуля"

		// Живая строка: обе составляющие непусты, отвечает ключ существования.
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object)
			VALUES ($1, 'ghost', 'get', true)`, ghost)
		require.Error(t, err, "живой глагол несуществующего ресурса обязан отвергаться")
		code, constraint := pgCode(err)
		t.Logf("живой глагол-призрак отвергнут: SQLSTATE %s, ограничение %q", code, constraint)
		require.Equal(t, "23503", code)
		require.Equal(t, "catalog_verb_resource_fk", constraint,
			"существование судит ПРЕЖНИЙ ключ — именно поэтому он не снимается "+
				"вместе с заведением ключа живости")

		// Снятая строка: составляющая живости пуста, ключ живости молчит
		// by construction — и если бы существование не держал второй ключ,
		// строка в никуда прошла бы. Проба утверждает, что не проходит.
		_, err = pool.Exec(ctx, `
			INSERT INTO kacho_iam.catalog_verb
			  (module, resource, verb, per_object, live, retired_at, retired_reason)
			VALUES ($1, 'ghost', 'get', true, false, now(), 'частичное совпадение')`, ghost)
		require.Error(t, err,
			"СНЯТЫЙ глагол несуществующего ресурса обязан отвергаться: ключ живости на "+
				"нём вакуумен, и если бы существование не держал второй ключ, пустая "+
				"составляющая пропустила бы строку в никуда")
		code, constraint = pgCode(err)
		t.Logf("снятый глагол-призрак отвергнут: SQLSTATE %s, ограничение %q", code, constraint)
		require.Equal(t, "23503", code)
		require.Equal(t, "catalog_verb_resource_fk", constraint)
	})
}
