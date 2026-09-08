// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_withdrawal_integration_test.go — ОТЗЫВ МОДУЛЯ: обратная половина
// поставки данными.
//
// Приёмка `services/iam/docs/engineering/acceptance/module-withdrawal-is-described.md`
// (APPROVED круга 2), сценарии IAM-MW-1-02(б), -06, -07(а,б), -08, -09, -14, -15,
// -16, -17. Задачи продукта #1823 (обратимость — ядро) и #1859 (ключ живости).
//
// # Что здесь утверждается
//
// Что модуль СНИМАЕТСЯ и УСТАНАВЛИВАЕТСЯ СНОВА, а порядок обоих ходов держит
// КЛЮЧ, а не память автора: «глаголы → ресурсы → модуль» вниз и «модуль →
// ресурсы → глаголы» вверх. И что круг замкнут: перепись каталога после
// «установить → отозвать → установить» совпадает с исходной ПО МНОЖЕСТВАМ, а не
// по мощностям.
//
// # Чего здесь НЕТ, и это надо сказать прямо
//
// Глагола отзыва (RPC) здесь не заводится — он предмет #1034, и второй контракт
// об одном предмете разошёлся бы с первым молча. Отзыв подаётся АДМИНИСТРАТИВНЫМ
// путём — теми же операторами, какими его будет исполнять глагол, — ровно как
// снятие ресурса подаётся `retireResource` в соседнем файле. О транспорте,
// операции и правах эти пробы не говорят НИЧЕГО.
//
// Не утверждается и то, что «модуль снят» влияет на приём правил, — но уже по
// другой причине, чем прежде: у сценария IAM-MW-1-10 появился СВОЙ производитель
// в соседнем файле (`module_membership_from_rows_integration_test.go`, задача
// #1927). Здесь его не заводится, чтобы два места не утверждали об одном
// предмете. Прежняя редакция этого абзаца говорила, что членство читается
// литералом `domain.IsKnownModule` и сценарий производит ОБРАТНОЕ; литерал снят
// вместе с функцией, и утверждение пережило бы свой предмет.
//
// # Почему перепись сравнивается МНОЖЕСТВАМИ
//
// Мощности сошлись бы и при подмене одной строки другой — а это ровно тот исход,
// который обратимость обязана исключать. Поэтому сравниваются множества, и обе
// стороны печатаются.
//
// # Числа каталога НЕ выписаны литералом — они выводятся у производителя
//
// Приёмка называет «109 живых пар глаголов»; после #1863 словарь имеет ДВЕ
// половины и живых пар 135 (#1866 — про устаревшее число в двух приёмках).
// Выписать любое из них значило бы завести второе место об одном предмете,
// которое устареет молча. Ожидаемое берётся у `authzmap.CatalogSeedVerbs()` —
// того же производителя, из которого посеяна таблица.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// withdrawnModule — модуль, на котором ставятся сценарии отзыва.
//
// Выбран НЕ произвольно: у него две строки ресурса — наименьшее число, при
// котором «часть вернулась, часть нет» (IAM-MW-1-17) вообще представимо. Один
// ресурс сделал бы сценарий -17 неконструируемым, а не строгим.
const withdrawnModule = "registry"

// catalogCensus — перепись каталога ТРЕМЯ множествами.
//
// Не тремя числами: мощности сходятся и при подмене одной строки другой, и
// именно эту подмену обратимость обязана исключать (IAM-MW-1-16).
type catalogCensus struct {
	modules   map[string]bool
	resources map[string]bool
	verbs     map[string]bool
}

func readCatalogCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) catalogCensus {
	t.Helper()
	return catalogCensus{
		modules: readSet(t, ctx, pool,
			`SELECT module FROM kaname.catalog_module WHERE live`),
		resources: readSet(t, ctx, pool,
			`SELECT dotted FROM kaname.catalog_resource WHERE live`),
		verbs: readSet(t, ctx, pool,
			`SELECT module || '.' || resource || '.' || verb FROM kaname.catalog_verb WHERE live`),
	}
}

func (c catalogCensus) log(t *testing.T, when string) {
	t.Helper()
	t.Logf("перепись каталога (%s): модулей %d, ресурсов %d, глаголов %d",
		when, len(c.modules), len(c.resources), len(c.verbs))
}

// declaredCatalogSize — ожидаемая мощность каталога, выведенная У ПРОИЗВОДИТЕЛЯ
// посева, а не выписанная числом. Число в тексте устарело бы молча (#1866);
// производитель — нет.
func declaredCatalogSize() (modules, resources, verbs int) {
	seen := map[string]bool{}
	for _, e := range authzmap.Catalog() {
		seen[e.Module+"."+e.Resource] = true
	}
	return len(authzmap.CatalogSeedModules()), len(seen), len(authzmap.CatalogSeedVerbs())
}

// moduleResources — точечные имена ресурсов модуля, живых и снятых.
func moduleResources(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string) []string {
	t.Helper()
	return keysOf(readSet(t, ctx, pool,
		`SELECT resource FROM kaname.catalog_resource WHERE module = '`+module+`'`))
}

// relocateModuleGrants — переселение выдач и объявлений ВСЕГО модуля в след
// сирот. Форма взята дословно у `relocateGrants` соседнего файла: механизм
// снятия ресурса уже построен (#1030), и второго здесь не заводится.
//
// Переселение идёт ПЕРВЫМ, до снятия строк каталога, поэтому отказ приходит на
// своём операторе и отменять немедленность ключей не требуется. Фикстура,
// открывшая `SET CONSTRAINTS … DEFERRED`, была бы снисходительнее продукта.
func relocateModuleGrants(t *testing.T, ctx context.Context, tx pgx.Tx, module, reason string) (verbs, refs int) {
	t.Helper()

	tag, err := tx.Exec(ctx, `
		INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason)
		SELECT rv.role_id, rv.object_type, rv.verb, 'role_verb', $2
		  FROM kaname.role_verb rv
		  JOIN kaname.catalog_resource cr ON cr.dotted = rv.object_type
		 WHERE cr.module = $1
		ON CONFLICT (role_id, object_type, verb, source, cause)
		DO UPDATE SET reason = EXCLUDED.reason, orphaned_at = now()`, module, reason)
	require.NoError(t, err)
	verbs = int(tag.RowsAffected())

	_, err = tx.Exec(ctx, `
		DELETE FROM kaname.role_verb rv
		 USING kaname.catalog_resource cr
		 WHERE cr.dotted = rv.object_type AND cr.module = $1`, module)
	require.NoError(t, err)

	tag, err = tx.Exec(ctx, `
		INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason)
		SELECT rr.role_id, rr.module || '.' || rr.resource, COALESCE(rr.verb, ''), 'rule_ref', $2
		  FROM kaname.role_rule_ref rr
		 WHERE rr.module = $1
		ON CONFLICT (role_id, object_type, verb, source, cause)
		DO UPDATE SET reason = EXCLUDED.reason, orphaned_at = now()`, module, reason)
	require.NoError(t, err)
	refs = int(tag.RowsAffected())

	_, err = tx.Exec(ctx,
		`DELETE FROM kaname.role_rule_ref WHERE module = $1`, module)
	require.NoError(t, err)

	return verbs, refs
}

// withdrawModule — административный отзыв модуля ОДНОЙ транзакцией.
//
// Порядок «глаголы → ресурсы → модуль» здесь выписан, но держит его не он:
// последний оператор отвергается ключом `catalog_resource_module_live_fk`, если
// хоть один ресурс остался живым (IAM-MW-1-07(а)). Выписанный порядок — форма
// глагола, ключ — гарантия.
func withdrawModule(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, reason string) (verbs, refs int) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	verbs, refs = relocateModuleGrants(t, ctx, tx, module, reason)

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_verb
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	require.NoError(t, err, "снятие глаголов модуля")

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_resource
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	require.NoError(t, err, "снятие ресурсов модуля")

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_module
		   SET live = false, retired_at = now(), retired_reason = $2
		 WHERE module = $1 AND live`, module, reason)
	require.NoError(t, err, "снятие строки модуля")

	require.NoError(t, tx.Commit(ctx))
	return verbs, refs
}

// installModule — повторная установка модуля: ОЖИВЛЕНИЕ строк, не вставка.
//
// `resources` — то, что объявляет ПОВТОРНАЯ установка. Оно может быть уже
// прежнего: модуль возвращается новой ревизией, и ресурс, которого она больше не
// называет, обязан остаться снятым. Именно на этом стоит IAM-MW-1-17.
//
// Порядок «модуль → ресурсы → глаголы» — обратный отзыву, и он тоже держится
// ключом: оживление ресурса при снятом модуле отвергается (IAM-MW-1-07(б)).
//
// Возвращает число возвращённых строк выдачи и объявления. След сирот, чей
// предмет вернулся, снимается ТЕМ ЖЕ ПРЕДИКАТОМ, каким ставился, — иначе
// `DELETE … WHERE source = 'rule_ref'` снял бы и ту строку, чей предмет уцелел.
func installModule(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module string, resources []string) (verbs, refs int) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_module
		   SET live = true, retired_at = NULL, retired_reason = NULL
		 WHERE module = $1 AND NOT live`, module)
	require.NoError(t, err, "оживление строки модуля")

	// Четыре колонки ОДНИМ оператором: согласие живости с отметкой и запрет
	// преемника у живого держат ПРОВЕРКИ, а не писатель, поэтому промежуточное
	// состояние отвергается (IAM-MW-1-15).
	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_resource
		   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
		 WHERE module = $1 AND resource = ANY($2) AND NOT live`, module, resources)
	require.NoError(t, err, "оживление ресурсов модуля")

	_, err = tx.Exec(ctx, `
		UPDATE kaname.catalog_verb
		   SET live = true, retired_at = NULL, retired_reason = NULL
		 WHERE module = $1 AND resource = ANY($2) AND NOT live`, module, resources)
	require.NoError(t, err, "оживление глаголов модуля")

	tag, err := tx.Exec(ctx, `
		INSERT INTO kaname.role_verb (role_id, object_type, verb)
		SELECT o.role_id, o.object_type, o.verb
		  FROM kaname.role_grant_orphan o
		  JOIN kaname.catalog_resource cr
		    ON cr.dotted = o.object_type AND cr.live
		 WHERE o.source = 'role_verb' AND cr.module = $1
		ON CONFLICT DO NOTHING`, module)
	require.NoError(t, err, "возврат выдачи")
	verbs = int(tag.RowsAffected())

	tag, err = tx.Exec(ctx, `
		INSERT INTO kaname.role_rule_ref (role_id, module, resource, verb)
		SELECT o.role_id, cr.module, cr.resource, NULLIF(o.verb, '')
		  FROM kaname.role_grant_orphan o
		  JOIN kaname.catalog_resource cr
		    ON cr.dotted = o.object_type AND cr.live
		 WHERE o.source = 'rule_ref' AND cr.module = $1
		   AND (o.verb = '' OR EXISTS (
		         SELECT 1 FROM kaname.catalog_verb cv
		          WHERE cv.module = cr.module AND cv.resource = cr.resource
		            AND cv.verb = o.verb AND cv.live))`, module)
	require.NoError(t, err, "возврат объявления")
	refs = int(tag.RowsAffected())

	// Снимается ровно то, что вернулось: условие снятия — то же соединение с
	// ЖИВОЙ строкой каталога, каким строка возвращалась.
	//
	// ГРАНИЦА НАЗВАНА, а не умолчана. Условие возврата ОБЪЯВЛЕНИЯ несёт лишнюю
	// половину — живость ГЛАГОЛА, — и на входе «ресурс вернулся, а его глагол
	// нет» снятие оказалось бы шире возврата: строка следа исчезла бы, не став
	// объявлением, то есть право пропало бы молча — ровно там, где след и
	// заведён. Здесь этот вход не представим by construction: повторная
	// установка оживляет глаголы ТЕХ ЖЕ ресурсов, что и сами ресурсы. Сужение
	// условия принадлежит производственному писателю (#1034), а не этой пробе:
	// подавать вход, которого сценарий не производит, значило бы утверждать о
	// коде, которого ещё нет.
	_, err = tx.Exec(ctx, `
		DELETE FROM kaname.role_grant_orphan o
		 USING kaname.catalog_resource cr
		 WHERE cr.dotted = o.object_type AND cr.live AND cr.module = $1`, module)
	require.NoError(t, err, "снятие следа, чей предмет вернулся")

	require.NoError(t, tx.Commit(ctx))
	return verbs, refs
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-07 — ключ держит порядок в ОБЕ стороны.

func TestIAMMW107_ModuleLivenessKeyHoldsBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}

	t.Run("путь вниз: снять модуль при живом ресурсе", func(t *testing.T) {
		ctx, pool := catalogPool(t)

		var liveRes int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kaname.catalog_resource WHERE module = $1 AND live`,
			withdrawnModule).Scan(&liveRes))
		require.Positivef(t, liveRes,
			"предпосылка сценария: у модуля %s есть живые ресурсы — иначе -07(а) вакуумен",
			withdrawnModule)

		_, err := pool.Exec(ctx, `
			UPDATE kaname.catalog_module
			   SET live = false, retired_at = now(), retired_reason = 'проба IAM-MW-1-07(а)'
			 WHERE module = $1`, withdrawnModule)
		require.Error(t, err,
			"снятие модуля при %d живых ресурсах обязано отвергаться КЛЮЧОМ", liveRes)
		code, constraint := pgCode(err)
		t.Logf("снятие модуля отвергнуто: SQLSTATE %s, ограничение %q (живых ресурсов %d)",
			code, constraint, liveRes)
		require.Equal(t, "23503", code)
		require.Equal(t, "catalog_resource_module_live_fk", constraint,
			"имя ограничения — часть сценария: под другим именем отвечал бы другой ключ")

		var live bool
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT live FROM kaname.catalog_module WHERE module = $1`,
			withdrawnModule).Scan(&live))
		require.True(t, live, "отвергнутое снятие оставляет строку модуля живой")
	})

	t.Run("путь вверх: оживить ресурс при снятом модуле", func(t *testing.T) {
		ctx, pool := catalogPool(t)

		withdrawModule(t, ctx, pool, withdrawnModule, "проба IAM-MW-1-07(б)")

		res := moduleResources(t, ctx, pool, withdrawnModule)
		require.NotEmpty(t, res)

		_, err := pool.Exec(ctx, `
			UPDATE kaname.catalog_resource
			   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
			 WHERE module = $1 AND resource = $2`, withdrawnModule, res[0])
		require.Error(t, err,
			"оживление ресурса при снятом модуле обязано отвергаться: установка идёт "+
				"«модуль → ресурсы», а не наоборот")
		code, constraint := pgCode(err)
		t.Logf("оживление ресурса %s.%s отвергнуто: SQLSTATE %s, ограничение %q",
			withdrawnModule, res[0], code, constraint)
		require.Equal(t, "23503", code)
		require.Equal(t, "catalog_resource_module_live_fk", constraint)

		// Законный близнец: сперва модуль, затем ресурс — проходит. Без него
		// отрицание выше зеленело бы на схеме, где оживления не бывает вовсе.
		_, err = pool.Exec(ctx, `
			UPDATE kaname.catalog_module
			   SET live = true, retired_at = NULL, retired_reason = NULL
			 WHERE module = $1`, withdrawnModule)
		require.NoError(t, err, "оживление модуля")
		_, err = pool.Exec(ctx, `
			UPDATE kaname.catalog_resource
			   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
			 WHERE module = $1 AND resource = $2`, withdrawnModule, res[0])
		require.NoError(t, err, "после оживления модуля ресурс оживает")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-08 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к -07(а).
//
// Без него -07(а) не отличает «ключ работает» от «снять модуль нельзя никогда» —
// и ИМЕННО НА ЭТОМ ВХОДЕ отвергается форма ключа, предложенная кругом 1 приёмки
// (константная колонка под `CHECK`: у снятой строки она остаётся `true`, и
// ссылка на `(module, true)` живёт вечно).

func TestIAMMW108_ModuleWithAllResourcesRetiredIsWithdrawn(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	verbs, refs := withdrawModule(t, ctx, pool, withdrawnModule, "проба IAM-MW-1-08")
	t.Logf("переселено выдач %d, объявлений %d", verbs, refs)

	var moduleLive bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kaname.catalog_module WHERE module = $1`,
		withdrawnModule).Scan(&moduleLive))
	require.False(t, moduleLive, "модуль, все ресурсы которого сняты, ОБЯЗАН сниматься")

	var liveRes, liveVerbs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.catalog_resource WHERE module = $1 AND live`,
		withdrawnModule).Scan(&liveRes))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.catalog_verb WHERE module = $1 AND live`,
		withdrawnModule).Scan(&liveVerbs))
	require.Zero(t, liveRes)
	require.Zero(t, liveVerbs)

	// Соседний модуль не задет: ключ судит СВОЙ модуль, а не каталог целиком.
	var neighbours int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.catalog_module WHERE live AND module <> $1`,
		withdrawnModule).Scan(&neighbours))
	t.Logf("живых соседних модулей после отзыва %s: %d", withdrawnModule, neighbours)
	require.Positive(t, neighbours, "отзыв одного модуля не снимает остальные")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-09 — живой каталог ключом НЕ заперт.
//
// Контроль против миграции, которая заперла бы каталог целиком: перепись после
// неё обязана совпасть с объявленной производителем посева, а снятие и оживление
// ресурса ЖИВОГО модуля — проходить.

func TestIAMMW109_LiveCatalogIsNotLockedByTheKey(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	wantMod, wantRes, wantVerbs := declaredCatalogSize()
	got := readCatalogCensus(t, ctx, pool)
	t.Logf("объявлено производителем: модулей %d, ресурсов %d, глаголов %d",
		wantMod, wantRes, wantVerbs)
	got.log(t, "после миграции ключа")
	require.Equal(t, wantMod, len(got.modules))
	require.Equal(t, wantRes, len(got.resources))
	require.Equal(t, wantVerbs, len(got.verbs))

	// Ресурс живого модуля снимается и оживает — ключ живости МОДУЛЯ живости
	// ресурса не судит.
	requireNoRefsYet(t, ctx, pool, "vpc", "cidrGroup")
	require.NoError(t, retireResource(ctx, pool, "vpc", "cidrGroup", "проба IAM-MW-1-09"))
	_, err := pool.Exec(ctx, `
		UPDATE kaname.catalog_resource
		   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
		 WHERE module = 'vpc' AND resource = 'cidrGroup'`)
	require.NoError(t, err, "ресурс ЖИВОГО модуля оживает без оговорок")

	after := readCatalogCensus(t, ctx, pool)
	after.log(t, "после снятия и оживления ресурса живого модуля")
	require.Equal(t, keysOf(got.resources), keysOf(after.resources))
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-02(б) — полоса ВЫДАЧИ: правило, назвавшее снятый ресурс, получает
// текст контракта.
//
// Приёмка §5.7 называет эту клетку заказом: производитель текста есть
// (`pgmaperr.go`), а утверждающей пробы нет ни одной — ветвь исхода печатается
// `TestIAMCT112`, но утверждается там только код.
//
// Полоса СНЯТИЯ (-02(а)) текста не производит вовсе и утверждается
// `TestIAMCT108`: у снятия Go-вызывающего нет, подсказку писателя ставит
// `ReplaceRuleRefs`. Требовать пару под одним «Когда» нельзя — такого входа не
// существует.

func TestIAMMW102B_RuleNamingARetiredResourceGetsTheContractText(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.New(pool, nil)

	// Положительный контроль: тот же ресурс, пока он жив, правилом называется.
	requireNoRefsYet(t, ctx, pool, "vpc", "cidrGroup")
	ok := catalogRole(t, ctx, pool, "mw102ok")
	require.NoError(t, writeRuleRefs(t, ctx, repo, ok,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "cidrGroup", Verb: "get"}}))

	// Снятие возможно только после того, как объявление переселено, — иначе
	// отвергнет ключ. Пользуемся уже построенным механизмом (#1030).
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	relocateGrants(t, ctx, tx, "vpc", "cidrGroup", "проба IAM-MW-1-02(б)")
	require.NoError(t, retireResource(ctx, tx, "vpc", "cidrGroup", "проба IAM-MW-1-02(б)"))
	require.NoError(t, tx.Commit(ctx))

	bad := catalogRole(t, ctx, pool, "mw102")
	err = writeRuleRefs(t, ctx, repo, bad,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "cidrGroup", Verb: "get"}})
	require.Error(t, err, "правило, назвавшее снятый ресурс, обязано отвергаться")
	t.Logf("отказ полосы выдачи: %v", err)
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition,
		"тон — предусловия, а не валидации: отвечал ключ, а не грамматика")
	require.Contains(t, err.Error(), "resources: cidrGroup is not a live platform resource",
		"текст — часть контракта: клиент читает его, а не SQLSTATE")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-14 — оживление ВСТАВКОЙ отвергается: снятая строка занимает ключ.

func TestIAMMW114_RevivalByInsertIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	requireNoRefsYet(t, ctx, pool, "vpc", "cidrGroup")
	require.NoError(t, retireResource(ctx, pool, "vpc", "cidrGroup", "проба IAM-MW-1-14"))

	// Имя типа модели прав подаётся ЯВНО: колонка обязательна (миграция
	// 20260903112400), и без неё вставку отвергал бы `23502` — то есть проба
	// утверждала бы про NOT NULL вместо первичного ключа, о котором она.
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.catalog_resource (module, resource, dotted, object_type)
		VALUES ('vpc', 'cidrGroup', 'vpc.cidrGroup', 'vpc_cidr_group')`)
	require.Error(t, err, "повторная установка не вставляет строку заново")
	code, constraint := pgCode(err)
	t.Logf("вставка отвергнута: SQLSTATE %s, ограничение %q", code, constraint)
	require.Equal(t, "23505", code)
	require.Equal(t, "catalog_resource_pkey", constraint)
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-15 — оживление ОДНИМ оператором проходит; частичное — нет, и
// частичных входов ДВА, у каждого СВОЁ ограничение.

func TestIAMMW115_RevivalIsOneStatement(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// Снятый ресурс С ПРЕЕМНИКОМ уже посеян миграцией: без непустого
	// `superseded_by` вход (а2) неконструируем, а не строг.
	const dotted = "compute.disk"
	var successor *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT superseded_by FROM kaname.catalog_resource WHERE dotted = $1`, dotted).
		Scan(&successor))
	require.NotNil(t, successor, "предпосылка (а2): у снятой строки есть преемник")

	// (а1) правится ТОЛЬКО live — первым отвечает согласие живости с отметкой.
	_, err := pool.Exec(ctx,
		`UPDATE kaname.catalog_resource SET live = true WHERE dotted = $1`, dotted)
	require.Error(t, err)
	code, constraint := pgCode(err)
	t.Logf("(а1) правка одного live: SQLSTATE %s, ограничение %q", code, constraint)
	require.Equal(t, "23514", code)
	require.Equal(t, "catalog_resource_live_matches_retired", constraint)

	// (а2) правятся live и retired_at, преемник ОСТАВЛЕН — отвечает уже другое
	// ограничение. Одна половина без другой называла бы ЧУЖОЕ ограничение.
	_, err = pool.Exec(ctx, `
		UPDATE kaname.catalog_resource SET live = true, retired_at = NULL
		 WHERE dotted = $1`, dotted)
	require.Error(t, err)
	code, constraint = pgCode(err)
	t.Logf("(а2) правка live и retired_at при оставленном преемнике: SQLSTATE %s, ограничение %q",
		code, constraint)
	require.Equal(t, "23514", code)
	require.Equal(t, "catalog_resource_successor_only_when_retired", constraint)

	// (б) четыре колонки одним оператором — проходит. Без него (а1)/(а2) не
	// отличают «оживление работает» от «оживление невозможно».
	_, err = pool.Exec(ctx, `
		UPDATE kaname.catalog_resource
		   SET live = true, retired_at = NULL, retired_reason = NULL, superseded_by = NULL
		 WHERE dotted = $1`, dotted)
	require.NoError(t, err, "оживление ОДНИМ оператором обязано проходить")

	var live bool
	var retiredAt *time.Time
	var sup *string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live, retired_at, superseded_by FROM kaname.catalog_resource WHERE dotted = $1`,
		dotted).Scan(&live, &retiredAt, &sup))
	require.True(t, live)
	require.Nil(t, retiredAt)
	require.Nil(t, sup)
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-16 — ЯДРО #1823: установить → отозвать → установить, перепись
// совпадает ПО МНОЖЕСТВАМ.

func TestIAMMW116_WithdrawAndInstallRestoresTheCensusBySets(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.New(pool, nil)

	// Своя выдача на ресурсе отзываемого модуля. Без неё половина «права
	// арендатора возвращаются» была бы утверждением о пустом множестве: на
	// чистой базе строк выдачи по этому модулю ноль (замер: переселено 0 из 0).
	firstRes := moduleResources(t, ctx, pool, withdrawnModule)[0]
	requireNoRefsYet(t, ctx, pool, withdrawnModule, firstRes)
	role := catalogRole(t, ctx, pool, "mw116")
	require.NoError(t, writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{{Module: withdrawnModule, Resource: firstRes, Verb: "get"}}))
	require.NoError(t, writeRoleVerbs(t, ctx, repo, role,
		[]domain.RoleVerb{{ObjectType: withdrawnModule + "." + firstRes, Verb: "get"}}))

	before := readCatalogCensus(t, ctx, pool)
	before.log(t, "до отзыва")
	require.NotEmpty(t, before.modules, "пустой каталог сделал бы сравнение вакуумным")

	beforeRefs := readSet(t, ctx, pool, `
		SELECT role_id || '|' || module || '.' || resource || '|' || COALESCE(verb, '*')
		  FROM kaname.role_rule_ref`)
	beforeVerbs := readSet(t, ctx, pool,
		`SELECT role_id || '|' || object_type || '|' || verb FROM kaname.role_verb`)

	resources := moduleResources(t, ctx, pool, withdrawnModule)
	require.NotEmpty(t, resources)

	movedVerbs, movedRefs := withdrawModule(t, ctx, pool, withdrawnModule, "проба IAM-MW-1-16")
	t.Logf("отозван модуль %s: переселено выдач %d, объявлений %d, ресурсов %v",
		withdrawnModule, movedVerbs, movedRefs, resources)
	require.Positive(t, movedVerbs, "переселять было нечего — половина о правах вакуумна")
	require.Positive(t, movedRefs, "переселять было нечего — половина о правах вакуумна")

	mid := readCatalogCensus(t, ctx, pool)
	mid.log(t, "после отзыва")
	require.NotEqual(t, keysOf(before.modules), keysOf(mid.modules),
		"отзыв обязан быть НАБЛЮДАЕМ: перепись после него не может совпасть с исходной")

	backVerbs, backRefs := installModule(t, ctx, pool, withdrawnModule, resources)
	t.Logf("установлен снова: возвращено выдач %d, объявлений %d", backVerbs, backRefs)
	require.Equal(t, movedVerbs, backVerbs, "вернулось столько выдач, сколько переселено")
	require.Equal(t, movedRefs, backRefs, "вернулось столько объявлений, сколько переселено")

	after := readCatalogCensus(t, ctx, pool)
	after.log(t, "после повторной установки")

	// Сравниваются МНОЖЕСТВА: мощности сошлись бы и при подмене одной строки
	// другой, а это ровно тот исход, который обратимость обязана исключать.
	require.Equal(t, keysOf(before.modules), keysOf(after.modules), "множество модулей")
	require.Equal(t, keysOf(before.resources), keysOf(after.resources), "множество ресурсов")
	require.Equal(t, keysOf(before.verbs), keysOf(after.verbs), "множество глаголов")

	// Права арендатора — вторая половина обратимости: переселение возвращает то,
	// что забрало, иначе «переселено» неотличимо от «отобрано».
	afterRefs := readSet(t, ctx, pool, `
		SELECT role_id || '|' || module || '.' || resource || '|' || COALESCE(verb, '*')
		  FROM kaname.role_rule_ref`)
	afterVerbs := readSet(t, ctx, pool,
		`SELECT role_id || '|' || object_type || '|' || verb FROM kaname.role_verb`)
	t.Logf("объявлений до %d, после %d; выдач до %d, после %d",
		len(beforeRefs), len(afterRefs), len(beforeVerbs), len(afterVerbs))
	require.Equal(t, keysOf(beforeRefs), keysOf(afterRefs), "множество объявлений")
	require.Equal(t, keysOf(beforeVerbs), keysOf(afterVerbs), "множество выдач")

	var orphans int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.role_grant_orphan o
		  JOIN kaname.catalog_resource cr ON cr.dotted = o.object_type
		 WHERE cr.module = $1`, withdrawnModule).Scan(&orphans))
	require.Zero(t, orphans,
		"след, чей предмет вернулся целиком, не остаётся: он утверждал бы отобранное право")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-MW-1-17 — след сирот, чей предмет ВЕРНУЛСЯ, снят; чей не вернулся — уцелел.
//
// Повторная установка объявляет НЕ ВСЕ прежние ресурсы: модуль возвращается новой
// ревизией. Это и есть вход, на котором `DELETE … WHERE source = 'rule_ref'` без
// условия снял бы строку, чей предмет уцелел.

func TestIAMMW117_OrphanTraceDropsOnlyWhatCameBack(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.New(pool, nil)

	resources := moduleResources(t, ctx, pool, withdrawnModule)
	require.GreaterOrEqual(t, len(resources), 2,
		"сценарию нужны ДВА ресурса: один возвращается, другой нет")
	returning, staying := resources[0], resources[1]

	// Своя выдача на КАЖДОМ из двух ресурсов: без неё «след уцелел» было бы
	// утверждением о пустом множестве.
	//
	// Суффикс роли — буква, а не имя ресурса: из него строятся ИМЯ РОЛИ
	// (`roles_custom_name_check`) и ИМЯ АККАУНТА (`accounts_name_check`), и обе
	// проверки имя ресурса не пропускают. Отказ приходил бы на посеве и называл
	// виновником фикстуру, а не предмет пробы.
	for i, res := range []string{returning, staying} {
		requireNoRefsYet(t, ctx, pool, withdrawnModule, res)
		role := catalogRole(t, ctx, pool, "mw117"+string(rune('a'+i)))
		require.NoError(t, writeRuleRefs(t, ctx, repo, role,
			[]domain.RoleRuleRef{{Module: withdrawnModule, Resource: res, Verb: "get"}}))
		require.NoError(t, writeRoleVerbs(t, ctx, repo, role,
			[]domain.RoleVerb{{ObjectType: withdrawnModule + "." + res, Verb: "get"}}))
		t.Logf("роль %d: выдача на %s.%s", i+1, withdrawnModule, res)
	}

	movedVerbs, movedRefs := withdrawModule(t, ctx, pool, withdrawnModule, "проба IAM-MW-1-17")
	require.Positive(t, movedVerbs, "переселять было нечего — сценарий вакуумен")
	require.Positive(t, movedRefs, "переселять было нечего — сценарий вакуумен")

	// Повторная установка объявляет ТОЛЬКО один ресурс.
	installModule(t, ctx, pool, withdrawnModule, []string{returning})

	countTrace := func(res string) int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kaname.role_grant_orphan
			 WHERE object_type = $1`, withdrawnModule+"."+res).Scan(&n))
		return n
	}
	back, kept := countTrace(returning), countTrace(staying)
	t.Logf("след после установки: у вернувшегося %s — %d строк, у оставшегося снятым %s — %d",
		returning, back, staying, kept)
	require.Zero(t, back, "след, чей предмет вернулся, снят")
	require.Positive(t, kept, "след, чей предмет НЕ вернулся, уцелел — иначе право исчезло бы молча")

	var liveBack, liveKept bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kaname.catalog_resource WHERE module = $1 AND resource = $2`,
		withdrawnModule, returning).Scan(&liveBack))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kaname.catalog_resource WHERE module = $1 AND resource = $2`,
		withdrawnModule, staying).Scan(&liveKept))
	require.True(t, liveBack, "объявленный повторной установкой ресурс жив")
	require.False(t, liveKept, "не объявленный ею — остаётся снятым")
}
