// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// role_verb_reseed_integration_test.go — досев проекции «роль → тип объекта ×
// глагол» на старте: чего он НЕ обязан обнулять и что обязан сообщать.
//
// Приёмка `role-verb-projection-sole-writer.md`, сценарии IAM-RV-1-04, -05, -06,
// -07 (поведенческая половина), -08, -11.
//
// # Предмет
//
// Пересчёт проекции системных ролей жил в ОДНОЙ транзакции с досевом владельческих
// выдач и шёл по всем ролям сразу. Отсюда два следствия, и оба наблюдаемы отсюда:
// отказ на одной паре откатывал работу, к проекции отношения не имеющую, и
// откатывал пересчёт ВСЕХ прочих ролей. Приёмка развела транзакции и назначила
// зернистость — одна транзакция НА РОЛЬ; полосы зовутся порознь, и эти пробы
// зовут их так же, как композиционный корень (`bootSeedLanes`).
//
// # Как вносится отказ
//
// Триггером на самой таблице, в СВОЕЙ базе пробы (каждая проба этого пакета
// получает свою). Это и есть «состояние, на котором пересчёт отказывает» из
// текста сценариев: отказ детерминирован, адресуем одной ролью либо всеми сразу,
// и не требует ни правки продукта, ни подделки его слоёв.
//
// Пороль-адресный отказ ставится на INSERT: `DELETE` роли без строк проекции
// построчного триггера не задевает вовсе. Отказ «на всех» ставится на DELETE
// ОПЕРАТОРОМ — он срабатывает и на нуле строк, поэтому падает КАЖДАЯ роль,
// включая ту, у которой пар не оказалось.
//
// # Чего эти пробы НЕ утверждают
//
// Ни уровня журнала, ни счётчика отказов: они живут в композиционном корне, то
// есть в `package main`, куда проба Go не дотягивается by construction. Эту
// половину IAM-RV-1-07 держит гейт дерева
// `internal/repohygiene/roleverbreseedbootlane_test.go`.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// reseedProbeCluster — якорь, по которому роль считается системной.
const reseedProbeCluster = "cluster_kacho_root"

// materializingRules — правило, дающее непустой набор пар. Модуль и ресурс взяты
// из каталога платформы: правило вне каталога инертно целиком, и проба на нём
// зеленела бы, ничего не утверждая.
const materializingRules = `[{"module":"iam","resources":["role"],"verbs":["get"]}]`

// newReseedPool — своя база на пробу.
func newReseedPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool
}

// bootSeedLanes — «досев старта» в той части, что касается правил системной роли:
// селекторы и проекция глаголов, каждая своей полосой, в том же порядке, в каком
// их зовёт композиционный корень.
//
// Полосы разведены НАМЕРЕННО: у пересчёта проекции свой вход (порт записи), своя
// зернистость (транзакция на роль) и своя полоса отказа, поэтому досев селекторов
// его не зовёт — иначе на старте пересчёт шёл бы дважды, а его отказ приезжал бы
// обёрнутым в чужую ошибку. Отсюда и здесь два вызова, а не один.
//
// Возвращается отказ ПЕРЕСЧЁТА — та величина, по которой корень отличает
// транзиентную полосу от структурной.
func bootSeedLanes(ctx context.Context, pool *pgxpool.Pool) error {
	if err := seed.SyncAllSystemRoleSelectors(ctx, pool); err != nil {
		return err
	}
	_, err := seed.ReseedSystemRoleVerbs(ctx, kachopg.New(pool, nil), pool, catalogfixture.Facts(), nil)
	return err
}

// bootBindingsAndVerbs — досев владельческих выдач и пересчёт проекции: две
// РАЗНЫЕ полосы, идущие на старте одна за другой. Общей транзакции у них больше
// нет, и это предмет пробы IAM-RV-1-06, а не её обстановка.
func bootBindingsAndVerbs(ctx context.Context, pool *pgxpool.Pool) error {
	if err := seed.BackfillOwnerBindings(ctx, pool); err != nil {
		return err
	}
	_, err := seed.ReseedSystemRoleVerbs(ctx, kachopg.New(pool, nil), pool, catalogfixture.Facts(), nil)
	return err
}

// seedProbeSystemRole заводит системную роль сырым SQL — ровно тем путём, каким
// её заводит миграция, и каким она НИКОГДА не проходит через путь роли.
func seedProbeSystemRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, name, rules string) string {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '["iam.role.*.get"]'::jsonb, $3::jsonb, $4)`,
		id, name, rules, reseedProbeCluster)
	require.NoErrorf(t, err, "посев системной роли %s", id)
	return id
}

// seedProbeAccountWithoutOwnerBinding заводит пользователя и аккаунт БЕЗ
// владельческой выдачи — то состояние, ради которого досев выдач и существует.
func seedProbeAccountWithoutOwnerBinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (string, string) {
	t.Helper()
	uid := "usr-rv" + suffix
	accID := "acc-rv" + suffix
	// Обе строки — в ОДНОЙ транзакции: ключи пользователя и аккаунта ссылаются друг
	// на друга и объявлены отложенными, поэтому порядок вставки внутри транзакции
	// значения не имеет, а вне её невыполним НИ ОДИН порядок.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx,
		`INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		 VALUES ($1, $2, $3, $4, 'RoleVerb Probe', 'ACTIVE')`,
		uid, accID, "ext-"+uid, uid+"@probe.invalid")
	require.NoError(t, err, "посев пользователя")
	_, err = tx.Exec(ctx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		 VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "probe-acc-"+suffix, uid)
	require.NoError(t, err, "посев аккаунта")
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// refuseRoleVerbInsertFor вносит отказ пересчёта РОВНО ОДНОЙ роли.
func refuseRoleVerbInsertFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION kacho_iam.probe_refuse_role_verb() RETURNS trigger
		LANGUAGE plpgsql AS $fn$
		BEGIN
			RAISE EXCEPTION 'проба: запись проекции роли отвергнута';
		END $fn$;
		CREATE TRIGGER probe_refuse_role_verb_insert
			BEFORE INSERT ON kacho_iam.role_verb
			FOR EACH ROW WHEN (NEW.role_id = '`+roleID+`')
			EXECUTE FUNCTION kacho_iam.probe_refuse_role_verb();`)
	require.NoError(t, err, "внести отказ пересчёта одной роли")
}

// refuseEveryRoleVerbReseed вносит отказ пересчёта ВСЕХ ролей. Триггер —
// операторный на DELETE: пересчёт роли начинается с него всегда, даже когда
// вставлять нечего, поэтому не пересеивается НИ ОДНА роль.
func refuseEveryRoleVerbReseed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION kacho_iam.probe_refuse_role_verb() RETURNS trigger
		LANGUAGE plpgsql AS $fn$
		BEGIN
			RAISE EXCEPTION 'проба: пересчёт проекции отвергнут для всех ролей';
		END $fn$;
		CREATE TRIGGER probe_refuse_role_verb_all
			BEFORE DELETE ON kacho_iam.role_verb
			FOR EACH STATEMENT
			EXECUTE FUNCTION kacho_iam.probe_refuse_role_verb();`)
	require.NoError(t, err, "внести отказ пересчёта всех ролей")
}

// projectionSizeOf — сколько пар у роли.
func projectionSizeOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, roleID).Scan(&n))
	return n
}

// wholeProjection — вся таблица в виде отсортированного набора: колонки порядка
// не несут, поэтому сравнивается СОСТАВ.
func wholeProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT role_id, object_type, verb FROM kacho_iam.role_verb`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r, ot, v string
		require.NoError(t, rows.Scan(&r, &ot, &v))
		out = append(out, r+"|"+ot+"|"+v)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// seedProbeCatalogResourceNotInCompiledSet кладёт ЖИВУЮ строку каталога ресурсов,
// точечное имя которой компилируемое множество раскрытия НЕ знает.
//
// # Зачем это нужно, и почему прежнего входа больше нет
//
// Утверждение «проекция не выдумывает типов» ставилось на роли, объявлявшей тип,
// которого каталог не знает вовсе. Такой строки селектора больше НЕ БЫВАЕТ:
// триггер `role_rule_selectors_types_live` (миграция
// `20260902174500_selector_types_name_a_live_resource.sql`) отвергает её НА ВХОДЕ,
// и вопрос вместе с входом стал непредставим — проба падала на своей фикстуре,
// не дойдя ни до одного утверждения (задача #1941).
//
// Вход, который дерево ПРОИЗВОДИТ сегодня, ровно один и он уже, а не шире:
// источников имени типа ДВА, и они разные по построению — таблица
// `kacho_iam.catalog_resource`, которую судит триггер, и закрытое компилируемое
// множество `authzmap.objectTypes`, по которому раскрывает `RoleVerbsFromSelectors`
// (`fgaType, ok := authzmap.FGAObjectType(dotted); if !ok { continue }`). Пока они
// сходятся, разницы не видно; разойдись они — а это ровно состояние, которое
// называет шапка самой миграции («рассинхрон литерала типов и каталога», #1816), —
// селектор пишется, а раскрывать его нечем.
//
// То есть проба стала ТОЧНЕЕ прежней, а не слабее: раньше «каталог не знает» и
// «множество не раскрывает» были истинны одновременно, и по зелени нельзя было
// сказать, которая половина держит границу. Теперь каталог тип ЗНАЕТ, и
// отсутствие пар удерживает ровно множество раскрытия — предмет `#1030`.
//
// Строка кладётся сырым SQL — тем же путём, каким её кладёт миграция посева, и
// проходит ВСЕ ограничения таблицы (`dotted = module || '.' || resource`, ключ
// модуля, живость): подделки здесь нет, есть законная строка каталога.
func seedProbeCatalogResourceNotInCompiledSet(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	module, resource string) string {
	t.Helper()
	dotted := module + "." + resource
	// Имя типа модели прав — ОБЯЗАТЕЛЬНАЯ колонка строки каталога
	// (`catalog_resource.object_type`, миграция 20260903112400: NOT NULL плюс
	// проверка формы). Фикстура, её опускавшая, была СНИСХОДИТЕЛЬНЕЕ продукта:
	// она подавала вход, которого в дереве не бывает, и с появлением колонки
	// перестала вставляться вовсе (`23502`). Значение выводится тем же правилом,
	// каким его выводит манифест синтетического модуля, — здесь это законно: имя
	// принадлежит фикстуре, а не каталогу платформы.
	objectType := module + "_" + strings.ToLower(resource)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type)
		 VALUES ($1, $2, $3, $4)`, module, resource, dotted, objectType)
	require.NoErrorf(t, err, "посев живой строки каталога %s", dotted)
	return dotted
}

// selectorRowsNaming — сколько строк селекторов роли называют этот точечный тип.
//
// Это ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ границы ниже, и без него она вакуумна: «пар нет»
// зеленело бы и на селекторе, который не записался вовсе, — то есть на том самом
// состоянии, из-за которого проба и переписывалась.
func selectorRowsNaming(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID, dotted string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors
		  WHERE role_id = $1 AND $2 = ANY(object_types)`, roleID, dotted).Scan(&n))
	return n
}

// IAM-RV-1-04 — два прогона досева дают одно и то же (ХАРАКТЕРИЗУЮЩИЙ ЗАМОК).
//
// Замок фиксирует СЕГОДНЯШНЕЕ поведение как известное, включая его границу: тип,
// ЖИВОЙ в каталоге ресурсов, но не раскрываемый компилируемым множеством, в
// проекции ОТСУТСТВУЕТ. Это предмет `#1030`, а не дефект этой полосы, и записан
// он здесь затем, чтобы его смена была видна.
//
// Вход этой границы был переписан по #1941: прежний (тип, которого каталог не
// знает вовсе) стал непредставим — его отвергает триггер живости на входе
// селектора. Разбор нового входа — у `seedProbeCatalogResourceNotInCompiledSet`.
func TestIAMRV104_TwoReseedRunsAgreeAndDoNotInventTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	resolvable := seedProbeSystemRole(t, ctx, pool, "rol-rv104-known", "probe.rv104.known", materializingRules)
	// Тип ЖИВЁТ в каталоге ресурсов — иначе триггер живости отверг бы селектор на
	// входе, — но компилируемое множество раскрытия его не знает: перевод его
	// пропускает.
	undisclosed := seedProbeCatalogResourceNotInCompiledSet(t, ctx, pool, "iam", "thereisnosuchresource")
	unknown := seedProbeSystemRole(t, ctx, pool, "rol-rv104-unknown", "probe.rv104.unknown",
		`[{"module":"iam","resources":["thereisnosuchresource"],"verbs":["get"]}]`)

	require.NoError(t, bootSeedLanes(ctx, pool))
	first := wholeProjection(t, ctx, pool)
	require.NoError(t, bootSeedLanes(ctx, pool))
	second := wholeProjection(t, ctx, pool)

	namedBySelector := selectorRowsNaming(t, ctx, pool, unknown, undisclosed)
	t.Logf("пар в проекции: прогон 1 — %d, прогон 2 — %d; роль с раскрываемым типом — %d пар, "+
		"роль с нераскрываемым — %d пар; строк селекторов, называющих %s, — %d",
		len(first), len(second),
		projectionSizeOf(t, ctx, pool, resolvable), projectionSizeOf(t, ctx, pool, unknown),
		undisclosed, namedBySelector)

	require.NotEmpty(t, first, "проекция пуста после досева — сравнение двух прогонов было бы "+
		"вакуумным: оно выполнялось бы на досеве, не пишущем ничего")
	require.Equal(t, first, second, "второй прогон досева изменил проекцию — пересчёт не идемпотентен")
	require.Positive(t, projectionSizeOf(t, ctx, pool, resolvable),
		"роль с раскрываемым типом пар не получила — положительный контроль границы ниже мёртв")
	require.Positivef(t, namedBySelector,
		"селектор, называющий %s, не записан — значит триггер живости его отверг либо досев "+
			"селекторов до него не дошёл. Тогда утверждение ниже вакуумно: «пар нет» верно по "+
			"причине, к множеству раскрытия отношения не имеющей", undisclosed)
	require.Zerof(t, projectionSizeOf(t, ctx, pool, unknown),
		"ГРАНИЦА, названная прямо: тип, живой в каталоге ресурсов, но не раскрываемый "+
			"компилируемым множеством, в проекции отсутствует. Это предмет #1030 (раскрытие "+
			"идёт через компилируемое множество Go), а не дефект этой полосы. Проба фиксирует "+
			"сегодняшнее поведение, чтобы его смена была видна")
}

// IAM-RV-1-05 — досев не трогает роли арендатора (ХАРАКТЕРИЗУЮЩИЙ ЗАМОК).
//
// Границу держит `WHERE is_system = true` в выборке досева. Её потеря переписывала
// бы проекции ролей арендатора на каждом старте — то есть отзывала бы права,
// которые он выдал себе сам, и делала бы это молча.
func TestIAMRV105_ReseedLeavesTenantRolesAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	uid, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "105")
	_ = uid
	systemRole := seedProbeSystemRole(t, ctx, pool, "rol-rv105-sys", "probe.rv105.sys", materializingRules)

	// Роль арендатора: аккаунтная, не системная. Её проекцию кладём вручную —
	// именно её досев обязан НЕ ТРОГАТЬ.
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.roles (id, account_id, name, permissions, rules)
		 VALUES ('rol-rv105-tenant', $1, 'probe_rv105_tenant', '["iam.role.*.get"]'::jsonb, $2::jsonb)`,
		accID, materializingRules)
	require.NoError(t, err, "посев роли арендатора")
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		 VALUES ('rol-rv105-tenant', 'iam.role', 'v_get')`)
	require.NoError(t, err, "посев проекции роли арендатора")

	before := projectionSizeOf(t, ctx, pool, "rol-rv105-tenant")
	require.Equal(t, 1, before)

	require.NoError(t, bootSeedLanes(ctx, pool))

	after := projectionSizeOf(t, ctx, pool, "rol-rv105-tenant")
	t.Logf("проекция роли арендатора: до досева %d пар, после %d; системная роль получила %d пар",
		before, after, projectionSizeOf(t, ctx, pool, systemRole))

	// Положительный контроль: досев ДОШЁЛ. Без него «роль арендатора не изменилась»
	// зеленело бы на досеве, не сделавшем ничего вовсе.
	require.Positive(t, projectionSizeOf(t, ctx, pool, systemRole),
		"системная роль проекции не получила — досев не дошёл, и утверждение о роли арендатора "+
			"ничего не значит")
	require.Equalf(t, before, after,
		"досев изменил проекцию роли АРЕНДАТОРА (%d → %d) — граница `is_system` потеряна, и "+
			"перекат пода отзывает права, выданные арендатором", before, after)
}

// IAM-RV-1-06 — отказ пересчёта проекции НЕ обнуляет досев владельческих выдач (RED).
//
// Досев держит в одной транзакции четыре операции: выдачи владельцу, их
// субъектные строки, намерение иерархии и пересчёт проекции. Отказ последней
// откатывает первые три, при том что к проекции они отношения не имеют.
func TestIAMRV106_ProjectionFailureDoesNotUndoTheOwnerBindingBackfill(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "106")
	good1 := seedProbeSystemRole(t, ctx, pool, "rol-rv106-a", "probe.rv106.a", materializingRules)
	good2 := seedProbeSystemRole(t, ctx, pool, "rol-rv106-b", "probe.rv106.b", materializingRules)
	bad := seedProbeSystemRole(t, ctx, pool, "rol-rv106-x", "probe.rv106.x", materializingRules)

	ownerBindings := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_bindings
			  WHERE resource_type = 'account' AND resource_id = $1 AND revoked_at IS NULL`,
			accID).Scan(&n))
		return n
	}
	hierarchyIntents := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE event_type = 'fga.tuple.write' AND payload->>'user' = 'account:' || $1`,
			accID).Scan(&n))
		return n
	}
	require.Zero(t, ownerBindings(), "предпосылка: у аккаунта пробы нет владельческой выдачи")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на том же входе БЕЗ внесённого отказа: обе половины
	// записаны. Без него проба зеленела бы на реализации, не пишущей выдачи вовсе.
	t.Run("положительный контроль: без отказа записаны обе половины", func(t *testing.T) {
		ctx2, pool2 := newReseedPool(t)
		_, acc2 := seedProbeAccountWithoutOwnerBinding(t, ctx2, pool2, "106c")
		role2 := seedProbeSystemRole(t, ctx2, pool2, "rol-rv106c", "probe.rv106c", materializingRules)
		require.NoError(t, bootBindingsAndVerbs(ctx2, pool2))
		var n int
		require.NoError(t, pool2.QueryRow(ctx2,
			`SELECT count(*) FROM kacho_iam.access_bindings
			  WHERE resource_type = 'account' AND resource_id = $1 AND revoked_at IS NULL`,
			acc2).Scan(&n))
		require.Positive(t, n, "владельческая выдача не записана и БЕЗ отказа")
		require.Positive(t, projectionSizeOf(t, ctx2, pool2, role2),
			"проекция не записана и БЕЗ отказа")
	})
	refuseRoleVerbInsertFor(t, ctx, pool, bad)
	err := bootBindingsAndVerbs(ctx, pool)

	reseeded := 0
	for _, r := range []string{good1, good2} {
		if projectionSizeOf(t, ctx, pool, r) > 0 {
			reseeded++
		}
	}
	t.Logf("после отказа на одной роли: владельческих выдач %d, намерений иерархии %d, "+
		"ролей пробы с непустой проекцией %d из 2; ошибка досева: %v",
		ownerBindings(), hierarchyIntents(), reseeded, err)

	require.Positivef(t, ownerBindings(),
		"владельческая выдача аккаунта ОТКАЧЕНА отказом пересчёта проекции — досев выдач и "+
			"пересчёт проекции делят одну транзакцию, и отказ одной пары обнуляет чужую работу")
	require.Positive(t, hierarchyIntents(),
		"намерение иерархии откачено тем же отказом — владелец остаётся без пути к собственной выдаче")
	require.Equalf(t, 2, reseeded,
		"роли, пересчитанные ДО отказавшей, не сохранены (сохранено %d из 2) — пересчёт идёт "+
			"одной транзакцией на все роли, а зернистость обязана быть ОДНА НА РОЛЬ", reseeded)
	require.Zero(t, projectionSizeOf(t, ctx, pool, bad),
		"роль, чей пересчёт отказал, получила проекцию — отказ не изолирован")

}

// IAM-RV-1-07 (ПОВЕДЕНЧЕСКАЯ ПОЛОВИНА) — транзиентный отказ на одной роли не
// отменяет пересчёт ОСТАЛЬНЫХ (RED).
//
// Вторая половина сценария — уровень журнала и счётчик отказов — живёт в
// композиционном корне и держится гейтом дерева
// `internal/repohygiene/roleverbreseedbootlane_test.go`. Здесь она НЕ
// утверждается, и зелёный этой пробы её не покрывает.
func TestIAMRV107_TransientFailureOfOneRoleDoesNotUndoTheOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	good1 := seedProbeSystemRole(t, ctx, pool, "rol-rv107-a", "probe.rv107.a", materializingRules)
	good2 := seedProbeSystemRole(t, ctx, pool, "rol-rv107-b", "probe.rv107.b", materializingRules)
	bad := seedProbeSystemRole(t, ctx, pool, "rol-rv107-x", "probe.rv107.x", materializingRules)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: успешный прогон отказа не производит вовсе — иначе
	// утверждение выполнялось бы на реализации, отказывающей всегда.
	t.Run("положительный контроль: без отказа пересчёт молчит", func(t *testing.T) {
		ctx2, pool2 := newReseedPool(t)
		r1 := seedProbeSystemRole(t, ctx2, pool2, "rol-rv107c", "probe.rv107c", materializingRules)
		require.NoError(t, bootSeedLanes(ctx2, pool2),
			"успешный пересчёт вернул ошибку — прибор, кричащий всегда, перестают читать")
		require.Positive(t, projectionSizeOf(t, ctx2, pool2, r1))
	})
	refuseRoleVerbInsertFor(t, ctx, pool, bad)
	err := bootSeedLanes(ctx, pool)

	reseeded := 0
	for _, r := range []string{good1, good2} {
		if projectionSizeOf(t, ctx, pool, r) > 0 {
			reseeded++
		}
	}
	t.Logf("ролей пробы пересеяно %d из 2; ошибка пересчёта: %v", reseeded, err)

	require.Equalf(t, 2, reseeded,
		"отказ ОДНОЙ роли отменил пересчёт остальных (пересеяно %d из 2). Пересчёт идёт одной "+
			"транзакцией на все роли, поэтому транзиентный отказ на любой из них оставляет "+
			"проекцию НЕИЗВЕСТНОЙ целиком — а самолечение обещано по ролям", reseeded)

}

// IAM-RV-1-08 — структурный отказ называет ОБЕ величины; «2 из 3» старт не роняет (RED).
//
// Полос отказа две, и смешивать их нельзя. Транзиентная — база не ответила,
// следующий старт пересчитает. Структурная — системные роли есть, пересеяно
// НОЛЬ: механизм не работает, и повтор даст то же. Отличает их ПЕРЕПИСЬ, поэтому
// отказ обязан называть сколько ролей осмотрено и сколько пересеяно.
func TestIAMRV108_StructuralFailureNamesBothQuantities(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	seedProbeSystemRole(t, ctx, pool, "rol-rv108-a", "probe.rv108.a", materializingRules)
	seedProbeSystemRole(t, ctx, pool, "rol-rv108-b", "probe.rv108.b", materializingRules)

	var systemRoles int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles
		  WHERE is_system = true AND rules IS NOT NULL
		    AND jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) > 0`).Scan(&systemRoles))
	require.Positive(t, systemRoles, "предпосылка структурной полосы: системных ролей с "+
		"материализующими правилами БОЛЬШЕ НУЛЯ — иначе полоса неотличима от свежей базы")

	// ПЕРВЫЙ БЛИЗНЕЦ: свежая база без внесённого отказа — пересчёт проходит.
	// Без него проверка роняла бы штатный старт, то есть краснела бы на достижении цели.
	t.Run("близнец: без отказа пересчёт проходит", func(t *testing.T) {
		ctx2, pool2 := newReseedPool(t)
		seedProbeSystemRole(t, ctx2, pool2, "rol-rv108c", "probe.rv108c", materializingRules)
		require.NoError(t, bootSeedLanes(ctx2, pool2))
	})

	// ВТОРОЙ БЛИЗНЕЦ, которого требует зернистость: часть ролей пересеяна, часть
	// нет — это ТРАНЗИЕНТНАЯ полоса, и старт она не роняет. Без него «пересеяно
	// ноль» было бы неотличимо от «пересеяно не всё».
	t.Run("близнец: пересеяно не всё — полоса транзиентная", func(t *testing.T) {
		ctx3, pool3 := newReseedPool(t)
		a := seedProbeSystemRole(t, ctx3, pool3, "rol-rv108d-a", "probe.rv108d.a", materializingRules)
		b := seedProbeSystemRole(t, ctx3, pool3, "rol-rv108d-b", "probe.rv108d.b", materializingRules)
		x := seedProbeSystemRole(t, ctx3, pool3, "rol-rv108d-x", "probe.rv108d.x", materializingRules)
		refuseRoleVerbInsertFor(t, ctx3, pool3, x)

		serr := bootSeedLanes(ctx3, pool3)
		done := 0
		for _, r := range []string{a, b} {
			if projectionSizeOf(t, ctx3, pool3, r) > 0 {
				done++
			}
		}
		t.Logf("пересеяно %d из 2 доступных; отказ: %v", done, serr)
		require.Equal(t, 2, done, "часть ролей обязана быть пересеяна: полоса транзиентная, "+
			"и «пересеяно не всё» — не «пересеяно ноль»")
		if serr != nil {
			require.NotContainsf(t, serr.Error(), "пересеяно 0",
				"транзиентный отказ объявлен структурным: %q", serr.Error())
		}
	})
	refuseEveryRoleVerbReseed(t, ctx, pool)
	err := bootSeedLanes(ctx, pool)

	var reseeded int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(DISTINCT role_id) FROM kacho_iam.role_verb`).Scan(&reseeded))
	t.Logf("системных ролей с материализующими правилами %d; пересеяно %d; отказ: %v",
		systemRoles, reseeded, err)

	require.Error(t, err, "пересеяно ноль при непустом множестве ролей, а отказа нет — "+
		"структурная полоса не отличима от успеха")
	require.Zero(t, reseeded, "предпосылка внесённого отказа: не пересеяна ни одна роль")

	msg := err.Error()
	require.Containsf(t, msg, "осмотрено",
		"отказ не называет, сколько ролей ОСМОТРЕНО: %q\nБез обеих величин «пересеяно ноль» "+
			"неотличимо от «пересеяно не всё», и оператор не может отличить сломанный механизм "+
			"от не созданного условия", msg)
	require.Containsf(t, msg, "пересеяно",
		"отказ не называет, сколько ролей ПЕРЕСЕЯНО: %q", msg)

}

// IAM-RV-1-11 — два досева разом не оставляют читателя с ПУСТОЙ проекцией (RED).
//
// Граница названа прямо: инвариант утверждается ВНУТРИ роли. Состояние «часть
// ролей пересчитана, часть нет» при зернистости по роли наблюдаемо и ЗАКОННО —
// оно же наблюдается между двумя стартами и между правками двух разных ролей.
func TestIAMRV111_ConcurrentReseedsNeverExposeAnEmptyProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)

	role := seedProbeSystemRole(t, ctx, pool, "rol-rv111", "probe.rv111", materializingRules)

	// Базовая линия ОДНИМ процессом — она же положительный контроль: без неё
	// проба не отличила бы «конкуренция безопасна» от «оба прогона ничего не сделали».
	require.NoError(t, bootSeedLanes(ctx, pool))
	baseline := projectionSizeOf(t, ctx, pool, role)
	require.Positivef(t, baseline, "базовая линия пуста — утверждение о «непустом промежутке» "+
		"было бы вакуумным")

	var (
		writers sync.WaitGroup
		reader  sync.WaitGroup
		mu      sync.Mutex
		empties int
		reads   int
		errs    []string
	)
	stop := make(chan struct{})

	reader.Add(1)
	go func() { // читатель цепи вердикта
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, role).Scan(&n); err == nil {
				mu.Lock()
				reads++
				if n == 0 {
					empties++
				}
				mu.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	}()

	for i := 0; i < 2; i++ {
		writers.Add(1)
		go func(n int) {
			defer writers.Done()
			for r := 0; r < 5; r++ {
				if err := bootSeedLanes(ctx, pool); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Sprintf("процесс %d, проход %d: %v", n, r, err))
					mu.Unlock()
				}
			}
		}(i)
	}

	// Ждём ПИСАТЕЛЕЙ, затем гасим читателя. Ждать их общим счётчиком с читателем
	// нельзя: читатель крутится до сигнала и увёл бы ожидание в предел времени —
	// проба зеленела бы, отняв минуту у очереди.
	done := make(chan struct{})
	go func() { writers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		close(stop)
		reader.Wait()
		t.Fatal("конкурирующие досевы не завершились за отведённое время — пересчёт одной " +
			"транзакцией на все роли сериализует их друг на друге")
	}
	close(stop)
	reader.Wait()

	final := projectionSizeOf(t, ctx, pool, role)
	t.Logf("чтений %d, из них пустых %d; пар после конкуренции %d (базовая линия %d); "+
		"отказов писателей %d %v", reads, empties, final, baseline, len(errs), errs)

	require.Positive(t, reads, "читатель не прочитал НИ РАЗУ — утверждение о промежутке вакуумно")
	require.Emptyf(t, errs, "конкурирующие досевы отказали: %v — два старта разом штатны "+
		"(перекат пода при живом поде), и отказ здесь означает, что зернистость транзакции "+
		"делает пересчёт неустойчивым к конкуренции", errs)
	require.Zerof(t, empties, "читатель цепи вердикта видел ПУСТУЮ проекцию %d раз из %d — "+
		"в этом окне всякий вердикт по роли отказывает, и отказывает МОЛЧА: пустое соединение "+
		"не отличается от честного «права нет»", empties, reads)
	require.Equalf(t, baseline, final,
		"после конкуренции пар %d против %d у одиночного прогона — либо дубли, либо потеря",
		final, baseline)
	require.False(t, strings.Contains(fmt.Sprint(errs), "deadlock"),
		"конкуренция дала взаимную блокировку")
}
