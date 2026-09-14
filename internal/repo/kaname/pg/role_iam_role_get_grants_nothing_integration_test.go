// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_iam_role_get_grants_nothing_integration_test.go — глагол `get` на
// `iam.role` СНЯТ со строки каталога и больше не попадает в проекцию, которую
// читает вердикт.
//
// # Предмет (kacho#1922, приёмка role-read-relation-retired-not-half-declared.md)
//
// Тип `iam_role` объявлял отношение `v_get`, и читателя у него не было ни одного:
// единичное чтение роли энфорсится ТЕМ ЖЕ предикатом, что страница
// (`{viewer, v_list}`, internal/authzfilter/visibility.go), и обе поверхности
// зовут один резолвер `resolveVisibleRoleIDs`. Ни одна запись каталога прав края
// не называет `v_get` на этом типе.
//
// Наблюдаемая цена была не «лишняя строка в модели». Правило с подстановкой
// (`classes: ["*"]` у `iam.role.admin`) разворачивается в набор ТИПА — значит
// превью роли обещало арендатору глагол `get`, которого не исполняет ни один путь
// запроса, а проекция `role_verb` несла пару, о которой никто никогда не спросит.
//
// # Что здесь утверждается — СТРОКИ, а не объявление
//
// «Отношения нет в модели» держат гейты соседних пакетов (`authzmap`,
// `authzmodel`); «посев согласен с литералом» — гейт дерева в `internal/check`.
// Здесь вердикт выносится по тому, что лежит в БД после наката ВСЕХ миграций и
// самолечащего посева, — то есть по тому, что увидит вопрос о доступе.
//
// # Почему пары контролей обязательны
//
// «Строк нет» истинно и на пустой базе, и на не доехавшем посеве, и на сломанном
// запросе. Поэтому рядом стоят положительные контроли: роль `iam.role.admin`
// обязана ОСТАТЬСЯ непустой (она продолжает давать всё, что тип объявляет), а
// глагол `get` обязан остаться живым у СОСЕДНИХ типов — иначе «на iam.role его
// нет» читалось бы как «его нет нигде», то есть как поломка проекции, а не как
// сужение набора одного типа.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestRoleIamRoleGet_IsRetiredNotDeletedAndGrantsNothing — GWT-7 и GWT-10
// приёмки: строка каталога ПОМЕЧЕНА снятой (а не удалена), и проекция роли пары
// с этим глаголом не даёт.
func TestRoleIamRoleGet_IsRetiredNotDeletedAndGrantsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Проекция системных ролей самолечащая. Зовём её ЯВНО: иначе «ноль пар с
	// глаголом get» был бы получен из того, что проекцию не считал никто, а не из
	// сужения набора типа.
	require.NoError(t, bootSeedRuleSides(ctx, pool))

	// ── Перепись ДО вердикта ────────────────────────────────────────────────
	totalRoles := scalarInt(t, ctx, pool, `SELECT count(*) FROM kaname.roles`)
	totalVerbs := scalarInt(t, ctx, pool, `SELECT count(*) FROM kaname.role_verb`)
	onRole := scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.role_verb WHERE object_type = 'iam.role'`)
	catalogRows := scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.catalog_verb WHERE module = 'iam' AND resource = 'role'`)
	t.Logf("осмотрено: ролей=%d, строк проекции роль→глагол=%d, из них на iam.role=%d; "+
		"строк словаря глаголов у iam/role=%d", totalRoles, totalVerbs, onRole, catalogRows)
	require.NotZero(t, totalRoles, "предпосылка сломана: в посеве нет ни одной роли")
	require.NotZero(t, totalVerbs,
		"предпосылка сломана: проекция роль→глагол пуста, и «ноль пар с get» был бы даром")
	require.NotZero(t, onRole,
		"предпосылка сломана: на iam.role проекция не даёт НИ ОДНОЙ пары — тогда отсутствие "+
			"именно `get` не означает ничего")

	// ── GWT-7: строка СНЯТА, а не удалена ──────────────────────────────────
	//
	// Снятые строки каталога не удаляются: удаление сделало бы снятое
	// неотличимым от никогда не объявленного, и преемник строки потерял бы
	// референт.
	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.catalog_verb
		  WHERE module = 'iam' AND resource = 'role' AND verb = 'get'`),
		"строка словаря про iam.role.get исчезла — снятие УДАЛИЛО её вместо пометки")
	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.catalog_verb
		  WHERE module = 'iam' AND resource = 'role' AND verb = 'get'
		    AND NOT live AND retired_at IS NOT NULL AND retired_reason <> ''`),
		"строка iam.role.get не помечена снятой либо снята без причины: снятие без причины "+
			"неотличимо от порчи данных")

	// ── GWT-10: проекция пары не даёт ──────────────────────────────────────
	//
	// Находка НАЗЫВАЕТ роли поимённо: «строк N» не говорит, какие выдачи стали бы
	// мёртвым правом, и разбирать пришлось бы отдельным запросом.
	offenders := scalarString(t, ctx, pool,
		`COALESCE((SELECT string_agg(r.name, ', ' ORDER BY r.name)
		             FROM kaname.role_verb rv
		             JOIN kaname.roles r ON r.id = rv.role_id
		            WHERE rv.object_type = 'iam.role' AND rv.verb = 'get'), '')`)
	require.Emptyf(t, offenders,
		"проекция всё ещё даёт `get` на iam.role — роли: %s. Отношение снято с типа, значит "+
			"правило, назвавшее глагол (в том числе подстановкой `*`), не должно давать ничего: "+
			"читателя у пары (iam_role, v_get) нет ни одного, чтение роли энфорсится предикатом "+
			"страницы", offenders)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1 (GWT-3, GWT-4): подстановочная роль НЕ опустела
	//
	// `iam.role.admin` — правило `classes: ["*"]`, разворачиваемое в набор ТИПА.
	// После снятия она обязана давать РОВНО три оставшихся глагола: «ноль пар с
	// get» зеленело бы и на роли, у которой отняли всё.
	adminRole := scalarString(t, ctx, pool, `'rol' || substr(md5('iam.role.admin'), 1, 17)`)
	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.roles WHERE id = $1`, adminRole),
		"роль iam.role.admin исчезла — снято больше, чем предмет kacho#1922")
	for _, verb := range []string{"list", "update", "delete"} {
		require.Equalf(t, 1, scalarInt(t, ctx, pool,
			`SELECT count(*) FROM kaname.role_verb
			  WHERE role_id = $1 AND object_type = 'iam.role' AND verb = $2`, adminRole, verb),
			"роль iam.role.admin перестала давать `%s` на iam.role — у этого глагола читатель "+
				"ЕСТЬ (записи каталога прав RoleService/Update, Delete, ListOperations), и "+
				"сужение его не касается", verb)
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: глагол жив у СОСЕДНИХ типов ───────────────
	require.Positive(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.role_verb WHERE verb = 'get' AND object_type <> 'iam.role'`),
		"глагол `get` не встречается в проекции НИ У ОДНОГО типа — сужение задело не только "+
			"iam.role, и это уже не предмет kacho#1922")
	require.Positive(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.catalog_verb
		  WHERE verb = 'get' AND live AND NOT (module = 'iam' AND resource = 'role')`),
		"живых строк словаря с глаголом `get` не осталось ни одной — снятие вышло за свой "+
			"ресурс, и вердикт выше говорил бы о поломке словаря, а не о сужении")
}

// TestRoleIamRoleGet_RetirementIsReversible — GWT-8 приёмки: снятие ОБРАТИМО, и
// оживление поднимает ТУ ЖЕ строку, а не заводит вторую.
//
// Без этого сценария «обратимо» из §3.2 приёмки — обещание, а не свойство.
// Утверждается наблюдаемое: число строк пары (модуль, ресурс, глагол) не
// меняется ни на снятии, ни на оживлении — у неё первичный ключ один.
//
// Зовётся НАСТОЯЩИЙ писатель (`UpsertVerb` через `RunInWriteTx`), а не его копия
// в пробе: копия доказывала бы свойство копии.
func TestRoleIamRoleGet_RetirementIsReversible(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const rowsOfPair = `SELECT count(*) FROM kaname.catalog_verb
	                     WHERE module = 'iam' AND resource = 'role' AND verb = 'get'`
	const livePair = rowsOfPair + ` AND live`

	// ПРЕДПОСЫЛКА: строка есть и она снята — иначе оживлять нечего, и «оживила
	// ту же строку» зеленело бы на вставке первой.
	require.Equal(t, 1, scalarInt(t, ctx, pool, rowsOfPair),
		"предпосылка сломана: строки iam.role.get нет вовсе")
	require.Zero(t, scalarInt(t, ctx, pool, livePair),
		"предпосылка сломана: строка iam.role.get жива, и снятие оживлять нечем")

	repo := kanamepg.NewCatalogWriteRepo(pool)
	var revived bool
	require.NoError(t, repo.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		var werr error
		revived, werr = w.UpsertVerb(ctx, catalog.VerbRow{
			Module: "iam", Resource: "role", Verb: "get", PerObject: true,
		})
		return werr
	}))
	require.True(t, revived, "оживление не изменило ни одной строки — снятая строка не поднялась")

	require.Equal(t, 1, scalarInt(t, ctx, pool, rowsOfPair),
		"оживление завело ВТОРУЮ строку пары: у неё первичный ключ один, и две строки "+
			"означали бы, что снятое и живое существуют одновременно")
	require.Equal(t, 1, scalarInt(t, ctx, pool, livePair),
		"строка не ожила: отметка снятия либо признак живости не сброшены")
	require.Equal(t, 1, scalarInt(t, ctx, pool, rowsOfPair+
		` AND retired_at IS NULL AND retired_reason IS NULL`),
		"оживлённая строка сохранила отметку снятия — «живая и снятая» состоянием не является")
}
