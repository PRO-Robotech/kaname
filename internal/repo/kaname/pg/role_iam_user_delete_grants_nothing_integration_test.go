// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_iam_user_delete_grants_nothing_integration_test.go — глагол `delete` на
// `iam.user` больше НЕ ПОПАДАЕТ в проекцию, которую читает вердикт.
//
// # Предмет (#1189)
//
// Тип `iam_user` объявлял глагол `v_delete`, и читателя у него не было ни одного:
// снятие строки личности спрашивает `identity_remover` (#1131), правку записи —
// `record_writer`, запрет и его снятие — `identity_suspender` (#1102). Каталог
// прав не нёс ни одной записи с парой (`iam_user`, `v_delete`), и явного Check в
// хендлере тоже не было.
//
// Наблюдаемая цена этого была не «лишняя строка в модели». Правило с подстановкой
// (`verbs: ["*"]`) разворачивается в набор ТИПА — значит выдача такой роли
// материализовала пару `(iam.user, delete)` в проекции `role_verb`, которую читает
// вердикт. Право, о котором никто никогда не спросит: выдача его арендатору не
// давала ничего, и узнать это арендатор мог только по последствиям. Замер перед
// снятием: таких ролей на свежепосеянной базе было ЧЕТЫРЕ.
//
// ВТОРОЕ СЛЕДСТВИЕ, и оно тяжелее первого. `delete` был ПОСЛЕДНИМ глаголом
// административного яруса у этого типа, поэтому роль `iam.user.admin` после снятия
// материализует ярус наблюдателя и ровно те же два глагола, что `iam.user.view`, —
// дубликат под именем, обещающим администрирование. Она выведена из обращения той
// же работой, как `iam.user.edit` была выведена вместе со снятием `v_update`
// (#1128).
//
// # Что здесь утверждается — СТРОКИ, а не объявление
//
// «Отношения нет в модели» держат гейты соседнего пакета (`authzmap`). Здесь
// вердикт выносится по тому, что лежит в БД после наката ВСЕХ миграций и
// самолечащего посева, — то есть по тому, что увидит вопрос о доступе.
//
// # Почему пара обязательна
//
// «Строк нет» истинно и на пустой базе, и на не доехавшем посеве, и на сломанном
// запросе. Поэтому рядом стоят два положительных контроля: роль `iam.user.admin`
// обязана ОСТАТЬСЯ непустой (она продолжает давать всё, что тип объявляет), а
// глагол `delete` обязан остаться живым у СОСЕДНИХ типов — иначе «на iam.user его
// нет» читалось бы как «его нет нигде», то есть как поломка проекции, а не как
// сужение набора одного типа.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestRoleIamUserDelete_GrantsNothingAndIsNoLongerProjected — вердикт по
// закоммиченным строкам после наката всех миграций.
func TestRoleIamUserDelete_GrantsNothingAndIsNoLongerProjected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не `defer pool.Close()`: отложенное закрытие ждёт
	// соединение, которого проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт всего пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	// Проекция системных ролей самолечащая. Зовём её явно: иначе «ноль пар с
	// глаголом delete» был бы получен из того, что проекцию не считал никто, а не
	// из сужения набора типа.
	require.NoError(t, bootSeedRuleSides(ctx, pool))

	// ── Перепись ДО вердикта ────────────────────────────────────────────────
	totalRoles := scalarInt(t, ctx, pool, `SELECT count(*) FROM kaname.roles`)
	totalVerbs := scalarInt(t, ctx, pool, `SELECT count(*) FROM kaname.role_verb`)
	onIdentity := scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.role_verb WHERE object_type = 'iam.user'`)
	t.Logf("осмотрено: ролей=%d, строк проекции роль→глагол=%d, из них на iam.user=%d",
		totalRoles, totalVerbs, onIdentity)
	require.NotZero(t, totalRoles, "предпосылка сломана: в посеве нет ни одной роли")
	require.NotZero(t, totalVerbs,
		"предпосылка сломана: проекция роль→глагол пуста, и «ноль пар с delete» был бы даром")
	require.NotZero(t, onIdentity,
		"предпосылка сломана: на iam.user проекция не даёт НИ ОДНОЙ пары — тогда отсутствие "+
			"именно `delete` не означает ничего")

	// ── Предмет ─────────────────────────────────────────────────────────────
	//
	// Находка НАЗЫВАЕТ роли поимённо: «строк 4» не говорит, какие выдачи стали бы
	// мёртвым правом, и разбирать пришлось бы отдельным запросом.
	offenders := scalarString(t, ctx, pool,
		`COALESCE((SELECT string_agg(r.name, ', ' ORDER BY r.name)
		             FROM kaname.role_verb rv
		             JOIN kaname.roles r ON r.id = rv.role_id
		            WHERE rv.object_type = 'iam.user' AND rv.verb = 'delete'), '')`)
	require.Emptyf(t, offenders,
		"проекция всё ещё даёт `delete` на iam.user — роли: %s. Глагол снят с типа, значит правило, "+
			"назвавшее его (в том числе подстановкой `*`), не должно давать ничего: читателя "+
			"у пары (iam_user, v_delete) нет ни одного, снятие строки личности спрашивает "+
			"identity_remover (#1131)", offenders)

	// ── СЛЕДСТВИЕ: роль `iam.user.admin` ВЫВЕДЕНА ИЗ ОБРАЩЕНИЯ ──────────────
	//
	// Её правило — подстановка `*`, разворачиваемая в набор ТИПА. С набором
	// `[get list]` она материализует ярус НАБЛЮДАТЕЛЯ и те же два глагола, что
	// соседняя `iam.user.view`, — то есть стала её дубликатом под именем, которое
	// обещает администрирование. Ярус, которому нечем быть, в посеве существовать не
	// должен (гейт паритета ярусов), поэтому роль снята той же работой.
	adminRole := scalarString(t, ctx, pool, `'rol' || substr(md5('iam.user.admin'), 1, 17)`)
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.roles WHERE id = $1`, adminRole),
		"роль iam.user.admin обязана быть снята: последний глагол административного яруса "+
			"снят с типа, поэтому её имя обещает ярус, которого материализация не даст")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.access_bindings WHERE role_id = $1`, adminRole),
		"привязка на снятую роль остаться не может")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: семейство осталось ПРАВОМ ────────────────
	// Иначе «строк нет» читалось бы как «снесли всё семейство», а не как вывод
	// одной роли, чьё имя перестало быть исполнимым.
	viewRole := scalarString(t, ctx, pool, `'rol' || substr(md5('iam.user.view'), 1, 17)`)
	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.roles WHERE id = $1`, viewRole),
		"роль iam.user.view исчезла — снято больше, чем предмет #1189: чтение своих людей "+
			"остаётся правом аккаунта")
	for _, verb := range []string{"get", "list"} {
		require.Equalf(t, 1, scalarInt(t, ctx, pool,
			`SELECT count(*) FROM kaname.role_verb
			  WHERE role_id = $1 AND object_type = 'iam.user' AND verb = $2`, viewRole, verb),
			"роль iam.user.view перестала давать `%s` на iam.user — у этого глагола читатель "+
				"ЕСТЬ (UserService/Get, UserService/ListOperations), и сужение его не касается", verb)
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: глагол жив у СОСЕДНИХ типов ───────────────
	require.Positive(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kaname.role_verb WHERE verb = 'delete' AND object_type <> 'iam.user'`),
		"глагол `delete` не встречается в проекции НИ У ОДНОГО типа — сужение задело не только "+
			"iam.user, и это уже не предмет #1189")
}
