// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// role_iam_user_edit_retired_integration_test.go — роль `iam.user.edit` выведена
// из обращения, и её соседи по каталогу — НЕТ.
//
// # Предмет (#1128)
//
// Роль объявляла один глагол — `update` на `iam.user`. Тем же изменением этот
// глагол снят с типа `iam_user`: правку содержимого строки личности спрашивает
// `record_writer`, запрет и его снятие — `identity_suspender` (#1102), и читателя
// у глагола не осталось ни одного.
//
// После снятия роль не даёт НИЧЕГО: набор глаголов правила сверяется с набором
// ТИПА в одной точке, глагол вне набора отбрасывается, и выводимое «правка влечёт
// удаление» вместе с ним отпадает. Роль, которая ничего не даёт, но предлагается
// как «Edit User», обещает не то, что делает.
//
// # Почему пара обязательна
//
// «Строк нет» истинно и на пустой базе, и на не доехавшем посеве, и на сломанном
// запросе. Поэтому рядом стоит соседняя роль того же семейства — она обязана
// ОСТАТЬСЯ: `iam.user.view` даёт чтение (у `get`/`list` читатели есть).
//
// Здесь стояла ВТОРАЯ соседка — `iam.user.admin`, «подстановка разворачивается в
// набор типа, поэтому роль продолжает давать всё, что тип объявляет». Довод был
// верен и перестал им быть: снятие `v_delete` (#1189) оставило типу только чтение,
// роль стала дубликатом `view` под именем, обещающим администрирование, и выведена
// из обращения той же работой. Контроль перепривязан к пережившей роли — привязка
// к снимаемому предмету истекает вместе с ним.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// TestRoleIamUserEdit_RetiredWhileItsNeighboursRemain — вердикт по закоммиченным
// строкам после наката всех миграций.
func TestRoleIamUserEdit_RetiredWhileItsNeighboursRemain(t *testing.T) {
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

	// Селекторы системных ролей проецируются самолечащим посевом. Зовём его явно:
	// иначе «ноль селекторов у снятой роли» был бы получен из того, что их не
	// проецировал никто, а не из снятия.
	require.NoError(t, bootSeedRuleSides(ctx, pool))

	// ── Перепись ДО вердикта ────────────────────────────────────────────────
	totalRoles := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.roles`)
	totalVerbs := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.role_verb`)
	t.Logf("осмотрено: ролей=%d, строк проекции роль→глагол=%d", totalRoles, totalVerbs)
	require.NotZero(t, totalRoles, "предпосылка сломана: в посеве нет ни одной роли")
	require.NotZero(t, totalVerbs,
		"предпосылка сломана: проекция роль→глагол пуста, и «ноль у снятой роли» был бы даром")

	retired := scalarString(t, ctx, pool, `'rol' || substr(md5('iam.user.edit'), 1, 17)`)

	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, retired),
		"роль iam.user.edit обязана быть снята: её единственный глагол снят с типа, "+
			"поэтому выдача этой роли материализует ноль кортежей, а имя обещает правку")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE role_id = $1`, retired),
		"привязка на снятую роль остаться не может")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, retired),
		"селекторы снятой роли обязаны уйти вместе с ней")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, retired),
		"проекция роль→глагол снятой роли обязана уйти вместе с ней")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: соседи остались и остались НЕПУСТЫМИ ────────
	for _, n := range []struct{ name, why string }{
		{"iam.user.view", "чтение записи человека остаётся правом аккаунта: у `get`/`list` читатели есть"},
	} {
		id := scalarString(t, ctx, pool, `'rol' || substr(md5('`+n.name+`'), 1, 17)`)
		require.Equalf(t, 1, scalarInt(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, id),
			"роль %s исчезла — снято больше, чем предмет #1128 (%s)", n.name, n.why)
		require.Positivef(t, scalarInt(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, id),
			"роль %s не даёт ни одного глагола — она осталась строкой, но перестала быть правом (%s)",
			n.name, n.why)
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: глагол `update` жив у СОСЕДНЕГО типа ──────
	// Иначе «на iam.user его нет» читалось бы как «его нет нигде», то есть как
	// поломка проекции, а не как сужение набора одного типа.
	require.Positive(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE verb = 'update' AND object_type <> 'iam.user'`),
		"глагол `update` не встречается в проекции НИ У ОДНОГО типа — сужение задело не только "+
			"iam.user, и это уже не предмет #1128")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE verb = 'update' AND object_type = 'iam.user'`),
		"проекция всё ещё даёт `update` на iam.user — глагол снят с типа, значит правило, "+
			"назвавшее его, не должно давать ничего")
}
