// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// passwordless_fixture_integration_test.go — «Дано» личности без строки
// способа «пароль» для проб полосы (Ф5-34, Ф13-19, FP-01…FP-11).
//
// После пары `active-identity-has-a-way-in.md` (kaname#608, AWI-01) личность
// ACTIVE без пароля фиксируется базой ТОЛЬКО с отметкой открытого пути
// восстановления (`users_active_has_a_way_in_fk`, отложенный ключ). Продукт
// такую строку не производит; её форма — «после переноса» (AWI-11), и посев
// приводит личность к ней ОДНОЙ транзакцией прямой записи: снять строку пароля
// и поставить отметку. Подтверждённость адреса посев не трогает — её «Дано»
// каждой пробы называет само.
package loginlanehttp_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// seedPasswordless снимает строку «пароль» личности и ставит отметку открытого
// пути одной транзакцией. Строка пароля обязана быть ровно одна — иначе посев
// не выполнился, а не проба покраснела.
func seedPasswordless(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user domain.UserID) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие строки «пароль»")
	require.EqualValues(t, 1, tag.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка «пароль» снята записью")
	tag, err = tx.Exec(ctx, `UPDATE kaname.users SET recovery_path_opened_at = now() WHERE id = $1`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка открытого пути")
	require.EqualValues(t, 1, tag.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): личность для отметки найдена")
	require.NoError(t, tx.Commit(ctx), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев формы «после переноса» отвергнут")
}
