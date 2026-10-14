// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// active_way_in_fixture_test.go — посев фикстур под инвариант «у действующей
// личности есть способ входа» (задача PRO-Robotech/kaname#608, приёмка
// `active-identity-has-a-way-in.md` §1 «радиус», §4.1 п. 5).
//
// Отложенный ключ `users_active_has_a_way_in_fk` отвергает фиксацию транзакции,
// оставившей личность `ACTIVE` без строки пароля и без открытого пути
// восстановления. Фикстура не снисходительнее продукта: она заводит то, что
// заводит продукт, — строку пароля той же транзакцией, что строку личности
// (как регистрация). Материал строки — фиксированное значение, которым не
// войти: пробы, которым нужен вход, заводят пароль сами продуктом.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// wayInFixtureSQL — строка пароля каждой личности `ACTIVE`, которую ЭТА
// транзакция завела либо изменила и у которой нет ни строки пароля, ни
// открытого пути. Узнаёт личность по `xmin` строки — то есть по самой
// транзакции, — поэтому фикстуре не нужно перечислять идентификаторы.
const wayInFixtureSQL = `
	INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
	SELECT u.id, 'password', 'fixture-password-row-without-a-known-password'
	  FROM kaname.users u
	 WHERE u.xmin = pg_current_xact_id()::xid
	   AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
	   AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
	                    WHERE m.user_id = u.id AND m.kind = 'password')`

// wayInExecer — исполнитель оператора открытой транзакции фикстуры.
type wayInExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// seedOpenPath — для проб, чей предмет сама строка способа входа: личностям
// `ACTIVE` этой транзакции ставится отметка открытого пути (форма «после
// переноса», AWI-11), а строку пароля проба заводит сама.
const seedOpenPathSQL = `
	UPDATE kaname.users u SET recovery_path_opened_at = now()
	 WHERE u.xmin = pg_current_xact_id()::xid
	   AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
	   AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
	                    WHERE m.user_id = u.id AND m.kind = 'password')`

// withWayIn оборачивает ОДИН оператор вставки строк личностей, исполняемый вне
// явной транзакции, так, что строка пароля ложится тем же оператором:
// `WITH u AS (<вставка> RETURNING …) INSERT INTO <способы> SELECT … FROM u`.
func withWayIn(insertUsers string) string {
	return "WITH way_in_people AS (" + strings.TrimSpace(insertUsers) + " RETURNING id, invite_status) " +
		"INSERT INTO kaname.user_login_methods (user_id, kind, verifier) " +
		"SELECT id, 'password', 'fixture-password-row-without-a-known-password' FROM way_in_people " +
		"WHERE invite_status = 'ACTIVE'"
}

// seedWayIn заводит строки пароля личностям транзакции перед её фиксацией.
func seedWayIn(t testing.TB, ctx context.Context, tx wayInExecer) {
	t.Helper()
	_, err := tx.Exec(ctx, wayInFixtureSQL)
	require.NoError(t, err, "посев строки пароля личностей фикстуры (kaname#608)")
}

// seedOpenPath ставит отметку открытого пути личностям транзакции перед её
// фиксацией (см. seedOpenPathSQL).
func seedOpenPath(t testing.TB, ctx context.Context, tx wayInExecer) {
	t.Helper()
	_, err := tx.Exec(ctx, seedOpenPathSQL)
	require.NoError(t, err, "отметка открытого пути личностей фикстуры (kaname#608)")
}
