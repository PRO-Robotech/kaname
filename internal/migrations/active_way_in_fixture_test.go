// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// active_way_in_fixture_test.go — посев фикстур схемы под инвариант «у
// действующей личности есть способ входа» (задача PRO-Robotech/kaname#608).
//
// Фикстуры этого пакета ставятся на РАЗНЫХ ревизиях цепочки (`goose.UpTo`), и
// инварианта на ранних ревизиях нет. Поэтому посев судит саму ревизию: пока
// ключа `users_active_has_a_way_in_fk` в схеме нет, он не делает ничего; когда
// ключ есть — ставит личностям `ACTIVE` этой транзакции отметку открытого пути
// (форма «после переноса», AWI-11). Отметка, а не строка пароля: строка пароля
// сделала бы откат свода способов входа невозможным по построению (его страж
// отказывает на любой строке способа), и пробы откатов мерили бы посев, а не
// предмет.

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// wayInGuardedSQL — отметка открытого пути личностям `ACTIVE` текущей
// транзакции без строки пароля, если инвариант в схеме уже стоит.
const wayInGuardedSQL = `
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_active_has_a_way_in_fk') THEN
    EXECUTE $q$
      UPDATE kaname.users u SET recovery_path_opened_at = now()
       WHERE u.xmin = pg_current_xact_id()::xid
         AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
         AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
                          WHERE m.user_id = u.id AND m.kind = 'password')$q$;
  END IF;
END
$$`

// seedWayIn — посев перед фиксацией транзакции фикстуры.
func seedWayIn(t testing.TB, tx *sql.Tx) {
	t.Helper()
	_, err := tx.Exec(wayInGuardedSQL)
	require.NoError(t, err, "посев отметки открытого пути личностей фикстуры (kaname#608)")
}

// execWithWayIn исполняет ОДИН оператор фикстуры, заводящий либо
// активирующий личность, в своей транзакции с посевом отметки открытого пути
// перед фиксацией: оператор, исполненный вне транзакции, фиксировался бы раньше,
// чем посев успел бы лечь. Исход — как у `db.Exec`.
func execWithWayIn(t testing.TB, db *sql.DB, query string, args ...any) (sql.Result, error) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(wayInGuardedSQL); err != nil {
		return nil, err
	}
	return res, tx.Commit()
}
