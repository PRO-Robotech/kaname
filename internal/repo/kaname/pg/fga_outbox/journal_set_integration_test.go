// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// journal_set_integration_test.go — набор транзакции ложится в журнал одним оператором
// в порядке (объект, субъект, отношение) до последнего кортежа.
//
// ПРЕДМЕТ. Триггер журнала берёт блокировку строки факта в порядке строк. Набор, в
// котором у одной пары субъект–объект есть и выдачи, и отзывы, нельзя положить двумя
// строками-группами: группа «выдано» целиком легла бы раньше группы «снято», и порядок
// по отношению внутри пары был бы нарушен ровно там, где её делят две транзакции.
// Такая пара раскладывается по строке на отношение; пара одного рода остаётся одной
// строкой-набором (её форма — TestFGAOutboxEmitter_SetInsertPreservesPerKeyOrder).
//
// Кортеж в обоих списках сразу отвергается: порядок «выдать — снять» и «снять — выдать»
// дают разный исход, а один оператор порядка между ними не несёт.
//
// Skipped under `go test -short` (needs Docker).
package fga_outbox_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestEmitJournalTx_MixedPairFoldsInRelationOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	const user = "user:usr_journal"
	mixed, plain := "account:acc_journal_mixed", "account:acc_journal_plain"
	writes := []clients.RelationTuple{
		{User: user, Relation: "viewer", Object: mixed},
		{User: user, Relation: "admin", Object: mixed},
		// Пара одного рода — положительный близнец: она остаётся одной строкой-набором.
		{User: user, Relation: "viewer", Object: plain},
		{User: user, Relation: "admin", Object: plain},
	}
	deletes := []clients.RelationTuple{{User: user, Relation: "editor", Object: mixed}}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	require.NoError(t, fga_outbox.EmitJournalTx(ctx, tx, writes, deletes))
	require.NoError(t, tx.Commit(ctx))

	rowsOf := func(object string) []string {
		t.Helper()
		rows, err := pool.Query(ctx, `
			SELECT event_type || '|' ||
			       coalesce((SELECT string_agg(r, '+') FROM jsonb_array_elements_text(payload->'relations') AS t(r)),
			                payload->>'relation')
			  FROM kaname.fga_outbox
			 WHERE payload->>'user' = $1 AND payload->>'object' = $2
			 ORDER BY id ASC`, user, object)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			require.NoError(t, rows.Scan(&s))
			out = append(out, s)
		}
		require.NoError(t, rows.Err())
		return out
	}
	require.Equal(t, []string{
		"fga.tuple.write|admin",
		"fga.tuple.delete|editor",
		"fga.tuple.write|viewer",
	}, rowsOf(mixed), "пара с выдачами и отзывами ложится по отношению — строкой на отношение")
	require.Equal(t, []string{"fga.tuple.write|admin+viewer"}, rowsOf(plain),
		"пара одного рода остаётся одной строкой-набором")

	// Прямой факт сложен из набора: выданное есть, снятого нет.
	var granted int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type='account' AND object_id='acc_journal_mixed' AND subject=$1
		   AND relation IN ('admin','viewer')`, user).Scan(&granted))
	require.Equal(t, 2, granted)
}

func TestEmitJournalTx_RefusesATupleBothGrantedAndRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	both := clients.RelationTuple{User: "user:usr_journal_both", Relation: "viewer", Object: "account:acc_journal_both"}
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	err = fga_outbox.EmitJournalTx(ctx, tx, []clients.RelationTuple{both}, []clients.RelationTuple{both})
	require.ErrorContains(t, err, "both granted and revoked")

	var n int
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user' = $1`, both.User).Scan(&n))
	require.Zero(t, n, "отвергнутый набор не кладёт ни одной строки")
	// Соединение транзакции возвращается в пул ДО закрытия пула: иначе закрытие ждёт его.
	require.NoError(t, tx.Rollback(ctx))
}
