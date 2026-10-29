// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// deferred_integration_test.go — отложенная транзакция журнала (Deferred): все
// вызовы писателей ложатся ОДНИМ оператором, исход свёртки — тот же, что у
// вызовов по очереди, а нарушение порядка «копить → Flush → фиксировать» —
// отказ (kaname#617).
//
// Под `go test -short` пропускается: нужен Docker.
package fga_outbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalstmt"
)

func deferredPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return ctx, pool
}

func factRelations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, k swapKey) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT relation FROM kaname.relation_fact
		  WHERE object_type || ':' || object_id = $1 AND subject = $2 ORDER BY relation`, k.object, k.user)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return got
}

// TestDeferred_CallsOfManyWritersLayOneStatement — выдача, снятие и выдача тремя
// вызовами разных писателей на отложенной транзакции: один оператор журнала, факты —
// намеренные. Близнец — те же вызовы на обычной транзакции: три оператора, те же
// факты.
func TestDeferred_CallsOfManyWritersLayOneStatement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deferred bool
		want     int
	}{
		{"отложенная", true, 1},
		{"обычная", false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool := deferredPool(t)
			k := swapTuples("usr_def617", "prj_def617")
			seed, err := pool.Begin(ctx)
			require.NoError(t, err)
			require.NoError(t, fga_outbox.EmitWriteTx(ctx, seed, k.tuples([]string{"viewer"})))
			require.NoError(t, seed.Commit(ctx))
			probe := journalstmt.Install(t, ctx, pool)
			probe.Reset(t, ctx)

			raw, err := pool.Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Rollback(context.Background()) })
			var tx pgx.Tx = raw
			if tc.deferred {
				tx = fga_outbox.Defer(raw)
			}
			require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, k.tuples([]string{"editor"})))
			require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, k.tuples([]string{"viewer"})))
			require.NoError(t, fga_outbox.EmitJournalTx(ctx, tx, k.tuples([]string{"admin"}), nil))
			if d, ok := tx.(*fga_outbox.Deferred); ok {
				require.NoError(t, d.Flush(ctx))
			}
			require.NoError(t, tx.Commit(ctx))

			c := probe.Count(t, ctx)
			assert.Equal(t, tc.want, c.MaxPerTx, "операторов журнала в транзакции")
			assert.Equal(t, []string{"admin", "editor"}, factRelations(t, ctx, pool, k), "факты — намеренные")
		})
	}
}

// TestDeferred_OneTupleKeepsTheOrderOfItsIntents — «выдать, снять, выдать» одного
// кортежа в одной отложенной транзакции оставляет факт, «выдать, снять» — снимает:
// намерения одного кортежа ложатся в порядке записи, а не схлопываются набором.
func TestDeferred_OneTupleKeepsTheOrderOfItsIntents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []string
		want  []string
	}{
		{"выдать, снять, выдать", []string{"w", "d", "w"}, []string{"viewer"}},
		{"выдать, снять", []string{"w", "d"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool := deferredPool(t)
			k := swapTuples("usr_ord617", "prj_ord617")
			raw, err := pool.Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Rollback(context.Background()) })
			d := fga_outbox.Defer(raw)
			for _, s := range tc.steps {
				if s == "w" {
					require.NoError(t, fga_outbox.EmitWriteTx(ctx, d, k.tuples([]string{"viewer"})))
				} else {
					require.NoError(t, fga_outbox.EmitDeleteTx(ctx, d, k.tuples([]string{"viewer"})))
				}
			}
			require.NoError(t, d.Flush(ctx))
			require.NoError(t, d.Commit(ctx))
			assert.ElementsMatch(t, tc.want, factRelations(t, ctx, pool, k))
		})
	}
}

// TestDeferred_OutOfOrderUseIsRefused — строка после Flush, второй Flush, фиксация
// с неуложенными строками и точка сохранения — отказы, а не второй оператор и не
// молчаливая потеря.
func TestDeferred_OutOfOrderUseIsRefused(t *testing.T) {
	ctx, pool := deferredPool(t)
	k := swapTuples("usr_ref617", "prj_ref617")

	laid, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = laid.Rollback(context.Background()) })
	d := fga_outbox.Defer(laid)
	require.NoError(t, d.Flush(ctx))
	require.ErrorContains(t, fga_outbox.EmitWriteTx(ctx, d, k.tuples([]string{"viewer"})), "already laid")
	require.ErrorContains(t, d.Flush(ctx), "already laid")
	_, err = d.Begin(ctx)
	require.ErrorContains(t, err, "savepoint")

	unlaid, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unlaid.Rollback(context.Background()) })
	u := fga_outbox.Defer(unlaid)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, u, []clients.RelationTuple{{User: k.user, Relation: "viewer", Object: k.object}}))
	require.ErrorContains(t, u.Commit(ctx), "not laid")
	assert.Empty(t, factRelations(t, ctx, pool, k), "строка, не уложенная до фиксации, факта не дала")
}
