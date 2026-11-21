// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Внешняя серверная граница ставится ПОСЛЕ claim. Часы, захваченные в prepare
// или materialized SRF, эту границу не пройдут; проверяется сохранённая строка.
func TestNativeDeleteReceiptClockAfterClaimBoundary(t *testing.T) {
	r := writerProtocolRig(t)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nonce, id, payload := nativeDeleteReceiptClaim(t, r, tx)
	var lower, upper, actual time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&lower))
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at)
 SELECT $2,'fga.tuple.delete',$3::jsonb,kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT created_at FROM kaname.fga_outbox WHERE id=$1`, id).Scan(&actual))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&upper))
	require.False(t, actual.Before(lower), "сохранённые часы предшествуют границе после claim")
	require.False(t, actual.After(upper))
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
}

// Нужное ожидание доказывают точный blocker PID и незахваченный physical lock.
// Граница часов читается сервером держателя только после появления ожидающего.
func TestNativeDeleteReceiptClockFollowsActualReservationWait(t *testing.T) {
	for _, kind := range []string{"table-rx", "reserved-key"} {
		t.Run(kind, func(t *testing.T) {
			r := writerProtocolRig(t)
			ctx, cancel := context.WithTimeout(r.ctx, 12*time.Second)
			defer cancel()
			holder, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(holder)
			var holderPID int
			require.NoError(t, holder.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
			var next int64
			if kind == "table-rx" {
				_, err = holder.Exec(ctx, `LOCK TABLE ONLY kaname.fga_outbox IN SHARE MODE`)
			} else {
				require.NoError(t, holder.QueryRow(ctx, `SELECT last_value+CASE WHEN is_called THEN 1 ELSE 0 END FROM kaname.fga_outbox_id_seq`).Scan(&next))
				_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(1262569305,hashtext($1::bigint::text))`, next)
			}
			require.NoError(t, err)
			cfg := r.runtime.Config()
			cfg.MaxConns, cfg.MinConns = 1, 0
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			pgtest.ClosePoolAtEnd(t, pool)
			var writerPID int
			require.NoError(t, pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				tx, e := pool.Begin(ctx)
				if e != nil {
					return e
				}
				defer attestationLocksetRollback(tx)
				if _, e = tx.Exec(ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a); e != nil {
					return e
				}
				return tx.Commit(ctx)
			})
			require.Eventually(t, func() bool {
				var waiting bool
				e := r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer)) AND EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted AND
 (($3='table-rx' AND locktype='relation' AND relation='kaname.fga_outbox'::regclass AND mode='RowExclusiveLock')
 OR ($3='reserved-key' AND locktype='advisory' AND classid=1262569305::oid AND objid=hashtext($4::bigint::text)::oid AND objsubid=2 AND mode='ExclusiveLock')))`, writerPID, holderPID, kind, next).Scan(&waiting)
				return e == nil && waiting
			}, 5*time.Second, 10*time.Millisecond, "ожидание на нужном замке конкретного backend")
			var lower, upper, actual time.Time
			require.NoError(t, holder.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&lower))
			require.NoError(t, holder.Rollback(ctx))
			require.NoError(t, lifecycleResult(t, ctx, done))
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT created_at FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload=(`+forwardReceiptPayload+`)`, r.a).Scan(&actual))
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&upper))
			require.False(t, actual.Before(lower), "сохранённые часы предшествуют доказанному ожиданию")
			require.False(t, actual.After(upper))
		})
	}
}
