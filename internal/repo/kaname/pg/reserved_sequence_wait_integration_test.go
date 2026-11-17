// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
	"time"
)

// Отдельно доказываем participation actual INSERT и RX-before-key. Consumer
// обычного FGA writer может задержать prepared writer ещё раньше; это не
// выдаётся за ожидание final preflight на самом surrogate key.
func TestSequenceDirectInsertHoldsRXBeforeSharedJournalAndFGAKey(t *testing.T) {
	for _, table := range []string{"resource_journal", "fga_outbox"} {
		t.Run(table, func(t *testing.T) {
			r := writerProtocolRig(t)
			namespace := 1262569304
			if table == "fga_outbox" {
				namespace = 1262569305
			}
			const key int64 = 9223372036854775700
			holder, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer holder.Rollback(context.WithoutCancel(r.ctx))
			_, err = holder.Exec(r.ctx, `SELECT pg_advisory_xact_lock($1,hashtext($2::bigint::text))`, namespace, key)
			require.NoError(t, err)
			cfg := r.runtime.Config()
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			var pid int
			require.NoError(t, pool.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				tx, e := pool.Begin(ctx)
				if e != nil {
					return e
				}
				defer tx.Rollback(context.WithoutCancel(ctx))
				if table == "resource_journal" {
					_, e = tx.Exec(ctx, `INSERT INTO kaname.resource_journal(sequence_no,resource_kind,resource_id,project_id,scope,event_type,payload)
     VALUES($1,'account',$2,'','[]'::jsonb,'UPDATED',jsonb_build_object('id',$2::text))`, key, r.a)
				} else {
					// Canonical fold намеренно не материализует v_*: не создаём ложное право.
					_, e = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at)
     VALUES($1,'fga.tuple.write',jsonb_build_object('object','account:'||$2::text,'user','user:usr_sequence_probe','relation','v_get'),now())`, key, r.a)
				}
				return e
			})
			require.Eventually(t, func() bool {
				var blocked bool
				require.NoError(t, r.admin.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, int(holder.Conn().PgConn().PID())).Scan(&blocked))
				return blocked
			}, 5*time.Second, 10*time.Millisecond)
			var rx, keyWait bool
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT
   EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation=to_regclass('kaname.'||$2) AND mode='RowExclusiveLock' AND granted),
   EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=$3::oid AND objid=hashtext($4::bigint::text)::oid AND objsubid=2 AND NOT granted)`, pid, table, namespace, key).Scan(&rx, &keyWait))
			require.True(t, rx)
			require.True(t, keyWait)
			require.NoError(t, holder.Rollback(ctx))
			require.NoError(t, lifecycleResult(t, ctx, done))
			var present bool
			column := "sequence_no"
			if table == "fga_outbox" {
				column = "id"
			}
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.`+table+` WHERE `+column+`=$1)`, key).Scan(&present))
			require.False(t, present, "probe всегда откатывает actual INSERT")
		})
	}
}

func TestClusterFullPreparedSequenceWaitPrecedesFinalClockForLiveAndExpiredActor(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expire], func(t *testing.T) {
			f := newClusterParticipantFixture(t, false)
			interval := "1 hour"
			if expire {
				interval = "8 seconds"
			}
			var expires time.Time
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=clock_timestamp()+$2::interval WHERE subject_type='user' AND subject_id=$1 RETURNING granted_until`, f.actor, interval).Scan(&expires))
			_, _ = fullContractActivate(t, f.r)
			trace := &finalDecisionTrace{}
			cfg := f.r.runtime.Config()
			cfg.MaxConns = 1
			cfg.ConnConfig.Tracer = trace
			pool, err := pgxpool.NewWithConfig(f.r.ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			repo := kanamepg.New(pool, nil)
			contract, err := kanamepg.NewFullWriterContract(f.r.ctx, repo, f.r.bundle)
			require.NoError(t, err)
			full, err := repo.WithFullWriterContract(contract)
			require.NoError(t, err)
			participant, err := kanamepg.NewClusterAdminParticipant(f.r.ctx, full, f.r.bundle)
			require.NoError(t, err)
			clusterapp.NewHandler(nil, f.grant, f.revoke, nil).WithAdminTxBeginner(participant)
			var pid int
			require.NoError(t, pool.QueryRow(f.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			var next int64
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT CASE WHEN is_called THEN last_value+1 ELSE last_value END FROM kaname.fga_outbox_id_seq`).Scan(&next))
			holder, err := f.r.runtime.Begin(f.r.ctx)
			require.NoError(t, err)
			defer holder.Rollback(context.WithoutCancel(f.r.ctx))
			_, err = holder.Exec(f.r.ctx, `SELECT pg_advisory_xact_lock(1262569305,hashtext($1::bigint::text))`, next)
			require.NoError(t, err)
			before := sevenCRUDCommandSnapshot(t, f.r)
			ctx, cancel := context.WithCancel(f.ctx())
			defer cancel()
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, false) })
			require.Eventually(t, func() bool {
				var blocked bool
				require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, int(holder.Conn().PgConn().PID())).Scan(&blocked))
				return blocked
			}, 5*time.Second, 10*time.Millisecond)
			var query string
			var keyWait bool
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT query,EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569305::oid AND objid=hashtext($2::bigint::text)::oid AND objsubid=2 AND NOT granted) FROM pg_stat_activity WHERE pid=$1`, pid, next).Scan(&query, &keyWait))
			require.Contains(t, query, "authority_cluster_admin_preflight_v4")
			require.True(t, keyWait)
			require.Zero(t, trace.preflights.Load())
			var at time.Time
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at))
			require.True(t, at.Before(expires), "источник жив после подтверждённого exact key wait")
			if expire {
				require.Eventually(t, func() bool {
					require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at))
					return !at.Before(expires)
				}, 10*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, holder.Rollback(ctx))
			err = lifecycleResult(t, ctx, done)
			if expire {
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				f.assertAbsent(t)
				require.Equal(t, before, sevenCRUDCommandSnapshot(t, f.r))
			} else {
				require.NoError(t, err)
				clusterFinalActive(t, f, true)
			}
		})
	}
}
