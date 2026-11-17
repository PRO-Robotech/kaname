// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func sevenCRUDDedicatedFactory(t *testing.T, f sevenCRUDPublicWorld) (context.Context, *kanamepg.CRUDWriters, int) {
	t.Helper()
	cfg := f.r.runtime.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(f.ctx, repo, f.r.bundle)
	require.NoError(t, err)
	full, err := repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	ctx := contract.Context(f.ctx)
	factory, err := kanamepg.NewCRUDWriters(ctx, full, f.r.bundle)
	require.NoError(t, err)
	var pid int
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	return ctx, factory, pid
}

func TestSevenCRUDGrantExpiresDuringActualParentAndJournalWaitBeforeFinalClock(t *testing.T) {
	for _, kind := range []string{"parent-row", "missing-journal-key"} {
		t.Run(kind, func(t *testing.T) {
			var expires time.Time
			f := sevenCRUDPublicFixture(t, "project.delete", "", func(w *sevenCRUDPublicWorld) {
				require.NotEmpty(t, w.authorityBinding)
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '8 seconds'
    WHERE id=$1 RETURNING expires_at`, string(w.authorityBinding)).Scan(&expires))
			})
			ctx, factory, pid := sevenCRUDDedicatedFactory(t, f)
			ctx, cancel := context.WithCancel(ctx)
			before := sevenCRUDCommandSnapshot(t, f.r)
			holder, err := f.r.runtime.Begin(ctx)
			require.NoError(t, err)
			defer holder.Rollback(context.WithoutCancel(ctx))
			defer cancel()
			holderPID := int(holder.Conn().PgConn().PID())
			var next int64
			if kind == "parent-row" {
				var id string
				require.NoError(t, holder.QueryRow(ctx, `SELECT id FROM kaname.projects WHERE id=$1 FOR UPDATE`, string(f.project.ID)).Scan(&id))
			} else {
				// Реальный shared arbitration key ещё отсутствующего journal ID.
				// Actual direct INSERT participation проверяется отдельным native TOP;
				// здесь ordinary LOGIN держит тот же ключ без фиктивного journal effect.
				require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT CASE WHEN is_called THEN last_value+1 ELSE last_value END FROM kaname.resource_journal_sequence_no_seq`).Scan(&next))
				_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(1262569304,hashtext($1::bigint::text))`, next)
				require.NoError(t, err)

			}
			type result struct {
				writer kaname.SemanticAuthorityWriter
				err    error
			}
			done := make(chan result, 1)
			go func() {
				w, e := factory.ProjectDeleteWriter(ctx, f.project.ID, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)})
				done <- result{w, e}
				if w != nil {
					<-ctx.Done()
					_ = w.Rollback(context.WithoutCancel(ctx))
				}
			}()
			waitCtx, stopWait := context.WithTimeout(ctx, 5*time.Second)
			waitTick := time.NewTicker(10 * time.Millisecond)
			blocked := false
			for !blocked && waitCtx.Err() == nil {
				if waitErr := f.r.admin.QueryRow(waitCtx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, holderPID).Scan(&blocked); waitErr != nil {
					break
				}
				if blocked {
					break
				}
				select {
				case <-waitTick.C:
				case <-waitCtx.Done():
				}
			}
			waitTick.Stop()
			stopWait()
			require.True(t, blocked, "точный worker PID ждёт именно holder")
			if kind == "missing-journal-key" {
				var keyWait, rx bool
				require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT
                 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569304::oid AND objid=hashtext($2::bigint::text)::oid AND objsubid=2 AND NOT granted),
                 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='kaname.resource_journal'::regclass AND mode='RowExclusiveLock' AND granted)`, pid, next).Scan(&keyWait, &rx))
				require.True(t, keyWait)
				require.True(t, rx)
			}

			var query string
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query))
			require.Contains(t, query, "authority_resource_prewait_v2")
			var serverAt time.Time
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&serverAt))
			require.True(t, serverAt.Before(expires), "grant обязан быть жив ПОСЛЕ доказанного настоящего ожидания")
			allowed, checkErr := f.door.Check(ctx, "user:"+f.actor, "v_delete", "project:"+string(f.project.ID))
			require.NoError(t, checkErr)
			require.True(t, allowed, "реальный native role grant жив во время ожидания")
			clockCtx, stopClock := context.WithTimeout(ctx, 10*time.Second)
			tick := time.NewTicker(10 * time.Millisecond)
			for serverAt.Before(expires) && clockCtx.Err() == nil {
				if clockErr := f.r.admin.QueryRow(clockCtx, `SELECT clock_timestamp()`).Scan(&serverAt); clockErr != nil {
					break
				}
				if !serverAt.Before(expires) {
					break
				}
				select {
				case <-tick.C:
				case <-clockCtx.Done():
				}
			}
			tick.Stop()
			stopClock()
			require.False(t, serverAt.Before(expires), "server clock достиг expiry при удерживаемом blocker")

			var stillBlocked bool
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, holderPID).Scan(&stillBlocked))
			require.True(t, stillBlocked)
			allowed, checkErr = f.door.Check(ctx, "user:"+f.actor, "v_delete", "project:"+string(f.project.ID))
			require.NoError(t, checkErr)
			require.False(t, allowed, "тот же native role grant истёк до release")
			require.NoError(t, holder.Rollback(ctx))
			select {
			case got := <-done:
				if got.writer != nil {
					_ = got.writer.Rollback(ctx)
				}
				require.Nil(t, got.writer)
				require.ErrorIs(t, got.err, iamerr.ErrPermissionDenied)
			case <-time.After(10 * time.Second):
				t.Fatal("prepared writer не завершился после release")
			}
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, f.r))
		})
	}
}
