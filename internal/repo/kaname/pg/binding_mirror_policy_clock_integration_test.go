// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func mirrorRequireCommittedViewer(t *testing.T, ctx context.Context, r protocolRig, binding domain.AccessBindingID, uid, object string) {
	t.Helper()
	for _, relation := range []string{"viewer", "v_get"} {
		require.True(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, relation, "vpc_network:"+object), "actual committed ledger: %s", relation)
	}
	var viewer bool
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='vpc_network' AND object_id=$1 AND subject=$2 AND relation='viewer')`, object, "user:"+uid).Scan(&viewer))
	require.True(t, viewer, "настоящий relation_fact fold обязателен, одной v_get эмиссии недостаточно")
	allow, err := (delegationNativeDoor{r}).Check(ctx, "user:"+uid, "v_get", "vpc_network:"+object)
	require.NoError(t, err)
	if !allow {
		mirrorLogPublicVGet(t, ctx, r, binding, uid, object, allow)
	}
	require.True(t, allow)
}

func TestBindingMirrorPolicyEpochWaitPrecedesFinalClock(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "complete_viewer_control"
		if blocked {
			name = "actual_user_policy_epoch_wait"
		}
		t.Run(name, func(t *testing.T) {
			r, binding, object, uid := mirrorLocalityFixture(t)
			ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
			defer cancel()
			trace := &stageLegacyClockTrace{lockSQL: kanamepg.LockBindingsSQL, before: make(chan uint32, 1)}
			// Tracer подключён ДО FULL activation; factory с nil не заменяет FULL repo.
			cfg := r.runtime.Config()
			cfg.ConnConfig.Tracer = trace
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			r.runtime = pool
			r.repo = kanamepg.New(pool, nil)
			setup := r
			setup.ctx = ctx
			r.repo, _ = fullContractActivate(t, setup)
			require.NoError(t, lifecycleOwner(r).ValidateFullAuthorityBundle(ctx, r.bundle))
			kanamepg.BindingMirrorViewerStageForTest(t, ctx, r.repo, r.bundle, binding, r.a, uid, object)
			require.False(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "viewer", "vpc_network:"+object), "RR probe не применяет эффекты")
			// Проба завершена; дальше счётчик принадлежит только actual worker attempt.
			trace.mu.Lock()
			trace.state = stageLegacyClockState{}
			trace.stages.Store(0)
			trace.mu.Unlock()
			engine := bindingStageEngine(t, r, nil)
			if !blocked {
				require.NoError(t, engine.ReconcileBinding(ctx, binding))
				mirrorRequireCommittedViewer(t, ctx, r, binding, uid, object)
				return
			}
			blocker, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer mirrorLocalityRollback(t, blocker)
			var revision int64
			require.NoError(t, blocker.QueryRow(ctx, `SELECT revision FROM kaname.authority_policy_epoch WHERE key=$1 FOR UPDATE`, "user:"+uid).Scan(&revision))
			blockerPID := blocker.Conn().PgConn().PID()
			done := make(chan error, 1)
			joined := make(chan struct{})
			go func() { defer close(joined); done <- engine.ReconcileBinding(ctx, binding) }()
			defer func() {
				cancel()
				mirrorLocalityRollback(t, blocker)
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Error("policy wait worker не завершился после cleanup")
				}
			}()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			var waiting stageLegacyClockState
			for {
				before := trace.snapshot()
				if before.attempt > 0 && before.pid != 0 {
					var actualBlock bool
					require.NoError(t, r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1))`, before.pid, blockerPID).Scan(&actualBlock))
					if actualBlock {
						waiting = trace.snapshot()
						require.Equal(t, before.attempt, waiting.attempt)
						require.Equal(t, before.pid, waiting.pid)
						break
					}
				}
				select {
				case err = <-done:
					t.Fatalf("не достигнут настоящий policy row wait: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
				}
			}
			require.False(t, waiting.invalid)
			require.Equal(t, int32(1), waiting.attempt)
			// Положительный pg_blocking_pids доказывает реальное ожидание именно
			// неизменённой user epoch строки. Два завершённых lock означают поздний wait.
			if waiting.epochCompleted >= 2 {
				t.Errorf("policy epoch lock получен после final clock: pid=%d blocker=%d attempt=%d completed=%d", waiting.pid, blockerPID, waiting.attempt, waiting.epochCompleted)
			}
			// Policy wait может быть внутри первого epoch SQL: TraceQueryEnd ещё
			// не выполнился, поэтому завершённых SQL ноль. Между первым и вторым
			// SQL допустима единица; два завершения означают wait после final clock.
			require.Contains(t, []int{0, 1}, waiting.epochCompleted, "policy wait должен предшествовать завершению final epoch SQL")
			var unchanged int64
			require.NoError(t, blocker.QueryRow(ctx, `SELECT revision FROM kaname.authority_policy_epoch WHERE key=$1`, "user:"+uid).Scan(&unchanged))
			require.Equal(t, revision, unchanged, "blocker не меняет source/revision")
			require.NoError(t, blocker.Commit(ctx))
			select {
			case err = <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			finished := trace.snapshot()
			require.False(t, finished.invalid)
			require.Equal(t, waiting.pid, finished.pid)
			require.Equal(t, waiting.attempt, finished.attempt)
			require.Equal(t, 2, finished.epochCompleted)
			require.Equal(t, int32(1), trace.stages.Load(), "без source mutation повторная попытка не скрывает поздний wait")
			mirrorRequireCommittedViewer(t, ctx, r, binding, uid, object)
		})
	}
}
