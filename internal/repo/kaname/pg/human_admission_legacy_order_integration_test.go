// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

type legacyAdmissionRollback interface {
	Rollback(context.Context) error
}

// Проверка наблюдает реальные backend locks и свободную строку личности,
// а не наличие нужного SQL в Go-тексте. Один runtime connection доказывает,
// что отменённое открытие возвращает pool slot, а TX не удерживает compat.
func TestHumanAdmissionLegacyCompatibilityPrecedesPersonAndCancels(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требуется PostgreSQL")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	uid := mustSeedUser(t, ctx, pool, "legacy-admission-order")
	trace := &finalDecisionTrace{}
	cfg := pool.Config()
	cfg.MaxConns = 1
	cfg.ConnConfig.Tracer = trace
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	store := kanamepg.NewRegistrationStore(runtime)
	recovery, err := kanamepg.NewRecoveryCompletionStore(runtime, userapp.ActivateInviteForLane)
	require.NoError(t, err)
	for _, door := range []struct {
		name   string
		person bool
		open   func(context.Context) (legacyAdmissionRollback, error)
	}{
		{"registration", false, func(ctx context.Context) (legacyAdmissionRollback, error) { return store.Writer(ctx) }},
		{"verification", true, func(ctx context.Context) (legacyAdmissionRollback, error) { return store.VerificationWriter(ctx, uid) }},
		{"email_change", true, func(ctx context.Context) (legacyAdmissionRollback, error) { return store.EmailChangeWriter(ctx, uid) }},
		{"recovery", true, func(ctx context.Context) (legacyAdmissionRollback, error) {
			return recovery.RecoveryCompletionWriter(ctx, uid)
		}},
	} {
		t.Run(door.name, func(t *testing.T) {
			for _, phase := range []struct {
				name           string
				person, cancel bool
			}{
				{"compat_cancel", false, true},
				{"compat_release", false, false},
				{"person_cancel", true, true},
			} {
				if phase.person && !door.person {
					continue // Регистрация создаёт новую личность, существующую не запирает.
				}
				t.Run(phase.name, func(t *testing.T) {
					legacyAdmissionWaitProbe(t, pool, runtime, trace, uid, door.open, phase.person, phase.cancel)
				})
			}
		})
	}
}

func legacyAdmissionWaitProbe(t *testing.T, pool, runtime *pgxpool.Pool, trace *finalDecisionTrace, uid domain.UserID, open func(context.Context) (legacyAdmissionRollback, error), personWait, cancelWait bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(holder)
	var holderPID int
	require.NoError(t, holder.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
	if personWait {
		var held string
		require.NoError(t, holder.QueryRow(ctx, `SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE`, string(uid)).Scan(&held))
		require.Equal(t, string(uid), held)
	} else {
		_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(1262569292,0)`)
		require.NoError(t, err)
	}
	waiting, stop := context.WithCancel(ctx)
	type result struct {
		opening, rollback error
	}
	done := make(chan result, 1)
	joined := false
	defer func() {
		stop()
		if !joined {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Error("legacy admission не завершился после отмены")
			}
		}
	}()
	go func() {
		w, err := open(waiting)
		var rollback error
		if err == nil {
			cleanup, finish := context.WithTimeout(context.WithoutCancel(waiting), 5*time.Second)
			rollback = w.Rollback(cleanup)
			finish()
		}
		done <- result{opening: err, rollback: rollback}
	}()
	require.Eventually(t, func() bool {
		pid := int(trace.pid.Load())
		if pid == 0 {
			return false
		}
		var blocked bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.wait_event_type='Lock'
 AND $2::integer=ANY(pg_blocking_pids(a.pid))
 AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory'
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=1262569292::oid AND l.objid=0::oid AND l.objsubid=2
   AND l.mode='ExclusiveLock' AND l.granted=$3::boolean)
 AND ((NOT $3::boolean AND position('SELECT pg_advisory_xact_lock(1262569292,0)' in a.query)>0)
   OR ($3::boolean AND position('FROM kaname.users WHERE id = $1' in a.query)>0
       AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
         AND l.locktype IN ('transactionid','tuple')))))`, pid, holderPID, personWait).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "точный compat/person wait должен сохранять порядок fence→person")
	waiterPID := int(trace.pid.Load())
	if !personWait {
		// Если opener успел взять person раньше compat, чужой NOWAIT откажет.
		require.NoError(t, personRowLockAttempt(t, ctx, pool, string(uid), "UPDATE"))
	}
	if cancelWait {
		stop()
	} else {
		require.NoError(t, holder.Rollback(ctx))
	}
	select {
	case got := <-done:
		joined = true
		require.NoError(t, got.rollback)
		if cancelWait {
			require.ErrorIs(t, got.opening, context.Canceled)
		} else {
			require.NoError(t, got.opening)
		}
	case <-ctx.Done():
		t.Fatal("opener не завершился после освобождения/отмены: ", ctx.Err())
	}
	if cancelWait {
		require.NoError(t, holder.Rollback(ctx))
	}
	var retained int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1
 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2`, waiterPID).Scan(&retained))
	require.Zero(t, retained, "завершённый opener не оставляет compatibility lock")
	var one int
	require.NoError(t, runtime.QueryRow(ctx, `SELECT 1`).Scan(&one), "единственный slot вернулся после отмены/rollback")
	require.Equal(t, 1, one)
	// Успешный twin после каждого отказа, через ту же дверь и тот же pool.
	w, err := open(ctx)
	require.NoError(t, err)
	require.NoError(t, w.Rollback(ctx))
}
