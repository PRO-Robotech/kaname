// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// Две независимые границы: обычный Writer сериализует конкурирующую выдачу
// на compatibility fence, а настоящий Group.Delete ждёт KEY SHARE самой строки.
// Точный SQL/PID отличает их от посторонней ошибки и ожидания другого замка.

import (
	"context"
	stderrors "errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// newLockTimeoutPool — a pgxpool whose every session sets `lock_timeout` so a
// guarded write that blocks on a conflicting row-lock self-releases (55P03)
// rather than waiting out statement_timeout. Used for the delete side so the
// serialization proof is bounded and deterministic.
func newLockTimeoutPool(t *testing.T, ctx context.Context, dsn string, lockTimeoutMS int) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = strconv.Itoa(lockTimeoutMS)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// Держатель — именно единственный обычный Writer текущей изолированной БД.
func groupDeleteCompatPID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var pids []int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(array_agg(pid), ARRAY[]::integer[]) FROM pg_locks
 WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND classid=1262569292::oid AND objid=0::oid AND objsubid=2 AND mode='ExclusiveLock' AND granted`).Scan(&pids))
	require.Len(t, pids, 1)
	return pids[0]
}

// Горутина не вызывает require: все ошибки, включая admission и rollback,
// проверяет текущий дочерний t. При неуспехе наблюдения cancel останавливает
// запрос до закрытия pool; исходный lock_timeout остаётся равен двум секундам.
func groupDeleteBlockedProbe(t *testing.T, parent context.Context, observer, deletePool *pgxpool.Pool, trace *finalDecisionTrace, id domain.GroupID, holderPID int, compat bool, release func() error) error {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	type outcome struct {
		admission, deletion, rollback error
	}
	done := make(chan outcome, 1)
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("delete probe не завершился после cancel")
			}
		}
	}()
	go func() {
		w, err := kanamepg.New(deletePool, nil).Writer(ctx)
		if err != nil {
			done <- outcome{admission: err}
			return
		}
		err = w.GroupsW().Delete(ctx, id)
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollback := w.Rollback(cleanup)
		stop()
		done <- outcome{deletion: err, rollback: rollback}
	}()
	require.Eventually(t, func() bool {
		pid := int(trace.pid.Load())
		if pid == 0 {
			return false
		}
		var waiting bool
		err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.wait_event_type='Lock'
 AND $2::integer=ANY(pg_blocking_pids(a.pid))
 AND (($3::boolean AND position('SELECT pg_advisory_xact_lock(1262569292,0)' in a.query)>0
       AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
         AND l.locktype='advisory' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
         AND l.classid=1262569292::oid AND l.objid=0::oid AND l.objsubid=2 AND l.mode='ExclusiveLock'))
   OR (NOT $3::boolean AND position('DELETE FROM groups g' in a.query)>0
       AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
         AND l.locktype IN ('transactionid','tuple')))))`, pid, holderPID, compat).Scan(&waiting)
		return err == nil && waiting
	}, 2*time.Second, 10*time.Millisecond, "ожидается точный DELETE row lock либо Writer compat lock с заданным blocker PID")
	require.NoError(t, release())
	select {
	case result := <-done:
		joined = true
		require.NoError(t, result.admission, "Writer обязан пройти после освобождения compat")
		require.NoError(t, result.rollback)
		return result.deletion
	case <-time.After(2 * time.Second):
		t.Fatal("Group.Delete не завершился после освобождения доказанного замка")
		return nil
	}
}

func TestGroup_DeleteVsAddSubject_ConcurrentCAS_NoDangling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)

	// master pool — seeding + the held-open AccessBinding write tx.
	master, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer master.Close()
	seedRepo := kanamepg.New(master, nil)

	// delete-side repo on a lock_timeout=2s pool so the production
	// groupWriter.Delete self-releases instead of blocking to statement_timeout.
	deleteTrace := &finalDecisionTrace{}
	deletePool := finalDecisionTracePool(t, ctx, newLockTimeoutPool(t, ctx, dsn, 2000), deleteTrace)
	delRepo := kanamepg.New(deletePool, nil)

	// realGroupDelete drives the PRODUCTION groupWriter.Delete on a fresh
	// lock_timeout writer-tx (rolled back — this side never commits a delete).
	realGroupDelete := func(t *testing.T, id domain.GroupID) error {
		t.Helper()
		w, werr := delRepo.Writer(ctx)
		require.NoError(t, werr)
		defer func() { _ = w.Rollback(ctx) }()
		return w.GroupsW().Delete(ctx, id)
	}

	// Только читающий держатель не входит в Writer и не занимает compat:
	// отсутствие AB гарантирует достижение самого DELETE, а не быстрого отказа.
	t.Run("unbound_group_row_key_share", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-row")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-row", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-row")
		holder, err := master.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = holder.Rollback(ctx) }()
		var holderPID int
		var locked string
		require.NoError(t, holder.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
		require.NoError(t, holder.QueryRow(ctx, `SELECT id FROM kaname.groups WHERE id=$1 FOR KEY SHARE`, string(g.ID)).Scan(&locked))
		require.Equal(t, string(g.ID), locked)
		require.NoError(t, groupDeleteBlockedProbe(t, ctx, master, deletePool, deleteTrace, g.ID, holderPID, false, func() error { return holder.Rollback(ctx) }))
		var count int
		require.NoError(t, master.QueryRow(ctx, `SELECT count(*) FROM kaname.groups WHERE id=$1`, string(g.ID)).Scan(&count))
		require.Equal(t, 1, count, "успешный настоящий DELETE откатан вместе с Writer")
	})

	// ── subjects[0] projection: the access_bindings NOT-EXISTS guard ──────────
	t.Run("subjects0_access_bindings_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-a")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-a", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-a")

		// A real AccessBinding.Create for subject group:g, held open (uncommitted).
		// Its 0049 subject_ref_exists trigger takes FOR KEY SHARE on the groups row.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		_, err = bindingset.Insert(ctx, wIns.AccessBindingsW(), domain.AccessBinding{
			ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
			SubjectType:  domain.SubjectTypeGroup,
			SubjectID:    domain.SubjectID(g.ID),
			RoleID:       "rol000000000sysviewer",
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)

		// AB Writer удерживает compat до commit; наблюдаем именно этот ранний
		// рубеж. После commit тот же обычный Writer обязан дойти до Delete.
		err = groupDeleteBlockedProbe(t, ctx, master, deletePool, deleteTrace, g.ID, groupDeleteCompatPID(t, ctx, master), true, func() error {
			err := wIns.Commit(ctx)
			committed = err == nil
			return err
		})
		require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)

		err = realGroupDelete(t, g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still bound), got %v", err)

		// Invariant: the group survived and the binding references a live group.
		var groupCnt, bindCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "bound group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_bindings WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&bindCnt))
		require.Equal(t, 1, bindCnt, "the committed binding must reference the live group")
	})

	// ── subjects[1..N]: the access_binding_subjects guard + 0050 trigger ──────
	t.Run("subjectsN_access_binding_subjects_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-b")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-b", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-b")

		// A COMMITTED binding whose subjects[0] is the user — group:g is NOT the
		// access_bindings projection; it exists ONLY as an access_binding_subjects
		// child row (the subjects[1..N] path guarded by migration 0050's BEFORE
		// DELETE trigger + the Delete CTE's second NOT EXISTS).
		bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
		wSeed, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = wSeed.Rollback(ctx) }()
		_, err = bindingset.Insert(ctx, wSeed.AccessBindingsW(), domain.AccessBinding{
			ID:           bindingID,
			SubjectType:  domain.SubjectTypeUser,
			SubjectID:    domain.SubjectID(uid),
			RoleID:       "rol000000000sysviewer",
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)
		require.NoError(t, wSeed.Commit(ctx))

		// Add group:g as an extra subject, held open (uncommitted) — the 0049
		// trigger fires on access_binding_subjects too, taking FOR KEY SHARE on
		// the groups row.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		require.NoError(t, wIns.AccessBindingsW().InsertSubjects(ctx, bindingID, []domain.Subject{
			{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(g.ID)},
		}))

		err = groupDeleteBlockedProbe(t, ctx, master, deletePool, deleteTrace, g.ID, groupDeleteCompatPID(t, ctx, master), true, func() error {
			err := wIns.Commit(ctx)
			committed = err == nil
			return err
		})
		require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)

		// Fresh guarded delete now sees the committed access_binding_subjects row
		// → rejected (0050 trigger / second NOT EXISTS), no dangling subject ref.
		err = realGroupDelete(t, g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still referenced as a binding subject), got %v", err)

		var groupCnt, subjCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "referenced group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&subjCnt))
		require.Equal(t, 1, subjCnt, "the committed subject row must reference the live group")
	})
}
