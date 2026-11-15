// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type projectDeleteEntryKey struct{}
type projectDeleteBeginClaimKey struct{}
type projectForwardPIDKey struct{}
type projectUnregisterPIDKey struct{}

// projectDeleteBeginGate задерживает ответ только первого успешного writer BEGIN
// помеченного Delete. Reader использует begin read only; Create/Claim операции
// исполняются одиночными запросами. SQL и ожидания под sync.Once здесь отсутствуют.
type projectDeleteBeginGate struct {
	claimed       atomic.Bool
	deletePID     atomic.Uint32
	forwardPID    atomic.Uint32
	unregisterPID atomic.Uint32
	entered       chan struct{}
	release       chan struct{}
	once          sync.Once
}

func (g *projectDeleteBeginGate) let() { g.once.Do(func() { close(g.release) }) }

func (g *projectDeleteBeginGate) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(projectForwardPIDKey{}) == g && data.SQL == "begin" {
		g.forwardPID.Store(conn.PgConn().PID())
	}
	if ctx.Value(projectUnregisterPIDKey{}) == g {
		g.unregisterPID.Store(conn.PgConn().PID())
	}
	if ctx.Value(projectDeleteEntryKey{}) == g && data.SQL == "begin" && g.claimed.CompareAndSwap(false, true) {
		g.deletePID.Store(conn.PgConn().PID())
		return context.WithValue(ctx, projectDeleteBeginClaimKey{}, g)
	}
	return ctx
}

func (g *projectDeleteBeginGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(projectDeleteBeginClaimKey{}) != g || data.Err != nil {
		return
	}
	close(g.entered)
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

// projectScheduleRollback ограничивает cleanup, сохраняя values без cancel.
func projectScheduleRollback(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}

// projectScheduleRead проверяет предпосылку отдельной read-only транзакцией.
func projectScheduleRead(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx)) {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, expiryRaceBudget)
	defer cancel()
	tx, err := pool.BeginTx(readCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer projectScheduleRollback(readCtx, tx)
	fn(tx)
}

// runProjectForwardUnregisterEntryRace сохраняет три настоящих участника:
// форвард уже прочитал выдачу, Delete открыл TX без бизнес-замков, unregister
// действительно ждёт admission форварда. Затем форвард коммитит захваченный факт,
// unregister делает проект пустым, и Delete снимает только что записанный факт.
func runProjectForwardUnregisterEntryRace(t *testing.T, kind forwardKind, suffix string, fix raceFixture) (*pgxpool.Pool, domain.AccessBindingID, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*expiryRaceBudget)
	defer cancel()
	gate := &projectDeleteBeginGate{entered: make(chan struct{}), release: make(chan struct{})}
	// Config копирует все эффективные параметры coredb: DSN, timeout и watcher.
	initial, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	cfg := initial.Config()
	initial.Close()
	cfg.ConnConfig.Tracer = gate
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	t.Cleanup(cancel)
	t.Cleanup(gate.let)
	require.NoError(t, pool.Ping(ctx))
	fx := setupGamma(t, ctx, pool, suffix)
	_, adapter := newReconciler(pool)
	ptx := newPausingTx(adapter)
	t.Cleanup(ptx.let)
	forwarder := reconcile.New(ptx, nil, catalogfixture.Source())
	bid, subj := seedRaceBinding(t, ctx, pool, fx, suffix, fix)
	fwdDone := make(chan error, 1)
	go func() {
		forwardCtx := context.WithValue(ctx, projectForwardPIDKey{}, gate)
		if kind == bindingForward {
			fwdDone <- forwarder.ReconcileBindingForward(forwardCtx, bid)
			return
		}
		fwdDone <- forwarder.ReconcileObjectForward(forwardCtx, "compute.instance", "iRace")
	}()
	select {
	case <-ptx.paused:
	case err := <-fwdDone:
		t.Fatalf("ПРЕДПОСЫЛКА: форвард завершился до чтения выдачи: %v", err)
	case <-time.After(expiryRaceBudget):
		t.Fatal("ПРЕДПОСЫЛКА: форвард не дошёл до чтения выдачи")
	}

	deleteCtx := context.WithValue(ctx, projectDeleteEntryKey{}, gate)
	deleteDone := startDeactivation(t, deleteCtx, pool, forwarder, fx, bid, projectDeleteDeactivation)
	select {
	case <-gate.entered:
	case err := <-deleteDone:
		t.Fatalf("ПРЕДПОСЫЛКА: Delete завершился до writer BEGIN: %v", err)
	case <-time.After(expiryRaceBudget):
		t.Fatal("ПРЕДПОСЫЛКА: Delete не дошёл до writer BEGIN")
	}
	projectScheduleRead(t, ctx, pool, func(tx pgx.Tx) {
		var started, clean bool
		require.NoError(t, tx.QueryRow(ctx, `SELECT a.xact_start IS NOT NULL AND a.state='idle in transaction',
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
 AND l.locktype IN ('advisory','relation','tuple'))
 FROM pg_catalog.pg_stat_activity a WHERE a.pid=$1 AND a.datname=current_database()`,
			gate.deletePID.Load()).Scan(&started, &clean))
		require.True(t, started, "ПРЕДПОСЫЛКА: настоящий Delete TX уже открыт")
		require.True(t, clean, "ПРЕДПОСЫЛКА: Delete ещё не владеет admission или бизнес-замками")
	})

	unregisterDone := make(chan error, 1)
	unregisterCtx, unregisterCancel := context.WithTimeout(context.WithValue(ctx, projectUnregisterPIDKey{}, gate), 2*expiryRaceBudget)
	defer unregisterCancel()
	go func() {
		tag, err := pool.Exec(unregisterCtx, `DELETE FROM kaname.resource_mirror WHERE object_type = 'compute.instance' AND object_id = 'iRace'`)
		if err == nil && tag.RowsAffected() != 1 {
			unregisterDone <- pgx.ErrNoRows
			return
		}
		unregisterDone <- err
	}()
	waitCtx, waitCancel := context.WithTimeout(ctx, expiryRaceBudget)
	defer waitCancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	blocked := false
	for !blocked {
		select {
		case err := <-unregisterDone:
			t.Fatalf("ПРЕДПОСЫЛКА: unregister завершился до коммита форварда: %v", err)
		case err := <-deleteDone:
			t.Fatalf("ПРЕДПОСЫЛКА: Delete завершился до release: %v", err)
		case <-waitCtx.Done():
			t.Fatal("ПРЕДПОСЫЛКА: unregister не встал на admission форварда")
		case <-tick.C:
			projectScheduleRead(t, waitCtx, pool, func(tx pgx.Tx) {
				require.NoError(t, tx.QueryRow(waitCtx, `SELECT EXISTS(
 SELECT 1 FROM pg_catalog.pg_locks waiting JOIN pg_catalog.pg_locks held
 ON held.locktype=waiting.locktype AND held.database=waiting.database
 AND held.classid=waiting.classid AND held.objid=waiting.objid AND held.objsubid=waiting.objsubid
 WHERE waiting.pid=$1 AND NOT waiting.granted AND held.pid=$2 AND held.granted
 AND waiting.locktype='advisory' AND waiting.classid=1262569292::oid
 AND waiting.objid=0::oid AND waiting.objsubid=2
 AND $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer)))`,
					gate.unregisterPID.Load(), gate.forwardPID.Load()).Scan(&blocked))
			})
		}
	}

	ptx.let()
	select {
	case err := <-fwdDone:
		require.NoError(t, err, "форвард коммитит захваченный факт")
	case <-time.After(expiryRaceBudget):
		t.Fatal("форвард не завершился после release")
	}
	_, _, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	require.Positive(t, facts, "БЛИЗНЕЦ В ПРОГОНЕ: настоящий форвард обязан закоммитить прямой факт до Delete")
	select {
	case err := <-unregisterDone:
		require.NoError(t, err, "настоящее unregister после коммита форварда")
	case <-time.After(expiryRaceBudget):
		t.Fatal("unregister не завершился после коммита форварда")
	}
	projectScheduleRead(t, ctx, pool, func(tx pgx.Tx) {
		var count int
		require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_mirror
 WHERE object_type='compute.instance' AND object_id='iRace'`).Scan(&count))
		require.Zero(t, count, "ПРЕДПОСЫЛКА PNE: объект действительно снят с регистрации до Delete")
	})
	gate.let()
	select {
	case err := <-deleteDone:
		require.NoError(t, err, "настоящий Project.Delete после unregister")
	case <-time.After(expiryRaceBudget):
		t.Fatal("Project.Delete не завершился после release")
	}
	return pool, bid, subj
}

// deactivationForwardAdmissionHolderPID фиксирует единственного настоящего
// держателя1292 после паузы форварда и ДО запуска снятия. Наблюдение не берёт
// бизнес-замков; отсутствие или неоднозначность держателя роняют предпосылку.
func deactivationForwardAdmissionHolderPID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var pid, count int
	projectScheduleRead(t, readCtx, pool, func(tx pgx.Tx) {
		require.NoError(t, tx.QueryRow(readCtx, `SELECT coalesce(min(pid),0), count(DISTINCT pid)
 FROM pg_catalog.pg_locks WHERE database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid
 AND objsubid=2 AND mode='ExclusiveLock' AND granted`).Scan(&pid, &count))
	})
	require.Equal(t, 1, count, "ПРЕДПОСЫЛКА: единственный держатель1292 — остановленный форвард")
	require.Positive(t, pid)
	return pid
}
