// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const sharedWriterEntrySQL = "SELECT pg_advisory_xact_lock(1262569292,0)"

type sharedWriterEntryKey struct{}

// PID принадлежит реальному Writer после BEGIN. Tracer не выполняет SQL и
// останавливает только первый внешний entry SELECT помеченного Writer.
type sharedWriterEntry struct {
	claimed atomic.Bool
	pid     atomic.Uint32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *sharedWriterEntry) let() { p.once.Do(func() { close(p.release) }) }

type sharedWriterTracer struct{}

func (sharedWriterTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	p, ok := ctx.Value(sharedWriterEntryKey{}).(*sharedWriterEntry)
	if !ok || data.SQL != sharedWriterEntrySQL || !p.claimed.CompareAndSwap(false, true) {
		return ctx
	}
	p.pid.Store(conn.PgConn().PID())
	close(p.entered)
	select {
	case <-p.release:
	case <-ctx.Done():
	}
	return ctx
}

func (sharedWriterTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Cleanup отпускает паузы и присоединяет наблюдателей исходов до закрытия
// обоих пулов, в том числе при Fatal. Превышение бюджета остаётся отказом.
// Канал finished не расходуется mustDone/waitReached; он закрывается после
// получения исхода awaitOutcome, а не при отпускании тестовой паузы.
type sharedWriterRace struct {
	pauses  []*pausePoint
	entries []*sharedWriterEntry
	joined  []<-chan struct{}
}

func newSharedWriterRace(t *testing.T, ctx context.Context, fx *sharedFixture) *sharedWriterRace {
	t.Helper()
	// Config копирует эффективные настройки coredb.NewPool: DSN, timeouts и
	// CancelRequest watcher. Исходный пул остаётся read-only наблюдателем гонки.
	cfg := fx.pool.Config()
	cfg.ConnConfig.Tracer = sharedWriterTracer{}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx.repo = kanamepg.New(pool, nil)
	r := &sharedWriterRace{}
	t.Cleanup(func() {
		for _, p := range r.entries {
			p.let()
		}
		for _, p := range r.pauses {
			p.let()
		}
		// Это прежний предел awaitOutcome, не новый бюджет операции/SQL.
		deadline := time.NewTimer(2 * sharedRaceBudget)
		defer deadline.Stop()
		for _, finished := range r.joined {
			select {
			case <-finished:
			case <-deadline.C:
				t.Error("cleanup: исход запущенной операции не получен до закрытия пула")
				return
			}
		}
	})
	return r
}

func (r *sharedWriterRace) pause() *pausePoint {
	p := newPausePoint()
	r.pauses = append(r.pauses, p)
	return p
}

func (r *sharedWriterRace) entry() *sharedWriterEntry {
	p := &sharedWriterEntry{entered: make(chan struct{}), release: make(chan struct{})}
	r.entries = append(r.entries, p)
	return p
}

func (r *sharedWriterRace) track(done <-chan error) <-chan error {
	result := make(chan error, 1)
	finished := make(chan struct{})
	r.joined = append(r.joined, finished)
	go func() {
		result <- <-done
		close(finished)
	}()
	return result
}

func sharedEntryStarted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, p *sharedWriterEntry, done <-chan error) time.Time {
	t.Helper()
	select {
	case <-p.entered:
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: Writer завершился до entry: %v", err)
	case <-time.After(sharedRaceBudget):
		t.Fatal("ПРЕДПОСЫЛКА: Writer не достиг entry за 30s")
	}
	observe, cancel := context.WithTimeout(ctx, sharedRaceBudget)
	defer cancel()
	var start time.Time
	var idle, noLocks bool
	require.NoError(t, pool.QueryRow(observe, `SELECT a.xact_start,
 a.state='idle in transaction',
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
  AND l.locktype IN ('advisory','relation','tuple'))
 FROM pg_catalog.pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.xact_start IS NOT NULL`,
		p.pid.Load()).Scan(&start, &idle, &noLocks))
	require.True(t, idle, "ПРЕДПОСЫЛКА: настоящий BEGIN уже выполнен")
	require.True(t, noLocks, "ПРЕДПОСЫЛКА: до entry нет authority или бизнес-замков")
	t.Logf("Writer до entry: pid=%d xact_start=%s", p.pid.Load(), start.Format(time.RFC3339Nano))
	return start
}

func sharedWaitWriterFence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, waiter *sharedWriterEntry, holderPID uint32, start time.Time, done <-chan error) {
	t.Helper()
	observe, cancel := context.WithTimeout(ctx, sharedRaceBudget)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		require.NoError(t, pool.QueryRow(observe, `SELECT EXISTS(
 SELECT 1 FROM pg_catalog.pg_stat_activity a
 JOIN pg_catalog.pg_locks w ON w.pid=a.pid
 JOIN pg_catalog.pg_locks h ON h.locktype=w.locktype
  AND h.database=w.database AND h.classid=w.classid
  AND h.objid=w.objid AND h.objsubid=w.objsubid
 WHERE a.pid=$1 AND a.datname=current_database() AND a.xact_start=$3
  AND a.state='active' AND a.wait_event_type='Lock' AND a.wait_event='advisory'
  AND a.query=$4 AND w.locktype='advisory' AND NOT w.granted
  AND w.classid=1262569292::oid AND w.objid=0::oid AND w.objsubid=2
  AND w.mode='ExclusiveLock' AND h.pid=$2 AND h.granted
  AND h.mode='ExclusiveLock' AND $2=ANY(pg_catalog.pg_blocking_pids(a.pid)))`,
			waiter.pid.Load(), holderPID, start, sharedWriterEntrySQL).Scan(&waiting))
		if waiting {
			t.Logf("Writer pid=%d xact_start=%s ждёт entry (1262569292,0), holder pid=%d", waiter.pid.Load(), start.Format(time.RFC3339Nano), holderPID)
			return
		}
		select {
		case err := <-done:
			t.Fatalf("ПРЕДПОСЫЛКА: Writer завершился без наблюдаемого ожидания fence: %v", err)
		case <-observe.Done():
			t.Fatal("ПРЕДПОСЫЛКА: ожидание конкретного Writer fence не подтверждено за 30s")
		case <-tick.C:
		}
	}
}
