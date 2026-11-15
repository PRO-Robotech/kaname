// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// accountEntryPauseKey помечает только контекст настоящего Delete use-case.
// operations.Run сохраняет Value через baggage.Extract/context.WithoutCancel.
type accountEntryPauseKey struct{}

// accountEntryPause останавливает первый целевой SELECT до отправки серверу.
// CAS захватывает вызов без мьютекса, который мог бы задержать другие запросы.
// Внутри tracer нет SQL; PID читается из уже открытого соединения.
type accountEntryPause struct {
	claimed atomic.Bool
	pid     atomic.Uint32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *accountEntryPause) let() { p.once.Do(func() { close(p.release) }) }

func (p *accountEntryPause) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(accountEntryPauseKey{}) != p ||
		data.SQL != "SELECT kaname.authority_parent_prelock_admit_v3()" ||
		!p.claimed.CompareAndSwap(false, true) {
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

func (*accountEntryPause) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// accountEntryPausePool сохраняет DSN setupTestDB и эффективные настройки
// corelib/db.NewPool v1.16.1: оба server timeout, CancelRequest watcher и Ping.
func accountEntryPausePool(t *testing.T, ctx context.Context, pause *accountEntryPause) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	cfg.ConnConfig.BuildContextWatcherHandler = func(c *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{
			Conn: c, CancelRequestDelay: 0, DeadlineDelay: 500 * time.Millisecond,
		}
	}
	cfg.ConnConfig.Tracer = pause
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	// LIFO: release всегда идёт до закрытия пула, включая отказ предпосылки.
	t.Cleanup(pause.let)
	require.NoError(t, pool.Ping(ctx))
	return pool
}

// runAccountDeactivationEntryPauseRace ставит второй порядок без artificial
// advisory holder: Delete уже открыл транзакцию, но ещё не взял admission или
// бизнес-замки. Форвард коммитит более поздний факт, затем Delete его снимает.
func runAccountDeactivationEntryPauseRace(t *testing.T, kind forwardKind, suffix string) (*pgxpool.Pool, domain.AccessBindingID, string) {
	t.Helper()
	ctx := context.Background()
	pause := &accountEntryPause{entered: make(chan struct{}), release: make(chan struct{})}
	pool := accountEntryPausePool(t, ctx, pause)
	fx := setupGamma(t, ctx, pool, suffix)
	forwarder, _ := newReconciler(pool)
	bid, subj := seedRaceBinding(t, ctx, pool, fx, suffix, fixtureFor(accountDeleteDeactivation))
	deleteCtx := context.WithValue(ctx, accountEntryPauseKey{}, pause)
	done := startDeactivation(t, deleteCtx, pool, forwarder, fx, bid, accountDeleteDeactivation)
	select {
	case <-pause.entered:
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: Delete завершился до остановки admission: %v", err)
	case <-time.After(expiryRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: Delete не дошёл до admission за %s", expiryRaceBudget)
	}

	// Административное наблюдение только чтением, на отдельном соединении.
	// BEGIN уже виден, SELECT admission ещё не отправлен, бизнес-замков нет.
	adminCtx, cancel := context.WithTimeout(ctx, expiryRaceBudget)
	defer cancel()
	admin, err := pool.BeginTx(adminCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = admin.Rollback(cleanup)
	}()
	var deletionStart time.Time
	var idle, noLocks bool
	require.NoError(t, admin.QueryRow(adminCtx, `SELECT a.xact_start,
 a.state='idle in transaction',
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
  AND l.locktype IN ('advisory','relation','tuple'))
 FROM pg_catalog.pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.xact_start IS NOT NULL`,
		pause.pid.Load()).Scan(&deletionStart, &idle, &noLocks))
	require.True(t, idle, "ПРЕДПОСЫЛКА: настоящая Delete TX уже началась")
	require.True(t, noLocks, "ПРЕДПОСЫЛКА: до entry нет ни9292, ни бизнес-замков")
	require.NoError(t, admin.Rollback(adminCtx))

	fwdDone := make(chan error, 1)
	go func() {
		if kind == bindingForward {
			fwdDone <- forwarder.ReconcileBindingForward(ctx, bid)
			return
		}
		fwdDone <- forwarder.ReconcileObjectForward(ctx, "compute.instance", "iRace")
	}()
	select {
	case err := <-fwdDone:
		require.NoError(t, err, "форвард в паузе настоящей Delete TX")
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: Delete завершился до отпускания admission: %v", err)
	case <-time.After(expiryRaceBudget):
		t.Fatalf("форвард не завершился в паузе Delete за %s", expiryRaceBudget)
	}
	_, _, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	require.Positive(t, facts, "БЛИЗНЕЦ В ПРОГОНЕ: форвард, зафиксированный раньше снятия, обязан дать прямой факт — иначе ноль после снятия ни о чём")
	var later bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*)>0 AND bool_and(created_at>$3)
 FROM kaname.fga_outbox WHERE event_type='fga.tuple.write'
 AND payload->>'user'=$1 AND payload->>'object'=$2`, subj, "compute_instance:iRace", deletionStart).Scan(&later))
	require.True(t, later, "ПРЕДПОСЫЛКА: created_at durable записи форварда новее начала Delete TX")
	unregisterRaceObjectFor(t, ctx, pool, accountDeleteDeactivation)

	pause.let()
	select {
	case err := <-done:
		require.NoError(t, err, "%s после коммита форварда", accountDeleteDeactivation)
	case <-time.After(2 * expiryRaceBudget):
		t.Fatalf("снятие (%s) не завершилось за %s после отпускания entry", accountDeleteDeactivation, 2*expiryRaceBudget)
	}
	return pool, bid, subj
}
