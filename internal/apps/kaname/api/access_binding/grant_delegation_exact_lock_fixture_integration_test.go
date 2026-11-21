// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Legacy Writer сериализует вход до бизнес-замков. Проверяем точный
// двухкомпонентный advisory key и PID держателя, а не постороннее ожидание.
func gdCompatOwner(w *gdWorld) int32 {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, gduBarrierDeadline)
	defer cancel()
	var pids []int32
	require.NoError(w.t, w.pool.QueryRow(ctx, `
		SELECT COALESCE(array_agg(pid), ARRAY[]::integer[]) FROM pg_locks
		WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
		  AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
		  AND mode='ExclusiveLock' AND granted`).Scan(&pids))
	require.Len(w.t, pids, 1, "fixture must own the single legacy compat fence")
	return pids[0]
}

func gdAwaitLockPID(parent context.Context, w *gdWorld, query string, args ...any) int32 {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(parent, gduBarrierDeadline)
	defer cancel()
	for {
		var pids []int32
		require.NoError(w.t, w.pool.QueryRow(ctx,
			`SELECT COALESCE(array_agg(pid), ARRAY[]::integer[]) FROM (`+query+`) AS exact_waiters`, args...).Scan(&pids))
		if len(pids) != 0 {
			require.Len(w.t, pids, 1, "expected one exact waiter, not an arbitrary lock count")
			return pids[0]
		}
		select {
		case <-ctx.Done():
			w.t.Fatal("exact fixture lock was not reached: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func gdAwaitCompatWaiter(w *gdWorld, holder int32, application string) int32 {
	w.t.Helper()
	return gdAwaitCompatWaiterUntil(w.ctx, w, holder, application)
}

func gdAwaitCompatWaiterUntil(ctx context.Context, w *gdWorld, holder int32, application string) int32 {
	w.t.Helper()
	return gdAwaitLockPID(ctx, w, `
		SELECT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
		WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid))
		  AND ($2='' OR a.application_name=$2) AND a.wait_event_type='Lock'
		  AND l.locktype='advisory' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
		  AND l.classid=1262569292::oid AND l.objid=0::oid AND l.objsubid=2
		  AND l.mode='ExclusiveLock' AND NOT l.granted`, holder, application)
}

// Держатель занимает только выбранную строку фикстуры. Его PID вместе с
// настоящим target SQL определяет row wait, в том числе transactionid:
// PostgreSQL не обязан показывать ungranted tuple lock каждому ожидающему.
func gdAwaitRowWaiter(w *gdWorld, waiter, holder int32, table string) int32 {
	w.t.Helper()
	return gdAwaitLockPID(w.ctx, w, `
		SELECT a.pid FROM pg_stat_activity a
		WHERE a.datname=current_database() AND ($1=0 OR a.pid=$1)
		  AND $2=ANY(pg_blocking_pids(a.pid)) AND a.wait_event_type='Lock'
		  AND position($3 in a.query)>0
		  AND EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
		              AND l.locktype IN ('transactionid','tuple'))`, waiter, holder, table)
}

func gdRowHolder(w *gdWorld, statement, id string) (pgx.Tx, int32) {
	w.t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(w.t, err)
	w.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	})
	var pid int32
	var locked string
	require.NoError(w.t, tx.QueryRow(w.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	require.NoError(w.t, tx.QueryRow(w.ctx, statement, id).Scan(&locked))
	require.Equal(w.t, id, locked, "holder must lock the exact fixture row")
	return tx, pid
}

// Настоящий метод repository работает через обычный Writer; read-only
// держатель отпускается лишь после точного доказательства ожидания. Здесь
// нет записи вне Writer или отключения guards. Observer использует прежний pool.
func gdBlockedWriterProbe(w *gdWorld, holder pgx.Tx, observe func(int32), action func(context.Context, kanamerepo.Writer) error) error {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, gduBarrierDeadline)
	defer cancel()
	writer, err := w.repo.Writer(ctx)
	require.NoError(w.t, err)
	done := make(chan error, 1)
	joined := false
	started := false
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer stop()
		_ = holder.Rollback(cleanup)
		if started && !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				w.t.Error("lock probe worker did not stop")
			}
		}
		_ = writer.Rollback(cleanup)
	}()
	pid := gdCompatOwner(w)
	started = true
	go func() { done <- action(ctx, writer) }()
	observe(pid)
	require.NoError(w.t, holder.Rollback(ctx))
	select {
	case err := <-done:
		joined = true
		return err
	case <-ctx.Done():
		w.t.Fatal("lock probe did not finish: ", ctx.Err())
		return ctx.Err()
	}
}

func gdRequireHoldActiveShareLock(w *gdWorld, id string) {
	w.t.Helper()
	// FOR KEY SHARE совместим с держателем: CE09 требует именно SHARE,
	// конфликтующий с non-key изменением при отзыве.
	holder, pid := gdRowHolder(w, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR NO KEY UPDATE`, id)
	var active bool
	var account domain.AccountID
	err := gdBlockedWriterProbe(w, holder, func(waiter int32) {
		gdAwaitRowWaiter(w, waiter, pid, "grant_delegations")
	}, func(ctx context.Context, writer kanamerepo.Writer) error {
		var err error
		account, active, err = writer.AccessBindingsW().GrantDelegationsW().HoldActive(ctx, domain.GrantDelegationID(id))
		return err
	})
	require.NoError(w.t, err)
	require.True(w.t, active)
	require.Equal(w.t, w.accA, account)
}

func gdRequireDeleteAccountRowLock(w *gdWorld, account, delegation string) {
	w.t.Helper()
	holder, pid := gdRowHolder(w, `SELECT id FROM kaname.service_accounts WHERE id=$1 FOR KEY SHARE`, account)
	err := gdBlockedWriterProbe(w, holder, func(waiter int32) {
		gdAwaitRowWaiter(w, waiter, pid, "service_accounts")
	}, func(ctx context.Context, writer kanamerepo.Writer) error {
		return writer.ServiceAccountsW().Delete(ctx, domain.ServiceAccountID(account))
	})
	require.Error(w.t, err)
	st, _ := status.FromError(shared.MapRepoErr(err))
	require.Equal(w.t, codes.FailedPrecondition, st.Code())
	require.Equal(w.t, fmt.Sprintf("service account %s holds an active grant delegation %s; revoke it first", account, delegation), st.Message())
}

func gdRequirePairBeforeRow(u *gduWorld) {
	u.t.Helper()
	// Держатель занимает настоящий pair key. Испытуемый — обычный API Update,
	// а не прямой вызов LockForRevoke. При row→pair наш NOWAIT обязан упасть.
	holder, err := u.pool.Begin(u.ctx)
	require.NoError(u.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(u.ctx), 5*time.Second)
		defer cancel()
		_ = holder.Rollback(ctx)
	}()
	var pid int32
	require.NoError(u.t, holder.QueryRow(u.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	pair := string(u.accA) + "/" + u.svaIss
	_, err = holder.Exec(u.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1038))`, pair)
	require.NoError(u.t, err)
	// Тождественный PATCH сохраняет оси и audit census следующего сценария,
	// но проходит настоящий Update worker с pair/row locks и authority recheck.
	_, msg, err := u.gdCall(asUser(u.ctx, u.usrA), "Update", u.body(gduMask("roleIds"), map[string]any{"roleIds": []string{string(u.rolPuller)}}))
	require.NoError(u.t, err)
	op := msg.(*operationpb.Operation)
	waiter := gdAwaitLockPID(u.ctx, u.gdWorld, `
		SELECT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
		WHERE $1=ANY(pg_blocking_pids(a.pid)) AND NOT l.granted
		  AND l.locktype='advisory' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
		  AND l.classid=((hashtextextended($2,1038)>>32)&4294967295)::oid
		  AND l.objid=(hashtextextended($2,1038)&4294967295)::oid AND l.objsubid=1
		  AND l.mode='ExclusiveLock'`, pid, pair)
	require.Equal(u.t, waiter, gdCompatOwner(u.gdWorld))
	var locked string
	require.NoError(u.t, holder.QueryRow(u.ctx, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR UPDATE NOWAIT`, u.d).Scan(&locked))
	require.Equal(u.t, u.d, locked)
	require.NoError(u.t, holder.Rollback(u.ctx))
	u.awaitSuccess(op)
	// Прежний положительный контроль настоящего HoldActive сохранён.
	writer, err := u.repo.Writer(u.ctx)
	require.NoError(u.t, err)
	defer func() { _ = writer.Rollback(u.ctx) }()
	_, active, err := writer.AccessBindingsW().GrantDelegationsW().HoldActive(u.ctx, domain.GrantDelegationID(u.d))
	require.NoError(u.t, err)
	require.True(u.t, active)
}

func gdSQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// Tracer сохраняет реальный backend отказ ДО production mapping, которое
// намеренно не оставляет PgError в публичной цепочке ошибки.
type gd45FKErrorTrace struct {
	native chan *pgconn.PgError
}

func (t *gd45FKErrorTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (t *gd45FKErrorTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var native *pgconn.PgError
	if errors.As(data.Err, &native) && native.Code == "23503" {
		select {
		case t.native <- native:
		default:
		}
	}
}

// Corelib сохраняет собственный worker deadline, но отрезает caller cancel.
// Этот tracer связывает с отменой фикстуры реальные SQL и pool Acquire только
// двух Update малого пула. Observer и durable operations repo не затрагиваются.
type gduWorkerCancelTrace struct {
	lifetime context.Context
}

type gduCancelTraceKey struct{}
type gduCancelTraceState struct {
	cancel context.CancelFunc
	stop   func() bool
}

func (t *gduWorkerCancelTrace) start(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.lifetime, cancel)
	if t.lifetime.Err() != nil {
		cancel()
	}
	return context.WithValue(ctx, gduCancelTraceKey{}, &gduCancelTraceState{cancel: cancel, stop: stop})
}

func (t *gduWorkerCancelTrace) end(ctx context.Context) {
	if state, ok := ctx.Value(gduCancelTraceKey{}).(*gduCancelTraceState); ok {
		state.stop()
		state.cancel()
	}
}

func (t *gduWorkerCancelTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// Rollback обязан освободить TX и после отмены испытуемого запроса.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(data.SQL)), "rollback") {
		return context.WithValue(ctx, gduCancelTraceKey{}, nil)
	}
	return t.start(ctx)
}

func (t *gduWorkerCancelTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	t.end(ctx)
}

func (t *gduWorkerCancelTrace) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return t.start(ctx)
}

func (t *gduWorkerCancelTrace) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireEndData) {
	t.end(ctx)
}

func gdDrainOwnedUpdates(w *gdWorld, g *gduClaimGate, pool *pgxpool.Pool) bool {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), gduBarrierDeadline)
	defer cancel()
	var ids []string
	if g != nil {
		g.mu.Lock()
		ids = append(ids, g.recorded...)
		for id, gate := range g.gates {
			close(gate)
			delete(g.gates, id)
		}
		g.mu.Unlock()
	}
	for {
		joined := pool.Stat().AcquiredConns() == 0
		for _, id := range ids {
			op, err := g.Repo.Get(ctx, id)
			if err != nil || !op.Done {
				joined = false
			}
		}
		if joined {
			return true
		}
		select {
		case <-ctx.Done():
			// Красный cleanup нельзя выдать за успех или зависнуть в Close,
			// пока испытуемый ещё удерживает соединение. Никакого global Wait.
			w.t.Error("отмена не завершила owned Update/соединения до Close: ", ctx.Err())
			return false
		case <-time.After(20 * time.Millisecond):
		}
	}
}
