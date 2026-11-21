// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Сохраняем исходный PgError до преобразования ошибок в repo: красный прогон
// должен предъявлять SQLSTATE сервера, а не только итоговую прикладную ошибку.
type legacyFenceErrors struct {
	mu   sync.Mutex
	list []*pgconn.PgError
}

func (e *legacyFenceErrors) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (e *legacyFenceErrors) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var original *pgconn.PgError
	if errors.As(data.Err, &original) {
		e.mu.Lock()
		e.list = append(e.list, original)
		e.mu.Unlock()
	}
}

func TestLegacyWriterCompatibilityFencePrecedesBindingDeactivation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()

	// Действующая выдача B и её аккаунт уже зафиксированы до двух участников.
	var actor domain.UserID
	require.NoError(t, r.admin.QueryRow(ctx,
		`SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, r.repo, bindingID, actor, r.a, false)
	var initial string
	require.NoError(t, r.admin.QueryRow(ctx,
		`SELECT status FROM kaname.access_bindings WHERE id=$1`, string(bindingID)).Scan(&initial))
	require.Equal(t, string(domain.AccessBindingStatusActive), initial)

	originals := &legacyFenceErrors{}
	defer func() {
		if !t.Failed() {
			return
		}
		originals.mu.Lock()
		defer originals.mu.Unlock()
		for _, original := range originals.list {
			t.Logf("original PostgreSQL error: SQLSTATE=%s message=%s detail=%s where=%s",
				original.Code, original.Message, original.Detail, original.Where)
		}
	}()

	// У F и R отдельные trusted LOGIN pools с одним соединением: PID снимается
	// до Writer и относится к его транзакции. Observer использует admin pool.
	dedicated := func() (*kanamepg.Repository, int) {
		cfg := r.runtime.Config()
		cfg.MaxConns = 1
		cfg.MinConns = 0
		cfg.ConnConfig.Tracer = originals
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		var pid int
		require.NoError(t, pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
		return kanamepg.New(pool, nil), pid
	}
	forwardRepo, forwardPID := dedicated()
	revokeRepo, revokePID := dedicated()
	require.NotEqual(t, forwardPID, revokePID)
	rollback := func(w kaname.Writer) {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = w.Rollback(cleanup)
	}

	// Настоящая запись F удерживает compatibility fence до конца транзакции.
	forward, err := forwardRepo.Writer(ctx)
	require.NoError(t, err)
	defer rollback(forward)
	serviceAccountID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err = forward.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
		ID: serviceAccountID, AccountID: domain.AccountID(r.a),
		Name: "legacy-fence-forward", Labels: domain.Labels{},
	})
	require.NoError(t, err)

	// Реальный порядок legacy revoke: Writer, advisory B, FOR UPDATE B, UPDATE.
	// Ни один участник не получает фиктивный SQL-замок вместо repo-операции.
	revoke := func() error {
		w, err := revokeRepo.Writer(ctx)
		if err != nil {
			return fmt.Errorf("R Writer: %w", err)
		}
		defer rollback(w)
		if err := w.AdvisoryXactLock(ctx, string(bindingID)); err != nil {
			return fmt.Errorf("R AdvisoryXactLock: %w", err)
		}
		if _, err := w.AccessBindingsW().GetForDeactivation(ctx, bindingID); err != nil {
			return fmt.Errorf("R GetForDeactivation: %w", err)
		}
		if _, err := w.AccessBindingsW().RevokeGuarded(ctx, bindingID, actor); err != nil {
			return fmt.Errorf("R RevokeGuarded: %w", err)
		}
		if err := w.Commit(ctx); err != nil {
			return fmt.Errorf("R Commit: %w", err)
		}
		return nil
	}
	revoked := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		revoked <- revoke()
	}()
	defer func() {
		// Включая Fatal на observer: сначала снимаем ожидания, затем обязательно
		// присоединяем goroutine; rollback не наследует отменённый контекст.
		cancel()
		rollback(forward)
		<-joined
	}()

	// Барьер — наблюдаемое ожидание точного compatibility key у R на F.
	// Дедлайн ограничивает неисправную фикстуру; его истечение не доказывает RED.
	observe, stopObserve := context.WithTimeout(ctx, 8*time.Second)
	defer stopObserve()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		err := r.admin.QueryRow(observe, `SELECT EXISTS (
    SELECT 1 FROM pg_locks
    WHERE pid=$1 AND locktype='advisory' AND mode='ExclusiveLock'
      AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
      AND NOT granted AND $2::int=ANY(pg_blocking_pids($1::int))
)`, revokePID, forwardPID).Scan(&waiting)
		require.NoError(t, err, "observer infrastructure failure before compatibility barrier")
		if waiting {
			break
		}
		select {
		case err := <-revoked:
			t.Fatalf("R completed before observed compatibility barrier: %v", err)
		case <-observe.Done():
			t.Fatalf("compatibility barrier not observed (not a deadlock oracle): %v", observe.Err())
		case <-tick.C:
		}
	}
	stopObserve()

	// На старом порядке R уже держит FOR UPDATE B: чтение F замыкает цикл.
	// При раннем fence R ещё не трогал B: F читает и фиксируется, затем R отзывает.
	bindingLocker, ok := forward.AccessBindings().(interface {
		GetForKeyShare(context.Context, domain.AccessBindingID) (domain.AccessBinding, error)
	})
	require.True(t, ok, "real pg binding reader must support GetForKeyShare")
	_, forwardErr := bindingLocker.GetForKeyShare(ctx, bindingID)
	if forwardErr == nil {
		forwardErr = forward.Commit(ctx)
	}
	if forwardErr != nil {
		rollback(forward)
	}
	revokeErr := <-revoked
	<-joined
	if forwardErr != nil {
		t.Errorf("F must read B and commit its service account: %v", forwardErr)
	}
	if revokeErr != nil {
		t.Errorf("R must revoke B and commit: %v", revokeErr)
	}
	if t.Failed() {
		return
	}

	// Обе полезные операции обязаны сохраниться в базе после обоих COMMIT.
	var finalStatus string
	var serviceAccountPersisted bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT b.status, EXISTS (
    SELECT 1 FROM kaname.service_accounts s WHERE s.id=$2 AND s.account_id=$3
) FROM kaname.access_bindings b WHERE b.id=$1`,
		string(bindingID), string(serviceAccountID), r.a).Scan(&finalStatus, &serviceAccountPersisted))
	require.Equal(t, string(domain.AccessBindingStatusRevoked), finalStatus)
	require.True(t, serviceAccountPersisted, "F service account must survive both commits")
}
