// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestReconcileCompatibilityEntryAcquiresAdmissionAndFailsClosed(t *testing.T) {
	for _, mode := range []string{"compatibility", "strict", "missing-helper", "revoked-helper", "missing-entry", "revoked-entry"} {
		t.Run(mode, func(t *testing.T) {
			r := writerProtocolRig(t)
			adapter := kanamepg.NewReconcileAdapter(r.runtime, catalogfixture.Source())
			switch mode {
			case "strict":
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			case "missing-helper":
				_, err := r.admin.Exec(r.ctx, `DROP FUNCTION kaname.authority_parent_prelock_admit_v3()`)
				require.NoError(t, err)
			case "revoked-helper":
				_, err := r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_parent_prelock_admit_v3() FROM `+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
			case "missing-entry":
				_, err := r.admin.Exec(r.ctx, `DROP FUNCTION kaname.authority_reconcile_enter_v3()`)
				require.NoError(t, err)
			case "revoked-entry":
				_, err := r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_reconcile_enter_v3() FROM `+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
			}
			called := false
			err := adapter.WithTx(r.ctx, func(context.Context, reconcile.ReconcileStore) error {
				called = true
				var admitted bool
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a USING(pid)
 WHERE l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND a.usename=$1 AND l.locktype='advisory' AND l.classid=1262569292::oid
 AND l.objid=0::oid AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted)`, r.role).Scan(&admitted))
				require.True(t, admitted, "runtime admission уже удерживается до первого callback")
				return nil
			})
			if mode == "compatibility" {
				require.NoError(t, err)
				require.True(t, called)
				return
			}
			require.False(t, called, "невалидный вход не достигает domain callback")
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			want := "42501"
			if mode == "missing-helper" || mode == "missing-entry" {
				want = "42883"
			}
			require.Equal(t, want, pgerr.Code)
		})
	}
}

// Настоящий callback адаптера пишет audit в той же TX; повтор использует тот
// же pooled backend, а отказ callback откатывает уже выполненную запись.
func TestReconcileCompatibilityEntryWritesAuditAtomically(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared=%t", prepared), func(t *testing.T) {
			r, _ := writerProtocolRigBeforePreparation(t)
			if prepared {
				require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
			}
			r = identityLifecycleSingle(t, r)
			adapter := kanamepg.NewReconcileAdapter(r.runtime, catalogfixture.Source())
			callbackErr := errors.New("reconcile callback rejected after audit")
			for pass := 0; pass < 3; pass++ {
				err := adapter.WithTx(r.ctx, func(ctx context.Context, store reconcile.ReconcileStore) error {
					if err := store.EmitAuditEvent(ctx, abrepo.AuditEvent{
						EventType: abrepo.AuditEventTypeRevoked, Actor: "system:expiry",
						BindingID: "reconcile-admission-audit-probe",
					}); err != nil {
						return err
					}
					if pass == 2 {
						return callbackErr
					}
					return nil
				})
				if pass == 2 {
					require.ErrorIs(t, err, callbackErr)
				} else {
					require.NoError(t, err)
				}
				var count int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type='iam.access_binding.revoked' AND event_payload->>'binding_id'='reconcile-admission-audit-probe'`).Scan(&count))
				require.Equal(t, min(pass+1, 2), count)
			}
		})
	}
}

func TestReconcileCompatibilityAdmissionCancellationRollsBack(t *testing.T) {
	r := writerProtocolRig(t)
	old, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, old)
	_, err = old.Exec(r.ctx, `UPDATE kaname.accounts SET description='held before reconcile admission' WHERE id=$1`, r.a)
	require.NoError(t, err)
	oldPID := int(old.Conn().PgConn().PID())
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	called := make(chan struct{}, 1)
	adapter := kanamepg.NewReconcileAdapter(r.runtime, catalogfixture.Source())
	done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
		return adapter.WithTx(ctx, func(context.Context, reconcile.ReconcileStore) error {
			called <- struct{}{}
			return nil
		})
	})
	waiter := receiptWaitForBlocker(t, r.ctx, r.admin, oldPID)
	cancel()
	require.ErrorIs(t, lifecycleResult(t, r.ctx, done), context.Canceled)
	select {
	case <-called:
		t.Fatal("отменённое ожидание admission не должно достигать callback")
	default:
	}
	require.NoError(t, waitAuthorityPIDRelease(r.ctx, r.admin, waiter))
	var holderRemains bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory'
 AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
 AND mode='ExclusiveLock' AND granted)`, oldPID).Scan(&holderRemains))
	require.True(t, holderRemains, "чужая законная TX не была освобождена отменой")
	require.NoError(t, old.Rollback(r.ctx))
	require.NoError(t, adapter.WithTx(r.ctx, func(context.Context, reconcile.ReconcileStore) error { return nil }))
}

// waitAuthorityPIDRelease подтверждает освобождение exact PID синхронно.
// Каждый SELECT и ожидание тика используют один независимый бюджет cleanup;
// после возврата нет goroutine, которая меняет результаты или держит запрос.
func waitAuthorityPIDRelease(ctx context.Context, pool *pgxpool.Pool, pid int) error {
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var released bool
		if err := pool.QueryRow(cleanup, `SELECT NOT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND (locktype='advisory'
 OR (locktype='relation' AND mode<>'AccessShareLock')))`, pid).Scan(&released); err != nil {
			return fmt.Errorf("проверка освобождения authority PID: %w", err)
		}
		if released {
			return nil
		}
		select {
		case <-cleanup.Done():
			return cleanup.Err()
		case <-tick.C:
		}
	}
}

func TestReconcileCompatibilityEntryDrainsBeforeProtocolRows(t *testing.T) {
	r := writerProtocolRig(t)
	adapter := kanamepg.NewReconcileAdapter(r.runtime, catalogfixture.Source())
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	forward := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		return adapter.WithTx(ctx, func(ctx context.Context, store reconcile.ReconcileStore) error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			// Настоящий domain SELECT после начала drain должен ещё завершаться:
			// drain пока не получил table fences, ожидая наш shared root.
			_, found, err := store.LoadBinding(ctx, domain.AccessBindingID("abnd-entry-cutover-probe"))
			if err != nil {
				return err
			}
			if found {
				return fmt.Errorf("ПРЕДПОСЫЛКА: отсутствующая probe-привязка существует")
			}
			return nil
		})
	})
	select {
	case <-entered:
	case <-time.After(expiryRaceBudget):
		t.Fatal("reconcile callback не начался в отведённом бюджете")
	}
	var exactlyOne bool
	var forwardPID int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*)=1,max(l.pid)
 FROM pg_locks l JOIN pg_stat_activity a USING(pid)
 WHERE a.datname=current_database() AND a.usename=$1 AND l.locktype='advisory'
 AND l.classid=1262569283::oid AND l.objid=0::oid AND l.objsubid=2
 AND l.mode='ShareLock' AND l.granted`, r.role).Scan(&exactlyOne, &forwardPID))
	require.True(t, exactlyOne, "точный runtime callback удерживает lifecycle shared root")
	activation := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		return lifecycleOwner(r).ActivateAuthorityBundle(ctx, r.bundle)
	})
	activationPID := receiptWaitForBlocker(t, r.ctx, r.admin, forwardPID)
	var waitsAtRoot, noDomainFence bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory'
 AND classid=1262569283::oid AND objid=0::oid AND objsubid=2
 AND mode='ExclusiveLock' AND NOT granted), NOT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation'
 AND mode='AccessExclusiveLock' AND granted)`, activationPID).Scan(&waitsAtRoot, &noDomainFence))
	require.True(t, waitsAtRoot, "drain ждёт root, до dependency table fences")
	require.True(t, noDomainFence, "drain не запирает callback tables перед ожиданием protocol row")
	close(release)
	require.NoError(t, lifecycleResult(t, r.ctx, forward))
	require.NoError(t, lifecycleResult(t, r.ctx, activation))
	lifecycleState(t, r, "active", "strict")
}
