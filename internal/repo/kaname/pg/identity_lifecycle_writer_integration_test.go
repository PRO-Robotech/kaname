// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func identityLifecycleSingle(t *testing.T, r protocolRig) protocolRig {
	t.Helper()
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	r.runtime, r.repo = pool, kanamepg.New(pool, nil)
	return r
}
func identityLifecycleExecute(t *testing.T, r protocolRig, f kaname.IdentityLifecycleWriterFactory, kind kaname.IdentityMutation, uid domain.UserID) *operations.Operation {
	t.Helper()
	ops := operations.NewRepo(r.runtime, "kaname")
	ctx := declarerCtx(r.ctx, bindingPublicOwner(t, r))
	var op *operations.Operation
	var err error
	switch kind {
	case kaname.IdentityUpdate:
		op, err = userapp.NewUpdateUserUseCase(r.repo, ops).WithIdentityLifecycleWriter(f).Execute(ctx, userapp.UpdateUserInput{ID: uid, Labels: domain.Labels{"tier": "gold"}, UpdateMask: []string{"labels"}})
	case kaname.IdentityDelete:
		op, err = userapp.NewDeleteUserUseCase(r.repo, ops).WithIdentityLifecycleWriter(f).Execute(ctx, uid)
	case kaname.IdentityBlock:
		op, err = userapp.NewBlockUserUseCase(r.repo, ops).WithIdentityLifecycleWriter(f).Execute(ctx, uid)
	case kaname.IdentityUnblock:
		op, err = userapp.NewUnblockUserUseCase(r.repo, ops).WithIdentityLifecycleWriter(f).Execute(ctx, uid)
	default:
		t.Fatalf("неизвестный тестовый intent %q", kind)
	}
	require.NoError(t, err)
	return awaitOperation(t, ctx, ops, op.ID)
}
func identityLifecycleAudit(t *testing.T, r protocolRig, uid domain.UserID, event string) {
	t.Helper()
	var n int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->>'resource_id'=$2`, event, string(uid)).Scan(&n))
	require.Equal(t, 1, n)
}
func identityLifecycleCutoff(t *testing.T, r protocolRig, uid domain.UserID) time.Time {
	t.Helper()
	var at time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT revoke_before FROM kaname.minted_token_revocations WHERE subject=$1`, string(uid)).Scan(&at))
	require.False(t, at.IsZero())
	return at
}

// Настоящие четыре worker, обычный LOGIN и один pool slot в обоих режимах.
func TestIdentityLifecycleActualWorkersPreparedAndStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := identityLifecycleSingle(t, writerProtocolRig(t))
			uid := domain.UserID(seedMemberUser(t, r.ctx, r.admin, r.a, "identity-lifecycle"))
			p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
			require.NoError(t, err)
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			require.Nil(t, identityLifecycleExecute(t, r, p, kaname.IdentityUpdate, uid).Error)
			var label string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT labels->>'tier' FROM kaname.users WHERE id=$1`, string(uid)).Scan(&label))
			require.Equal(t, "gold", label)
			identityLifecycleAudit(t, r, uid, "iam.user.updated")
			var reconcile int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='iam.user' AND object_id=$1`, string(uid)).Scan(&reconcile))
			require.Positive(t, reconcile)
			require.Nil(t, identityLifecycleExecute(t, r, p, kaname.IdentityBlock, uid).Error)
			var state string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT invite_status FROM kaname.users WHERE id=$1`, string(uid)).Scan(&state))
			require.Equal(t, string(domain.InviteStatusBlocked), state)
			blockedAt := identityLifecycleCutoff(t, r, uid)
			var identityAt time.Time
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT revoke_before FROM kaname.user_token_revocations WHERE user_id=$1`, string(uid)).Scan(&identityAt))
			require.True(t, identityAt.Equal(blockedAt))
			identityLifecycleAudit(t, r, uid, "iam.user.blocked")
			require.Nil(t, identityLifecycleExecute(t, r, p, kaname.IdentityUnblock, uid).Error)
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT invite_status FROM kaname.users WHERE id=$1`, string(uid)).Scan(&state))
			require.Equal(t, string(domain.InviteStatusActive), state)
			require.True(t, blockedAt.Equal(identityLifecycleCutoff(t, r, uid)), "снятие запрета не оживляет старые удостоверения")
			identityLifecycleAudit(t, r, uid, "iam.user.unblocked")
			require.Nil(t, identityLifecycleExecute(t, r, p, kaname.IdentityDelete, uid).Error)
			var users, events, tuples int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.users WHERE id=$1),(SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='iam.user' AND object_id=$1),(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'='user:'||$1)`, string(uid)).Scan(&users, &events, &tuples))
			require.Zero(t, users)
			require.Greater(t, events, reconcile)
			require.Positive(t, tuples)
			require.False(t, identityLifecycleCutoff(t, r, uid).Before(blockedAt))
			identityLifecycleAudit(t, r, uid, "iam.user.deleted")
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// Снимок конечного исхода не включает таблицу Operation: её ошибка обязана сохраниться.
func identityLifecycleSnapshot(t *testing.T, r protocolRig, uid domain.UserID) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'user',(SELECT to_jsonb(u) FROM kaname.users u WHERE id=$1),
 'identity_cutoff',(SELECT to_jsonb(c) FROM kaname.user_token_revocations c WHERE user_id=$1),
 'minted_cutoff',(SELECT to_jsonb(c) FROM kaname.minted_token_revocations c WHERE subject=$1),
 'audit',(SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id'=$1),
 'reconcile',(SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_id=$1),
 'fga',(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'='user:'||$1)
 )::text`, string(uid)).Scan(&snapshot))
	return snapshot
}

type identityAuditFailure struct {
	kaname.IdentityLifecycleWriterFactory
	reached bool
}

func (f *identityAuditFailure) IdentityLifecycleWriter(ctx context.Context, k kaname.IdentityMutation, id domain.UserID) (kaname.Writer, error) {
	w, err := f.IdentityLifecycleWriterFactory.IdentityLifecycleWriter(ctx, k, id)
	if err != nil {
		return nil, err
	}
	cleanup, cancel := context.WithCancel(ctx)
	return &identityAuditFailureWriter{Writer: w, f: f, cleanup: cleanup, cancel: cancel}, nil
}

type identityAuditFailureWriter struct {
	kaname.Writer
	f       *identityAuditFailure
	cleanup context.Context
	cancel  context.CancelFunc
}

func (w *identityAuditFailureWriter) EmitAuditEvent(ctx context.Context, e service.AuditEvent) error {
	// Отказ ПОСЛЕ реальной мутации и записи аудита, в той же транзакции.
	if err := w.Writer.EmitAuditEvent(ctx, e); err != nil {
		return err
	}
	w.f.reached = true
	w.cancel()
	return errors.New("контролируемый поздний отказ аудита")
}
func (w *identityAuditFailureWriter) Rollback(context.Context) error {
	defer w.cancel()
	return w.Writer.Rollback(w.cleanup)
}
func TestIdentityLifecycleActualMutationAuditFailureRollsBack(t *testing.T) {
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	kinds := []kaname.IdentityMutation{kaname.IdentityUpdate, kaname.IdentityDelete, kaname.IdentityBlock, kaname.IdentityUnblock}
	targets := make(map[kaname.IdentityMutation]domain.UserID)
	for _, k := range kinds {
		targets[k] = domain.UserID(seedMemberUser(t, r.ctx, r.admin, r.a, "identity-rollback-"+string(k)))
		if k == kaname.IdentityUnblock {
			_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET invite_status='BLOCKED' WHERE id=$1`, string(targets[k]))
			require.NoError(t, err)
		}
	}
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			uid := targets[kind]
			before := identityLifecycleSnapshot(t, r, uid)
			f := &identityAuditFailure{IdentityLifecycleWriterFactory: p}
			op := identityLifecycleExecute(t, r, f, kind, uid)
			require.NotNil(t, op.Error)
			require.True(t, f.reached, "ошибка должна быть после настоящего тела, не raw-denial")
			require.Equal(t, before, identityLifecycleSnapshot(t, r, uid))
			authorityWaitReleased(t, r.runtime)
			require.Nil(t, identityLifecycleExecute(t, r, p, kind, uid).Error)
		})
	}
}

func TestIdentityLifecycleGlobalWaitCancellationAndClosedBundle(t *testing.T) {
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	uid := domain.UserID(seedMemberUser(t, r.ctx, r.admin, r.a, "identity-wait"))
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	// Блокирующая account TX идёт по другому ordinary LOGIN pool, чтобы единственный
	// slot проверяемого pool был свободен именно для GLOBAL waiter.
	blockerRepo := kanamepg.New(writerIdentityOtherPool(t, r), nil)
	held, err := blockerRepo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	defer policyFixtureRollback(held)
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	defer cancel()
	go func() {
		w, e := p.IdentityLifecycleWriter(ctx, kaname.IdentityRemoveFromAccount, uid)
		if e == nil {
			policyFixtureRollback(w)
		}
		done <- e
	}()
	authorityWaitLock(t, r.ctx, r.admin)
	cancel()
	select {
	case err = <-done:
		require.Error(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("GLOBAL waiter не завершился после отмены")
	}
	require.NoError(t, held.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=repeat('f',64)`)
	require.NoError(t, err)
	for _, k := range []kaname.IdentityMutation{kaname.IdentityUpdate, kaname.IdentityDelete, kaname.IdentityBlock, kaname.IdentityUnblock, kaname.IdentityRemoveFromAccount} {
		w, e := p.IdentityLifecycleWriter(r.ctx, k, uid)
		require.Error(t, e)
		require.Nil(t, w)
	}
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=$1`, r.bundle.Identity().ModelID)
	require.NoError(t, err)
	twin, err := p.IdentityLifecycleWriter(r.ctx, kaname.IdentityRemoveFromAccount, uid)
	require.NoError(t, err)
	require.NoError(t, twin.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	for _, k := range []kaname.IdentityMutation{kaname.IdentityUpdate, kaname.IdentityDelete, kaname.IdentityBlock, kaname.IdentityUnblock, kaname.IdentityRemoveFromAccount} {
		w, e := p.IdentityLifecycleWriter(r.ctx, k, uid)
		require.Error(t, e)
		require.Nil(t, w)
	}
	authorityWaitReleased(t, r.runtime)
}
func writerIdentityOtherPool(t *testing.T, r protocolRig) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.NewWithConfig(r.ctx, r.runtime.Config())
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
