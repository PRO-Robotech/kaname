// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type delegationDecisionBarrier struct {
	inner           kaname.GrantDelegationWriterFactory
	subject, object string
	checked         chan struct{}
	resume          chan struct{}
	once            sync.Once
}

func (f *delegationDecisionBarrier) GrantDelegationWriter(ctx context.Context, k kaname.GrantDelegationMutation, d domain.GrantDelegation) (kaname.Writer, error) {
	w, err := f.inner.GrantDelegationWriter(ctx, k, d)
	if err != nil {
		return nil, err
	}
	return &delegationBarrierWriter{Writer: w, barrier: f}, nil
}

type delegationBarrierWriter struct {
	kaname.Writer
	barrier *delegationDecisionBarrier
}

func (w *delegationBarrierWriter) LockGrantDelegationCreate(ctx context.Context, d domain.GrantDelegation) error {
	return w.Writer.(interface {
		LockGrantDelegationCreate(context.Context, domain.GrantDelegation) error
	}).LockGrantDelegationCreate(ctx, d)
}
func (w *delegationBarrierWriter) RefreshGrantDelegationDecision(ctx context.Context) error {
	return w.Writer.(interface{ RefreshGrantDelegationDecision(context.Context) error }).RefreshGrantDelegationDecision(ctx)
}
func (w *delegationBarrierWriter) TransactionRelationChecker(p *authzmodel.Plans) (kaname.RelationChecker, error) {
	c, err := w.Writer.TransactionRelationChecker(p)
	if err != nil {
		return nil, err
	}
	return delegationBarrierChecker{inner: c, barrier: w.barrier}, nil
}

type delegationBarrierChecker struct {
	inner   kaname.RelationChecker
	barrier *delegationDecisionBarrier
}

func (c delegationBarrierChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	allowed, err := c.inner.Check(ctx, subject, relation, object)
	if err != nil || !allowed {
		return allowed, err
	}
	if subject == c.barrier.subject && relation == "admin" && object == c.barrier.object {
		c.barrier.once.Do(func() {
			close(c.barrier.checked)
			select {
			case <-ctx.Done():
			case <-c.barrier.resume:
			}
		})
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	return allowed, nil
}

// Actual public Create уже прошёл нативный Check, но ещё не записал GD.
// Compat raw source UPDATE не может проскочить между этим SELECT и Commit.
func TestDelegationPolicyActualCreateProtectsNativeReadThroughCommit(t *testing.T) {
	for _, mode := range []string{"revoke", "role_change"} {
		t.Run(mode, func(t *testing.T) {
			w := delegationUCFixture(t)
			binding := w.grantAdmin(t)
			barrier := &delegationDecisionBarrier{inner: w.participant, subject: "user:" + w.member, object: "account:" + w.r.a, checked: make(chan struct{}), resume: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(barrier.resume) }) }
			t.Cleanup(unblock)
			uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(barrier)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), w.input)
			require.NoError(t, err)
			select {
			case <-barrier.checked:
			case <-time.After(5 * time.Second):
				t.Fatal("actual native positive не достигнут")
			}
			raw, err := w.r.runtime.Begin(w.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, raw)
			var pid int
			require.NoError(t, raw.QueryRow(w.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			result := make(chan error, 1)
			go func() {
				var e error
				if mode == "revoke" {
					_, e = raw.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, binding)
				} else {
					_, e = raw.Exec(w.r.ctx, `UPDATE kaname.roles SET rules='[]',permissions='[]' WHERE id=$1`, domain.ClusterAdminRoleID)
				}
				result <- e
			}()
			require.Eventually(t, func() bool {
				var blocked bool
				e := w.r.admin.QueryRow(w.r.ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked)
				return e == nil && blocked
			}, 5*time.Second, 10*time.Millisecond, "реальный source writer ждёт protected decision")
			unblock()
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			require.Nil(t, done.Error, "первое решение предшествует source revoke/update")
			select {
			case err = <-result:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("source writer не освобождён")
			}
			require.NoError(t, raw.Commit(w.r.ctx))
			// Public read intentionally stale-positive. Второй actual worker не может
			// повторить разрешение по старому fact после canonical source изменения.
			positive, err := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
			require.NoError(t, err)
			require.True(t, positive)
			again := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(w.participant)
			op, err = again.Execute(declarerCtx(w.r.ctx, w.member), w.input)
			require.NoError(t, err)
			require.NotNil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
			var rows, audit int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, w.input.AccountID, w.input.DelegateID).Scan(&rows))
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND event_payload->>'delegate'=$1`, w.input.DelegateID).Scan(&audit))
			require.Equal(t, 1, rows)
			require.Equal(t, 1, audit)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

func TestDelegationPolicyTypedCallerOnePoolSlotAndMissingCallerClosed(t *testing.T) {
	r := writerProtocolRig(t)
	d := delegationProtocolFixture(t, r, r.a)
	cfg := r.runtime.Config().Copy()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	p, err := kanamepg.NewGrantDelegationParticipant(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	absent, err := p.GrantDelegationWriter(r.ctx, kaname.GrantDelegationCreate, d)
	require.Error(t, err)
	require.Nil(t, absent)
	require.Zero(t, pool.Stat().AcquiredConns())
	ctx, cancel := context.WithTimeout(delegationProtocolContext(r.ctx, d), 5*time.Second)
	defer cancel()
	writer, err := p.GrantDelegationWriter(ctx, kaname.GrantDelegationCreate, d)
	require.NoError(t, err)
	require.EqualValues(t, 1, pool.Stat().AcquiredConns())
	require.Equal(t, kaname.AuthorityFenceAccounts, writer.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.Equal(t, []domain.AccountID{d.AccountID}, writer.(kaname.AuthorityWriter).AuthorityFence().Accounts())
	require.NoError(t, writer.Rollback(ctx))
	require.Zero(t, pool.Stat().AcquiredConns())
}

// Actual group-membership phantom между RR discovery и coordinator entry.
// Старый owner-only план A не мог бы проверить живой holder из нового B.
func TestDelegationPolicyGroupSourcePhantomRestagesBeforeMutation(t *testing.T) {
	w := delegationUCFixture(t)
	group := ids.NewID("grp")
	_, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES($1,$2,'delegation-source-phantom')`, group, w.r.b)
	require.NoError(t, err)
	seed, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	require.NoError(t, err)
	defer seed.Rollback(context.Background())
	binding := domain.AccessBindingID(ids.NewID("acb"))
	_, err = bindingset.Insert(w.r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: binding, SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(group), RoleID: domain.RoleID(domain.ClusterAdminRoleID), ResourceType: "account", ResourceID: w.r.b, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	require.NoError(t, seed.Commit(w.r.ctx))
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	require.NoError(t, engine.ReconcileBinding(w.r.ctx, binding))
	before, err := w.door.Check(w.r.ctx, "user:"+w.owner, "admin", "account:"+w.r.b)
	require.NoError(t, err)
	require.False(t, before)
	d := delegationProtocolFixture(t, w.r, w.r.a)
	gate := delegationQueueFence(t, w.r)
	gate.acquired(t)
	out := delegationStart(t, w.r, w.participant, d)
	authorityWaitLock(t, w.r.ctx, w.r.admin)
	tag, err := gate.tx.Exec(w.r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'user',$2)`, group, w.owner)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, gate.tx.Commit(w.r.ctx))
	got := delegationTake(t, out)
	require.NoError(t, got.err)
	require.NotNil(t, got.writer)
	defer got.writer.Rollback(context.Background())
	fence := got.writer.(kaname.AuthorityWriter).AuthorityFence()
	if fence.Mode() == kaname.AuthorityFenceAccounts {
		require.Contains(t, fence.Accounts(), domain.AccountID(w.r.b))
	}
	checker, err := got.writer.TransactionRelationChecker(nil)
	require.NoError(t, err)
	after, err := checker.Check(w.r.ctx, "user:"+w.owner, "admin", "account:"+w.r.b)
	require.NoError(t, err)
	require.True(t, after, "реальный live foreign holder после full restage")
	_, err = got.writer.AccessBindingsW().GrantDelegationsW().Insert(w.r.ctx, d)
	require.NoError(t, err)
	require.NoError(t, got.writer.Rollback(w.r.ctx))
	var count int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE id=$1`, d.ID).Scan(&count))
	require.Zero(t, count)
	authorityWaitReleased(t, w.r.runtime)
}
