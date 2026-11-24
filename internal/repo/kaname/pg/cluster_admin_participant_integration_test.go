// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type clusterParticipantFixture struct {
	r                     protocolRig
	actor, keeper, target string
	participant           *kanamepg.ClusterAdminParticipant
	grant                 *clusterapp.GrantAdminUseCase
	revoke                *clusterapp.RevokeAdminUseCase
}

func newClusterParticipantFixture(t *testing.T, strict bool) clusterParticipantFixture {
	t.Helper()
	r := writerProtocolRig(t)
	actor := seedMemberUser(t, r.ctx, r.admin, r.a, "cluster-actor")
	keeper := seedMemberUser(t, r.ctx, r.admin, r.a, "cluster-keeper")
	target := seedMemberUser(t, r.ctx, r.admin, r.b, "cluster-target")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{actor, keeper, target})
	require.NoError(t, err)
	// До activation готовим настоящие источники и материализацию. Временный
	// actor остаётся живым, но не входит в прежний count постоянных admin.
	tx, err := r.admin.Begin(r.ctx)
	if tx != nil {
		defer policyFixtureRollback(tx)
	}
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `DELETE FROM kaname.cluster_admin_grants`)
	require.NoError(t, err)
	writer, emitter := kanamepg.NewClusterAdminGrantWriter(r.admin), kanamepg.NewFGAOutboxEmitter()
	for _, id := range []string{actor, keeper} {
		_, created, err := writer.Grant(r.ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(id), actor)
		require.NoError(t, err)
		require.True(t, created)
		require.NoError(t, emitter.EmitWriteTx(r.ctx, tx, []service.RelationTuple{{User: "user:" + id, Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID}}))
	}
	_, err = tx.Exec(r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=clock_timestamp()+interval '1 hour' WHERE subject_id=$1`, actor)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
	if strict {
		require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	}
	p, err := kanamepg.NewClusterAdminParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	ops := operations.NewRepo(r.runtime, "kaname")
	rw := kanamepg.NewClusterAdminGrantWriter(r.runtime)
	audit := kanamepg.NewAuditOutboxEmitter(r.runtime)
	door := delegationNativeDoor{r}
	allowed, err := door.Check(r.ctx, "user:"+actor, "system_admin", "cluster:"+domain.ClusterSingletonID)
	require.NoError(t, err)
	require.True(t, allowed, "настоящий canonical source и native checker")
	grant := clusterapp.NewGrantAdminUseCase(rw, kanamepg.NewClusterAdminGrantReader(r.runtime), emitter, kanamepg.NewPoolTxBeginner(r.runtime), ops).
		WithSubjectStateReader(kanamepg.NewSubjectStateReader(r.runtime)).WithAdminChecker(door).WithAuditEmitter(audit)
	revoke := clusterapp.NewRevokeAdminUseCase(rw, emitter, kanamepg.NewPoolTxBeginner(r.runtime), ops).WithAdminChecker(door).WithAuditEmitter(audit)
	clusterapp.NewHandler(nil, grant, revoke, nil).WithAdminTxBeginner(p)
	return clusterParticipantFixture{r, actor, keeper, target, p, grant, revoke}
}

func (f clusterParticipantFixture) ctx() context.Context { return declarerCtx(f.r.ctx, f.actor) }
func (f clusterParticipantFixture) auditCount(t *testing.T, subject string) int {
	t.Helper()
	var n int
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'subject_id'=$1 AND event_type IN ('iam.cluster_admin.granted','iam.cluster_admin.revoked')`, subject).Scan(&n))
	return n
}
func (f clusterParticipantFixture) native(t *testing.T, subject string, expected bool) {
	t.Helper()
	allowed, err := (delegationNativeDoor{f.r}).Check(f.r.ctx, "user:"+subject, "system_admin", "cluster:"+domain.ClusterSingletonID)
	require.NoError(t, err)
	require.Equal(t, expected, allowed)
}
func (f clusterParticipantFixture) assertAbsent(t *testing.T) {
	t.Helper()
	var rows, facts, outbox int
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT (SELECT count(*) FROM kaname.cluster_admin_grants WHERE subject_id=$1),(SELECT count(*) FROM kaname.relation_fact WHERE subject='user:'||$1 AND object_type='cluster' AND object_id=$2 AND relation='system_admin'),(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'='user:'||$1)`, f.target, domain.ClusterSingletonID).Scan(&rows, &facts, &outbox))
	require.Zero(t, rows)
	require.Zero(t, facts)
	require.Zero(t, outbox)
	require.Zero(t, f.auditCount(t, f.target))
}

func TestClusterAdminParticipantActualUCPreparedAndStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "prepared"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, strict)
			op, err := f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.NoError(t, err)
			require.True(t, op.GetDone())
			require.Nil(t, op.GetError())
			var original string
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT id FROM kaname.cluster_admin_grants WHERE subject_id=$1`, f.target).Scan(&original))
			f.native(t, f.target, true)
			require.Equal(t, 1, f.auditCount(t, f.target))
			_, err = f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.NoError(t, err)
			require.Equal(t, 1, f.auditCount(t, f.target))
			_, err = f.revoke.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.NoError(t, err)
			f.native(t, f.target, false)
			_, err = f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.NoError(t, err)
			f.native(t, f.target, true)
			var reactivated string
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT id FROM kaname.cluster_admin_grants WHERE subject_id=$1 AND granted_until IS NULL`, f.target).Scan(&reactivated))
			require.Equal(t, original, reactivated)
			require.Equal(t, 3, f.auditCount(t, f.target))
			_, err = f.revoke.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.keeper)
			require.NoError(t, err)
			_, err = f.revoke.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Contains(t, err.Error(), "last active")
			f.native(t, f.target, true)
			require.Equal(t, 3, f.auditCount(t, f.target))
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

type clusterParticipantFaultAudit struct {
	real     *kanamepg.AuditOutboxEmitter
	cancel   context.CancelFunc
	inserted bool
}

func (a *clusterParticipantFaultAudit) EmitTx(ctx context.Context, tx service.Tx, event service.AuditEvent) error {
	if err := a.real.EmitTx(ctx, tx, event); err != nil {
		return err
	}
	a.inserted = true
	if a.cancel != nil {
		a.cancel()
		return ctx.Err()
	}
	return errors.New("cluster participant audit fault after insert")
}
func TestClusterAdminParticipantActualUCRollbackAndCancel(t *testing.T) {
	for _, cancelAfterEmit := range []bool{false, true} {
		name := "audit-error"
		if cancelAfterEmit {
			name = "cancel-after-emit"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, true)
			ctx, cancel := context.WithCancel(f.ctx())
			defer cancel()
			fault := clusterParticipantFaultAudit{real: kanamepg.NewAuditOutboxEmitter(f.r.runtime)}
			if cancelAfterEmit {
				fault.cancel = cancel
			}
			f.grant.WithAuditEmitter(&fault)
			_, err := f.grant.Execute(ctx, iamv1.ClusterGrantSubjectType_USER, f.target)
			require.Error(t, err)
			require.True(t, fault.inserted, "отказ должен происходить после настоящих grant/fga/audit INSERT")
			f.assertAbsent(t)
			f.native(t, f.target, false)
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func TestClusterAdminParticipantWaitsBeforeMutationAndCancels(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		name := "release"
		if cancelWait {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, true)
			blocker, err := f.r.runtime.Begin(f.r.ctx)
			if blocker != nil {
				defer policyFixtureRollback(blocker)
			}
			require.NoError(t, err)
			f.r.enter(t, blocker, f.r.intent(f.r.a), "participant")
			ctx, cancel := context.WithTimeout(f.ctx(), 10*time.Second)
			defer cancel()
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				_, err := f.grant.Execute(ctx, iamv1.ClusterGrantSubjectType_USER, f.target)
				return err
			})
			receiptWaitForBlocker(t, f.r.ctx, f.r.admin, int(blocker.Conn().PgConn().PID()))
			f.assertAbsent(t)
			if cancelWait {
				cancel()
				require.Error(t, lifecycleResult(t, f.r.ctx, done))
				f.assertAbsent(t)
			} else {
				require.NoError(t, blocker.Commit(f.r.ctx))
				require.NoError(t, lifecycleResult(t, ctx, done))
				f.native(t, f.target, true)
			}
			policyFixtureRollback(blocker)
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func TestClusterAdminParticipantClosedCanceledAndRuntimeCannotSelfEnable(t *testing.T) {
	f := newClusterParticipantFixture(t, true)
	// Тот же LOGIN не может писать сырое authority-state или сам открыть bundle.
	_, err := f.r.runtime.Exec(f.r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=NULL WHERE subject_id=$1`, f.actor)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "42501", pgerr.Code)
	require.Error(t, f.r.repo.ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
	_, err = kanamepg.NewClusterAdminParticipant(f.r.ctx, lifecycleOwner(f.r), f.r.bundle)
	require.Error(t, err, "migration owner не runtime LOGIN")
	_, err = kanamepg.NewClusterAdminParticipant(f.r.ctx, f.r.repo, nil)
	require.Error(t, err)
	ctx, cancel := context.WithCancel(f.ctx())
	cancel()
	tx, err := f.participant.Begin(ctx)
	if tx != nil {
		policyFixtureRollback(tx)
	}
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, tx)
	require.NoError(t, lifecycleOwner(f.r).CloseAuthorityBundle(f.r.ctx))
	tx, err = f.participant.Begin(f.ctx())
	if tx != nil {
		policyFixtureRollback(tx)
	}
	require.Error(t, err)
	require.Nil(t, tx, "закрытый handoff не допускает legacy fallback")
	f.assertAbsent(t)
	authorityWaitReleased(t, f.r.runtime)
}
