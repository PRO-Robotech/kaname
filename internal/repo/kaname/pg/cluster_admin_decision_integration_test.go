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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func clusterFinalCall(f clusterParticipantFixture, ctx context.Context, revoke bool) error {
	if revoke {
		_, err := f.revoke.Execute(ctx, iamv1.ClusterGrantSubjectType_USER, f.target)
		return err
	}
	_, err := f.grant.Execute(ctx, iamv1.ClusterGrantSubjectType_USER, f.target)
	return err
}
func clusterFinalSeedTarget(t *testing.T, f clusterParticipantFixture) {
	t.Helper()
	_, err := f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
	require.NoError(t, err)
}
func clusterFinalWait(t *testing.T, f clusterParticipantFixture, blocker pgx.Tx) {
	t.Helper()
	pid := receiptWaitForBlocker(t, f.r.ctx, f.r.admin, int(blocker.Conn().PgConn().PID()))
	var sql string
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&sql))
	require.Contains(t, sql, "authority_cluster_admin_preflight", "достигнут настоящий final preflight, не ранний проверяющий или Begin")
}
func clusterFinalActive(t *testing.T, f clusterParticipantFixture, expected bool) {
	t.Helper()
	var active bool
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1 AND granted_until IS NULL)`, f.target).Scan(&active))
	require.Equal(t, expected, active)
	f.native(t, f.target, expected)
}

func TestClusterAdminFinalDecisionSeesCompatSourceChangeAfterWait(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		action := "grant"
		if revoke {
			action = "revoke"
		}
		for _, change := range []string{"live", "actor-revoked", "actor-unverified", "target-blocked"} {
			if revoke && change == "target-blocked" {
				continue
			}
			t.Run(action+"/"+change, func(t *testing.T) {
				f := newClusterParticipantFixture(t, false)
				if revoke {
					clusterFinalSeedTarget(t, f)
				}
				before := f.auditCount(t, f.target)
				blocker, err := f.r.admin.Begin(f.r.ctx)
				require.NoError(t, err)
				defer policyFixtureRollback(blocker)
				switch change {
				case "actor-revoked":
					_, err = blocker.Exec(f.r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=clock_timestamp() WHERE subject_type='user' AND subject_id=$1`, f.actor)
				case "actor-unverified":
					_, err = blocker.Exec(f.r.ctx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, f.actor)
				case "target-blocked":
					_, err = blocker.Exec(f.r.ctx, `UPDATE kaname.users SET invite_status='BLOCKED' WHERE id=$1`, f.target)
				default:
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.cluster_admin_grants IN ROW EXCLUSIVE MODE`)
				}
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(f.ctx(), 10*time.Second)
				defer cancel()
				done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, revoke) })
				clusterFinalWait(t, f, blocker)
				require.NoError(t, blocker.Commit(f.r.ctx))
				err = lifecycleResult(t, ctx, done)
				if change == "live" {
					require.NoError(t, err)
					clusterFinalActive(t, f, !revoke)
					require.Equal(t, before+1, f.auditCount(t, f.target))
				} else {
					code := codes.PermissionDenied
					if change == "target-blocked" {
						code = codes.FailedPrecondition
					}
					require.Equal(t, code, status.Code(err))
					require.Equal(t, before, f.auditCount(t, f.target))
					clusterFinalActive(t, f, revoke)
					if !revoke {
						f.assertAbsent(t)
					}
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}

func TestClusterAdminFinalDecisionExpiryAfterActualMutationWait(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		action := "grant"
		if revoke {
			action = "revoke"
		}
		for _, barrier := range []string{"legacy-advisory", "grant-row", "fold-row", "cluster-fk", "audit-table"} {
			for _, expire := range []bool{false, true} {
				suffix := "live"
				if expire {
					suffix = "expired"
				}
				t.Run(action+"/"+barrier+"/"+suffix, func(t *testing.T) {
					f := newClusterParticipantFixture(t, false)
					// Уже существующий target создаётся настоящим UC; Grant проверяет также
					// идемпотентный путь, который обязан заново доказать authority.
					clusterFinalSeedTarget(t, f)
					var expires time.Time
					interval := "1 hour"
					if expire {
						interval = "3 seconds"
					}
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=clock_timestamp()+$2::interval WHERE subject_type='user' AND subject_id=$1 RETURNING granted_until`, f.actor, interval).Scan(&expires))
					require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
					before := f.auditCount(t, f.target)
					blocker, err := f.r.admin.Begin(f.r.ctx)
					require.NoError(t, err)
					defer policyFixtureRollback(blocker)
					switch barrier {
					case "legacy-advisory":
						_, err = blocker.Exec(f.r.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "iam:cluster-admin-revoke:"+domain.ClusterSingletonID)
					case "grant-row":
						var held string
						err = blocker.QueryRow(f.r.ctx, `SELECT id FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1 FOR UPDATE`, f.target).Scan(&held)
						require.NotEmpty(t, held)
					case "fold-row":
						var held string
						err = blocker.QueryRow(f.r.ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type='cluster' AND object_id=$1 AND relation='system_admin' AND subject=$2 FOR UPDATE`, domain.ClusterSingletonID, "user:"+f.target).Scan(&held)
						require.Equal(t, "user:"+f.target, held)
					case "cluster-fk":
						var held string
						err = blocker.QueryRow(f.r.ctx, `SELECT id FROM kaname.clusters WHERE id=$1 FOR UPDATE`, domain.ClusterSingletonID).Scan(&held)
						require.Equal(t, domain.ClusterSingletonID, held)
					default:
						_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.audit_outbox IN ACCESS EXCLUSIVE MODE`)
					}
					require.NoError(t, err)
					ctx, cancel := context.WithTimeout(f.ctx(), 10*time.Second)
					defer cancel()
					done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, revoke) })
					clusterFinalWaitOrTerminal(t, f, blocker, done)
					if expire {
						var stillLive bool
						require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT clock_timestamp()<$1::timestamptz`, expires).Scan(&stillLive))
						require.True(t, stillLive, "источник должен истечь во время подтверждённого wait, а не до него")
						require.Eventually(t, func() bool {
							var past bool
							e := f.r.admin.QueryRow(f.r.ctx, `SELECT clock_timestamp()>$1::timestamptz`, expires).Scan(&past)
							return e == nil && past
						}, 4*time.Second, 10*time.Millisecond)
					}
					require.NoError(t, blocker.Commit(f.r.ctx))
					err = lifecycleResult(t, ctx, done)
					if expire {
						require.Equal(t, codes.PermissionDenied, status.Code(err))
						clusterFinalActive(t, f, true)
						require.Equal(t, before, f.auditCount(t, f.target))
					} else {
						require.NoError(t, err)
						clusterFinalActive(t, f, !revoke)
						delta := 0
						if revoke {
							delta = 1
						}
						require.Equal(t, before+delta, f.auditCount(t, f.target))
					}
					authorityWaitReleased(t, f.r.runtime)
				})
			}
		}
	}
}

type clusterFinalRetryAudit struct {
	real   *kanamepg.AuditOutboxEmitter
	calls  int
	always bool
}

func (a *clusterFinalRetryAudit) EmitTx(ctx context.Context, tx service.Tx, event service.AuditEvent) error {
	if err := a.real.EmitTx(ctx, tx, event); err != nil {
		return err
	}
	a.calls++
	if a.always || a.calls == 1 {
		return &pgconn.PgError{Code: "40001", Message: "fixture whole-attempt retry"}
	}
	return nil
}
func TestClusterAdminFinalDecisionWholeBodyRetryAndExhaustion(t *testing.T) {
	for _, always := range []bool{false, true} {
		name := "second-succeeds"
		if always {
			name = "three-abort"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, true)
			audit := &clusterFinalRetryAudit{real: kanamepg.NewAuditOutboxEmitter(f.r.runtime), always: always}
			f.grant.WithAuditEmitter(audit)
			_, err := f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			if always {
				require.Equal(t, codes.Aborted, status.Code(err))
				require.Equal(t, 3, audit.calls)
				f.assertAbsent(t)
			} else {
				require.NoError(t, err)
				require.Equal(t, 2, audit.calls)
				require.Equal(t, 1, f.auditCount(t, f.target))
				clusterFinalActive(t, f, true)
				var n int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'=$1`, "user:"+f.target).Scan(&n))
				require.Equal(t, 1, n)
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}
func TestClusterAdminFinalDecisionCommitRetry(t *testing.T) {
	f := newClusterParticipantFixture(t, true)
	// Только fixture-owned DDL: реальный deferred COMMIT отказ, а не имитация
	// ошибки тела. Sequence не откатывается и позволяет второй попытке завершиться.
	_, err := f.r.admin.Exec(f.r.ctx, `CREATE SEQUENCE kaname.cluster_final_retry_counter;
 CREATE FUNCTION kaname.cluster_final_retry_probe() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 BEGIN
  IF NEW.event_type='iam.cluster_admin.granted' AND nextval('kaname.cluster_final_retry_counter')=1 THEN
   RAISE EXCEPTION 'fixture commit retry' USING ERRCODE='40001';
  END IF; RETURN NULL;
 END $$;
 CREATE CONSTRAINT TRIGGER cluster_final_retry_probe AFTER INSERT ON kaname.audit_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.cluster_final_retry_probe();`)
	require.NoError(t, err)
	_, err = f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
	require.NoError(t, err)
	var calls int
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT last_value FROM kaname.cluster_final_retry_counter`).Scan(&calls))
	require.Equal(t, 2, calls)
	require.Equal(t, 1, f.auditCount(t, f.target))
	clusterFinalActive(t, f, true)
	var n int
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'=$1`, "user:"+f.target).Scan(&n))
	require.Equal(t, 1, n)
	authorityWaitReleased(t, f.r.runtime)
}
func TestClusterAdminFinalDecisionPreflightCancellationAndIdentity(t *testing.T) {
	f := newClusterParticipantFixture(t, true)
	blocker, err := f.r.admin.Begin(f.r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(blocker)
	_, err = blocker.Exec(f.r.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "iam:cluster-admin-revoke:"+domain.ClusterSingletonID)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(f.ctx())
	defer cancel()
	done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, false) })
	clusterFinalWaitOrTerminal(t, f, blocker, done)
	cancel()
	require.Error(t, lifecycleResult(t, f.r.ctx, done))
	f.assertAbsent(t)
	policyFixtureRollback(blocker)
	authorityWaitReleased(t, f.r.runtime)
	called := false
	_, err = f.participant.RunAdminDecision(f.ctx(), clusterapp.AdminDecisionIntent{Action: clusterapp.AdminActionGrant, Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.keeper)}, Target: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.target)}}, func(context.Context, service.Tx) (domain.ClusterAdminGrant, error) {
		called = true
		return domain.ClusterAdminGrant{}, nil
	})
	require.Error(t, err)
	require.False(t, called, "caller supplied actor не заменяет authenticated context")
	f.assertAbsent(t)
	_, err = f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
	require.NoError(t, err)
	clusterFinalActive(t, f, true)
}

func TestClusterAdminFinalDecisionOutboxCoordinateAfterNewerProducer(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "reactivate"
		if revoke {
			name = "revoke"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, false)
			clusterFinalSeedTarget(t, f)
			fence, err := f.r.runtime.Begin(f.r.ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(fence)
			f.r.enter(t, fence, f.r.intent(f.r.a), "participant")
			ctx, cancel := context.WithTimeout(f.ctx(), 10*time.Second)
			defer cancel()
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, revoke) })
			pid := receiptWaitForBlocker(t, ctx, f.r.admin, int(fence.Conn().PgConn().PID()))
			var began time.Time
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT xact_start FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&began))
			// Настоящий producer фиксируется после начала ожидающей public TX.
			// Compat допускает такой raw writer; final decision не использует старый snapshot.
			producer, err := f.r.admin.Begin(ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(producer)
			writer, emitter := kanamepg.NewClusterAdminGrantWriter(f.r.admin), kanamepg.NewFGAOutboxEmitter()
			tuples := []service.RelationTuple{{User: "user:" + f.target, Relation: "system_admin", Object: "cluster:" + domain.ClusterSingletonID}}
			if revoke {
				_, _, err = writer.Grant(ctx, producer, domain.GrantSubjectTypeUser, domain.SubjectID(f.target), f.actor)
				require.NoError(t, err)
				require.NoError(t, emitter.EmitWriteTx(ctx, producer, tuples))
			} else {
				_, err = writer.Revoke(ctx, producer, domain.GrantSubjectTypeUser, domain.SubjectID(f.target), f.actor)
				require.NoError(t, err)
				require.NoError(t, emitter.EmitDeleteTx(ctx, producer, tuples))
			}
			var newer time.Time
			require.NoError(t, producer.QueryRow(ctx, `SELECT max(created_at) FROM kaname.fga_outbox WHERE payload->>'user'=$1`, "user:"+f.target).Scan(&newer))
			require.True(t, newer.After(began))
			require.NoError(t, producer.Commit(ctx))
			require.NoError(t, fence.Commit(ctx))
			require.NoError(t, lifecycleResult(t, ctx, done))
			clusterFinalActive(t, f, !revoke)
			var source, stamp time.Time
			var versioned bool
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT CASE WHEN $2 THEN granted_until ELSE granted_at END FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1`, f.target, revoke).Scan(&source))
			require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT created_at,payload ? 'source_version' FROM kaname.fga_outbox WHERE payload->>'user'=$1 ORDER BY id DESC LIMIT 1`, "user:"+f.target).Scan(&stamp, &versioned))
			require.Equal(t, source, stamp)
			require.True(t, stamp.After(newer))
			require.False(t, versioned, "legacy tuple payload не становится owner-ordered")
			if !revoke {
				var folded time.Time
				require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT source_version FROM kaname.relation_fact WHERE object_type='cluster' AND object_id=$1 AND relation='system_admin' AND subject=$2`, domain.ClusterSingletonID, "user:"+f.target).Scan(&folded))
				require.Equal(t, stamp, folded)
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func TestClusterAdminFinalDecisionPreflightRequiresExactAttestation(t *testing.T) {
	f := newClusterParticipantFixture(t, true)
	for _, participant := range []bool{false, true} {
		name := "raw"
		if participant {
			name = "wrong-kind-and-mode"
		}
		t.Run(name, func(t *testing.T) {
			tx, err := f.r.runtime.Begin(f.r.ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(tx)
			if participant {
				f.r.enter(t, tx, f.r.intent(f.r.a), "participant")
			}
			_, err = tx.Exec(f.r.ctx, `SELECT kaname.authority_cluster_admin_preflight('user',$1)`, f.target)
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			require.Equal(t, "42501", pgerr.Code)
			require.NoError(t, tx.Rollback(f.r.ctx))
		})
	}
	clusterFinalSeedTarget(t, f)
	clusterFinalActive(t, f, true)
}

func TestClusterAdminFinalDecisionMachineActorFreshness(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "live"
		if disabled {
			name = "disabled-during-wait"
		}
		t.Run(name, func(t *testing.T) {
			f := newClusterParticipantFixture(t, false)
			sa := seedNativeSA(t, f.r.ctx, f.r.admin, domain.AccountID(f.r.a), "cluster-final-actor")
			_, err := f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, sa)
			require.NoError(t, err)
			native, err := (delegationNativeDoor{f.r}).Check(f.r.ctx, "service_account:"+sa, "system_admin", "cluster:"+domain.ClusterSingletonID)
			require.NoError(t, err)
			require.True(t, native)
			blocker, err := f.r.admin.Begin(f.r.ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(blocker)
			if disabled {
				_, err = blocker.Exec(f.r.ctx, `UPDATE kaname.service_accounts SET enabled=false WHERE id=$1`, sa)
			} else {
				_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.service_accounts IN ROW EXCLUSIVE MODE`)
			}
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(operations.WithPrincipal(f.r.ctx, operations.Principal{Type: "service_account", ID: sa}), 10*time.Second)
			defer cancel()
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return clusterFinalCall(f, ctx, false) })
			clusterFinalWaitOrTerminal(t, f, blocker, done)
			require.NoError(t, blocker.Commit(f.r.ctx))
			err = lifecycleResult(t, ctx, done)
			if disabled {
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				f.assertAbsent(t)
			} else {
				require.NoError(t, err)
				clusterFinalActive(t, f, true)
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

// Сохраняет прежний предел 5 секунд и точный pg_blocking_pids oracle.
// Ранний terminal (включая nil) не принимается за доказательство ожидания.
func clusterFinalWaitOrTerminal(t *testing.T, f clusterParticipantFixture, blocker pgx.Tx, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.r.ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	blockerPID := int(blocker.Conn().PgConn().PID())
	for {
		select {
		case err := <-done:
			t.Fatalf("cluster operation завершилась до preflight wait: blocker=%d code=%s err=%v", blockerPID, status.Code(err), err)
		default:
		}
		var pid int
		var preflight bool
		var event string
		err := f.r.admin.QueryRow(ctx, `SELECT pid,position('authority_cluster_admin_preflight' in query)>0,coalesce(wait_event,'') FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1`, blockerPID).Scan(&pid, &preflight, &event)
		if err == nil {
			require.True(t, preflight, "настоящий blocker достигнут после final preflight: waiter=%d blocker=%d wait_event=%s", pid, blockerPID, event)
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, err, "наблюдение blocker не удалось")
		}
		select {
		case err := <-done:
			t.Fatalf("cluster operation завершилась до preflight wait: blocker=%d code=%s err=%v", blockerPID, status.Code(err), err)
		case <-ctx.Done():
			t.Fatalf("preflight не ждёт конкретный blocker=%d за прежние 5 секунд: %v", blockerPID, ctx.Err())
		case <-tick.C:
		}
	}
}
