// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

func policyActor(t *testing.T, r protocolRig, account string) domain.Subject {
	t.Helper()
	var uid string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, account).Scan(&uid))
	return domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
}
func policyNewRole(account string) domain.Role {
	return domain.Role{AccountID: domain.AccountID(account), Name: "partition_role", Rules: domain.Rules{{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}}}}
}

// Cleanup регистрируется до assertions: даже ошибочно возвращённый writer
// освобождает единственную leased connection до Pool.Close.
func policyFixtureRollback(w interface{ Rollback(context.Context) error }) {
	if w == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = w.Rollback(ctx)
}

// Каждая strict fixture mutation проходит настоящий signed participant entry.
// Контекст discovery attempt передаётся без подмены глобальным фоновым ctx.
func policyFixtureApply(ctx context.Context, tx pgx.Tx, in kaname.AuthorityWriteIntent, sql string, args ...any) error {
	defer policyFixtureRollback(tx)
	if _, err := protocolEnter(ctx, tx, in, "participant"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func policyFixtureMutation(t *testing.T, r protocolRig, in kaname.AuthorityWriteIntent, sql string, args ...any) (<-chan error, uint32, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	tx, err := r.runtime.Begin(ctx)
	if err != nil {
		cancel()
		require.NoError(t, err)
	}
	pid := tx.Conn().PgConn().PID()
	done, stopped := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(stopped)
		done <- policyFixtureApply(ctx, tx, in, sql, args...)
	}()
	stop := func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(6 * time.Second):
			t.Error("fixture participant не завершился после отмены")
		}
	}
	return done, pid, stop
}

func policyFixtureWaitLock(t *testing.T, r protocolRig, pid uint32, kind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=$1 AND NOT l.granted AND l.locktype=$2 AND cardinality(pg_blocking_pids(l.pid))>0 AND ($2='advisory' OR EXISTS(SELECT 1 FROM pg_locks p WHERE p.pid=l.pid AND p.relation='kaname.authority_policy_epoch'::regclass AND p.mode='RowExclusiveLock' AND p.granted)))`, pid, kind).Scan(&waiting)
		require.NoError(t, err)
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("participant %d не встал на ожидаемый %s lock: %v", pid, kind, ctx.Err())
		}
	}
}

func TestPolicyPartitionIndependentAccountsAndOnePoolSlot(t *testing.T) {
	r := writerProtocolRig(t)
	// Обычный public viewer сохраняется: global READ source не становится
	// global MUTATION fence и не требует удаления seeded/default фактов.
	_, publicErr := r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('cluster','cluster_kacho_root','viewer','system_class:authenticated') ON CONFLICT DO NOTHING`)
	require.NoError(t, publicErr)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	a, err := writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, policyActor(t, r, r.a))
	defer policyFixtureRollback(a)
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceAccounts, a.AuthorityFence().Mode())
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancel()
	b, err := writers.RoleAuthorityWriter(ctx, policyNewRole(r.b), true, policyActor(t, r, r.b))
	defer policyFixtureRollback(b)
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceAccounts, b.AuthorityFence().Mode())
	require.NoError(t, b.Rollback(r.ctx))
	require.NoError(t, a.Rollback(r.ctx))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	one, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	w, err := one.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, policyActor(t, r, r.a))
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.EqualValues(t, 1, pool.Stat().AcquiredConns())
	require.NoError(t, w.Rollback(r.ctx))
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
}
func TestPolicyPartitionNativeForeignLastPageAndGlobalNegative(t *testing.T) {
	r := writerProtocolRig(t)
	actor := policyActor(t, r, r.a)
	// Более двух страниц настоящих native inputs; foreign account обязан войти
	// в held footprint независимо от canonical owner account.
	for i := 0; i < 513; i++ {
		account := r.a
		if i == 512 {
			account = r.b
		}
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('account',$1,$2,$3)`, account, fmt.Sprintf("policy_%04d", i), "user:"+string(actor.ID))
		require.NoError(t, err)
	}
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode())
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, w.AuthorityFence().Accounts())
	require.NoError(t, w.Rollback(r.ctx))
	unknown, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(unknown)
	require.NoError(t, err)
	in := r.intent(r.a)
	in.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	err = policyFixtureApply(r.ctx, unknown, in, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('unknown_native','opaque','admin',$1)`, "user:"+string(actor.ID))
	require.NoError(t, err)
	w, err = writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode())
	require.NoError(t, w.Rollback(r.ctx))
}
func TestPolicyPartitionCompatibilityFactInsertPhantomWaitsForPolicy(t *testing.T) {
	r := writerProtocolRig(t)
	actor := policyActor(t, r, r.a)
	// Реальный direct iam_group viewer имеет локальный scope B. Неизвестный
	// account-native tuple потребовал бы GLOBAL и ждал бы ещё на coordinator.
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-policy-native-phantom',$1,'native-phantom')`, r.b)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.Equal(t, []domain.AccountID{domain.AccountID(r.a)}, w.AuthorityFence().Accounts())
	done, pid, stop := policyFixtureMutation(t, r, r.intent(r.b), `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('iam_group','grp-policy-native-phantom','viewer',$1)`, "user:"+string(actor.ID))
	defer stop()
	// Coordinator B уже пройден: transactionid wait возникает при UPDATE
	// actor policy epoch, который Role(A) удерживает FOR SHARE.
	policyFixtureWaitLock(t, r, pid, "transactionid")
	select {
	case e := <-done:
		t.Fatalf("source завершился до release actor policy guard: %v", e)
	default:
	}
	require.NoError(t, w.Rollback(r.ctx))
	require.NoError(t, <-done)
	w, err = writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode())
	require.Contains(t, w.AuthorityFence().Accounts(), domain.AccountID(r.b))
	require.NoError(t, w.Rollback(r.ctx))
}
func TestPolicyPartitionDiscoveryTokenRejectsOwnerTransferAndABA(t *testing.T) {
	r := writerProtocolRig(t)
	oldActor, newActor := policyActor(t, r, r.a), policyActor(t, r, r.b)
	var before []byte
	keys := []string{"*", "user:" + string(oldActor.ID), "scope:" + r.a}
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&before))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.accounts SET owner_user_id=$2 WHERE id=$1`, r.a, string(newActor.ID))
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.accounts SET owner_user_id=$2 WHERE id=$1`, r.a, string(oldActor.ID))
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	tx, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(tx)
	require.NoError(t, err)
	r.enter(t, tx, r.intent(r.a), "decision")
	var at time.Time
	err = tx.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, before).Scan(&at)
	require.Error(t, err, "owner ABA must invalidate earlier complete discovery")
	require.NoError(t, tx.Rollback(r.ctx))
	var fresh []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&fresh))
	require.NotEqual(t, string(before), string(fresh))
}
func TestPolicyPartitionGlobalGuardBlocksRawNativeInsertAndMetadataIsPrivate(t *testing.T) {
	r := writerProtocolRig(t)
	// Compatibility attestation NULL не должна позволять вызвать lock helper.
	var unauthenticatedTime time.Time
	err := r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock(kaname.authority_policy_epoch_read(ARRAY['*']))`).Scan(&unauthenticatedTime)
	require.Error(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	var epochs []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read(ARRAY['*'])`).Scan(&epochs))
	tx, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(tx)
	require.NoError(t, err)
	intent := r.intent(r.a)
	intent.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	r.enter(t, tx, intent, "decision")
	var at time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, epochs).Scan(&at))
	mutator := r.intent(r.b)
	mutator.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	done, pid, stop := policyFixtureMutation(t, r, mutator, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('account',$1,'policy_global',$2)`, r.b, "user:"+string(policyActor(t, r, r.b).ID))
	defer stop()
	// В strict GLOBAL coordinator предшествует epoch guard. Доказываем
	// настоящий wait, затем положительный commit той же raw SQL mutation.
	policyFixtureWaitLock(t, r, pid, "advisory")
	select {
	case e := <-done:
		t.Fatalf("GLOBAL participant завершился до release: %v", e)
	default:
	}
	// Отмена реально ожидающего entry не выдаёт attestation и не пишет fact.
	stop()
	require.ErrorIs(t, <-done, context.Canceled)
	var count int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='policy_global'`, r.b).Scan(&count))
	require.Zero(t, count)
	done, pid, stop = policyFixtureMutation(t, r, mutator, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('account',$1,'policy_global',$2)`, r.b, "user:"+string(policyActor(t, r, r.b).ID))
	defer stop()
	policyFixtureWaitLock(t, r, pid, "advisory")
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, <-done)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='policy_global'`, r.b).Scan(&count))
	require.Equal(t, 1, count)
	_, err = r.runtime.Exec(r.ctx, `UPDATE kaname.authority_policy_epoch SET revision=0`)
	require.Error(t, err)
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_policy_keys('users','{"id":"forged"}'::jsonb)`)
	require.Error(t, err)
}

type policyDiscoveryTrace struct {
	calls  atomic.Int32
	mutate func(context.Context, int32) error
	err    error
}
type policyTraceKey struct{}

func (t *policyDiscoveryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, policyTraceKey{}, strings.Contains(d.SQL, "SELECT kaname.authority_policy_epoch_read($1::text[])"))
}
func (t *policyDiscoveryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	marked, _ := ctx.Value(policyTraceKey{}).(bool)
	if marked && d.Err == nil {
		n := t.calls.Add(1)
		if t.mutate != nil {
			if err := t.mutate(ctx, n); err != nil {
				t.err = err
			}
		}
	}
}
func TestPolicyPartitionWholeTransactionRetriesAfterDiscoveryAndIsBounded(t *testing.T) {
	for _, always := range []bool{false, true} {
		t.Run(fmt.Sprint(always), func(t *testing.T) {
			r := writerProtocolRig(t)
			actor := policyActor(t, r, r.a)
			// Дано до strict: настоящая группа A и membership actor. UPDATE
			// этой строки меняет actor/group epochs без GLOBAL identity intent.
			_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-policy-retry',$1,'policy-retry')`, r.a)
			require.NoError(t, err)
			_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES('grp-policy-retry','user',$1)`, string(actor.ID))
			require.NoError(t, err)
			require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			tracer := &policyDiscoveryTrace{}
			tracer.mutate = func(attempt context.Context, n int32) error {
				if n == 1 || always {
					tx, e := r.runtime.Begin(attempt)
					if e != nil {
						return e
					}
					in := r.intent(r.a)
					// r.intent сохраняет lawful KindGroup/account A. Даже no-op
					// UPDATE вызывает statement epoch trigger для OLD/NEW actor;
					// GLOBAL entry здесь создал бы цикл с RR phase SHARE gate.
					return policyFixtureApply(attempt, tx, in, `UPDATE kaname.group_members SET member_id=member_id WHERE group_id='grp-policy-retry' AND member_type='user' AND member_id=$1`, string(actor.ID))
				}
				return nil
			}
			cfg := r.runtime.Config()
			cfg.MaxConns = 1
			cfg.MinConns = 0
			cfg.ConnConfig.Tracer = tracer
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
			defer cancel()
			w, err := writers.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, actor)
			defer policyFixtureRollback(w)
			require.NoError(t, tracer.err)
			if always {
				require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
				require.Nil(t, w)
				require.EqualValues(t, 3, tracer.calls.Load())
			} else {
				require.NoError(t, err)
				require.EqualValues(t, 2, tracer.calls.Load())
				require.NoError(t, w.Rollback(r.ctx))
			}
			require.EqualValues(t, 0, pool.Stat().AcquiredConns())
		})
	}
}

func TestPolicyPartitionNewGroupAndNativeRevocationInvalidateDiscovery(t *testing.T) {
	r := writerProtocolRig(t)
	actor := policyActor(t, r, r.a)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-policy-phantom',$1,'policy-phantom')`, r.b)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('account',$1,'policy_revoke',$2)`, r.a, "user:"+string(actor.ID))
	require.NoError(t, err)
	var before []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, []string{"*", "user:" + string(actor.ID), "scope:" + r.a}).Scan(&before))
	_, err = r.admin.Exec(r.ctx, `DELETE FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='policy_revoke'`, r.a)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	tx, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(tx)
	require.NoError(t, err)
	r.enter(t, tx, r.intent(r.a), "decision")
	var at time.Time
	require.Error(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, before).Scan(&at))
	require.NoError(t, tx.Rollback(r.ctx))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	done, pid, stop := policyFixtureMutation(t, r, r.intent(r.b), `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES('grp-policy-phantom','user',$1)`, string(actor.ID))
	defer stop()
	policyFixtureWaitLock(t, r, pid, "transactionid")
	var beforeMember bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.group_members WHERE group_id='grp-policy-phantom' AND member_type='user' AND member_id=$1)`, string(actor.ID)).Scan(&beforeMember))
	require.False(t, beforeMember)
	require.NoError(t, w.Rollback(r.ctx))
	require.NoError(t, <-done)
	w, err = writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.Contains(t, w.AuthorityFence().Accounts(), domain.AccountID(r.b))
	require.NoError(t, w.Rollback(r.ctx))
}

func TestPolicyPartitionSharedSystemDefinitionAndNilMutationOwners(t *testing.T) {
	r := writerProtocolRig(t)
	var roleID string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE is_system ORDER BY id LIMIT 1`).Scan(&roleID))
	var expected []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, []string{"*", "role:" + roleID}).Scan(&expected))
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	a, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(a)
	require.NoError(t, err)
	r.enter(t, a, r.intent(r.a), "decision")
	var at time.Time
	require.NoError(t, a.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, expected).Scan(&at))
	b, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(b)
	require.NoError(t, err)
	r.enter(t, b, r.intent(r.b), "decision")
	ctx, cancel := context.WithTimeout(r.ctx, time.Second)
	defer cancel()
	require.NoError(t, b.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, expected).Scan(&at), "общая definition role должна читаться совместно")
	require.NoError(t, b.Rollback(r.ctx))
	require.NoError(t, a.Rollback(r.ctx))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := writers.RoleAuthorityWriter(r.ctx, domain.Role{IsSystem: true, ClusterID: domain.ClusterID(domain.ClusterSingletonID)}, true, policyActor(t, r, r.a))
	defer policyFixtureRollback(w)
	require.NoError(t, err, "nil mutation owners должны кодироваться как [], не JSON null")
	require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode())
	require.NoError(t, w.Rollback(r.ctx))
}

func TestPolicyPartitionSharedCarrierLatchAndSortedDeferredMultiRoleRevision(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('cluster','cluster_kacho_root','viewer','system_class:authenticated') ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	var roleIDs []string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT array_agg(id ORDER BY id) FROM (SELECT id FROM kaname.roles WHERE is_system ORDER BY id LIMIT 2) r`).Scan(&roleIDs))
	require.Len(t, roleIDs, 2)
	keys := []string{"*", "carrier_latch:role:" + roleIDs[0], "carrier_latch:role:" + roleIDs[1]}
	populationKeys := append(append([]string{}, keys...), "carriers:role:"+roleIDs[0], "carriers:role:"+roleIDs[1])
	var expected, populationBefore []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&expected))
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, populationKeys).Scan(&populationBefore))
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	a, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(a)
	require.NoError(t, err)
	b, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(b)
	require.NoError(t, err)
	ia, ib := r.intent(r.a), r.intent(r.b)
	ia.Kind = kaname.AuthorityBinding
	ib.Kind = kaname.AuthorityBinding
	r.enter(t, a, ia, "decision")
	r.enter(t, b, ib, "decision")
	var at time.Time
	require.NoError(t, a.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, expected).Scan(&at))
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancel()
	require.NoError(t, b.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_lock($1::jsonb)`, expected).Scan(&at))
	// Оба actual source writers завершают apply до первого commit, используя
	// общие system roles в противоположном порядке. Revision UPDATE ещё нет.
	for i, roleID := range roleIDs {
		_, err = a.Exec(ctx, bindingset.With(`INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) VALUES($1,'user',$2,$3,'account',$4,'PENDING')`), fmt.Sprintf("acb-policy-parallel-a-%d", i), string(policyActor(t, r, r.a).ID), roleID, r.a)
		require.NoError(t, err)
	}
	for i := len(roleIDs) - 1; i >= 0; i-- {
		_, err = b.Exec(ctx, bindingset.With(`INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) VALUES($1,'user',$2,$3,'account',$4,'PENDING')`), fmt.Sprintf("acb-policy-parallel-b-%d", i), string(policyActor(t, r, r.b).ID), roleIDs[i], r.b)
		require.NoError(t, err, "общий carrier revision не должен удерживаться через apply")
	}
	var populationDuring []byte
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, populationKeys).Scan(&populationDuring))
	require.Equal(t, string(populationBefore), string(populationDuring))
	// B исполняет настоящий deferred callback, удерживая оба revision rows.
	// A уже завершил apply, но его Commit обязан дать конкретный конфликт,
	// а не ждать B и не сохранить часть своего body.
	_, err = b.Exec(ctx, `SET CONSTRAINTS kaname.policy_carrier_flush IMMEDIATE`)
	require.NoError(t, err)
	err = a.Commit(ctx)
	var conflict *pgconn.PgError
	require.ErrorAs(t, err, &conflict)
	require.Equal(t, "40001", conflict.Code)
	require.Equal(t, "carrier revision is busy", conflict.Message)
	require.NoError(t, b.Commit(ctx))
	var lost, kept int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FILTER(WHERE id LIKE 'acb-policy-parallel-a-%'),count(*) FILTER(WHERE id LIKE 'acb-policy-parallel-b-%') FROM kaname.access_bindings`).Scan(&lost, &kept))
	require.Zero(t, lost)
	require.Equal(t, 2, kept)
	// Старый Role.Update snapshot отклоняется после exclusive population latch.
	check, err := r.runtime.Begin(r.ctx)
	defer policyFixtureRollback(check)
	require.NoError(t, err)
	r.enter(t, check, r.intent(r.a, r.b), "decision")
	require.Error(t, check.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_lock_for_write($1::jsonb,$2::text[])`, populationBefore, keys[1:]).Scan(&at))
	require.NoError(t, check.Rollback(r.ctx))
	var pending int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_policy_carrier_pending`).Scan(&pending))
	require.Zero(t, pending, "deferred queue не должна оставлять persistent мусор")
}

func TestPolicyPartitionForeignActorHomeEntersAccountsAndNativePolicy(t *testing.T) {
	r := writerProtocolRig(t)
	actor := policyActor(t, r, r.a)
	// A — настоящий home/owner source actor, B — единственный mutation owner.
	// Viewer B получен из настоящего read-only binding и production materializer,
	// а не из независимого raw allow. Источник не даёт editor/admin в B.
	viewerBinding := groupLifecycleBinding(t, r, r.b, string(actor.ID), "policy_foreign_viewer", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, viewerBinding))
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND relation='viewer' AND object=$2 AND fga_user=$3`, viewerBinding, "account:"+r.b, "user:"+string(actor.ID)).Scan(&holders))
	require.Positive(t, holders, "viewer должен иметь настоящий materialized source")
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	// Обычный semantic read допускает viewer-вопрос. Mutation writer ниже
	// принимает только заранее объявленные вопросы actual Role Create.
	read, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	defer policyFixtureRollback(read)
	require.NoError(t, err)
	var at time.Time
	require.NoError(t, read.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&at))
	checker := authzcascade.WrapAdmitted(relverdict.NewSemanticTransactionAsker(read, r.bundle, at), personmarks.NewTransaction(read))
	allowed, err := checker.Check(r.ctx, "user:"+string(actor.ID), "viewer", "account:"+r.b)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, read.Rollback(r.ctx))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := writers.RoleAuthorityWriter(r.ctx, policyNewRole(r.b), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err, "foreign source accounts must pass the actual SQL ownership equality gate")
	require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode())
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, w.AuthorityFence().Accounts())
	for _, relation := range []string{"editor", "admin"} {
		allowed, err = w.SemanticRelationChecker().Check(r.ctx, "user:"+string(actor.ID), relation, "account:"+r.b)
		require.NoError(t, err, "объявленный Role Create вопрос %s", relation)
		require.False(t, allowed, "viewer не даёт %s в чужом account", relation)
	}
	// Наличие A+B в fence не разрешает произвольный дополнительный native root.
	allowed, err = w.SemanticRelationChecker().Check(r.ctx, "user:"+string(actor.ID), "viewer", "account:"+r.b)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.False(t, allowed)
	require.NoError(t, grantpolicy.RequireScopeAdministration(r.ctx, w, actor, domain.ScopeAnchor{Type: "account", ID: r.a}))
	// Viewer чужого scope не превращается в D3 administrator вследствие
	// добавления account ownerref: fence metadata не разрешает mutation.
	require.ErrorIs(t, grantpolicy.RequireScopeAdministration(r.ctx, w, actor, domain.ScopeAnchor{Type: "account", ID: r.b}), iamerr.ErrPermissionDenied)
	require.NoError(t, w.Rollback(r.ctx))
}

// Наблюдатель не меняет writer, policy, SQL или ошибки. Барьер ставится ПОСЛЕ
// фактического server COMMIT 40001, до возврата ошибки whole-attempt runner.
// Это не отмена request context LRO: worker использует отдельный контекст.
type carrierCommitTrace struct {
	conflicts atomic.Int32
	first     chan struct{}
	release   chan struct{}
	once      sync.Once
	timedOut  atomic.Bool
}
type carrierCommitTraceKey struct{}

func (p *carrierCommitTrace) resume() { p.once.Do(func() { close(p.release) }) }
func (p *carrierCommitTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, carrierCommitTraceKey{}, strings.EqualFold(strings.TrimSpace(d.SQL), "commit"))
}
func (p *carrierCommitTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	commit, _ := ctx.Value(carrierCommitTraceKey{}).(bool)
	var e *pgconn.PgError
	if !commit || !errors.As(d.Err, &e) || e.Code != "40001" || e.Message != "carrier revision is busy" {
		return
	}
	if p.conflicts.Add(1) != 1 {
		return
	}
	close(p.first)
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-p.release:
	case <-ctx.Done():
	case <-timer.C:
		p.timedOut.Store(true)
	}
}

// Сравнивается весь durable footprint изолированной fixture, включая native
// facts и ledger. Отсутствующая binding не делает проверку дочерних строк
// пустой: счётчики читаются без JOIN к уже откатившейся business строке.
func carrierDurableCounts(t *testing.T, r protocolRig) []int64 {
	t.Helper()
	counts := make([]int64, 8)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
	 (SELECT count(*) FROM kaname.access_bindings),
	 (SELECT count(*) FROM kaname.access_binding_subjects),
	 (SELECT count(*) FROM kaname.access_binding_emitted_tuples),
	 (SELECT count(*) FROM kaname.relation_fact),
	 (SELECT count(*) FROM kaname.fga_outbox),
	 (SELECT count(*) FROM kaname.audit_outbox),
	 (SELECT count(*) FROM kaname.subject_change_outbox),
	 (SELECT count(*) FROM kaname.resource_reconcile_outbox)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5], &counts[6], &counts[7]))
	return counts
}

func TestPolicyCarrierPublicCreateWholeAttemptOutcomes(t *testing.T) {
	for _, outcome := range []string{"live", "expired", "abort"} {
		t.Run(outcome, func(t *testing.T) {
			w := delegationUCFixture(t)
			seed := stageBinding(t, w.r, w.r.a, false)
			template := bindingRow(t, w.r, seed)
			authority := w.grantAdmin(t)
			deadline := grantPreflightDeadline(t, w, authority, outcome == "expired")
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			trace := &carrierCommitTrace{first: make(chan struct{}), release: make(chan struct{})}
			cfg := w.r.runtime.Config()
			if cfg.ConnConfig.Tracer == nil {
				cfg.ConnConfig.Tracer = trace
			} else {
				cfg.ConnConfig.Tracer = multitracer.New(cfg.ConnConfig.Tracer, trace)
			}
			pool, err := pgxpool.NewWithConfig(w.r.ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			// До Close всегда отпускаем tracer, даже при assertion failure.
			defer trace.resume()
			writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, kanamepg.New(pool, nil), w.r.bundle)
			require.NoError(t, err)
			blocker, err := w.r.admin.Begin(w.r.ctx)
			defer policyFixtureRollback(blocker)
			require.NoError(t, err)
			var locked string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT key FROM kaname.authority_policy_epoch WHERE key=$1 FOR UPDATE`, "carriers:role:"+string(template.RoleID)).Scan(&locked))
			before := carrierDurableCounts(t, w.r)
			uc := bindingapp.NewCreateAccessBindingUseCase(w.r.repo, w.ops, w.source).WithBindingDecisions(writers)
			input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.input.DelegateID)}}, Target: domain.AccessTarget{AllInScope: true}}
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), input)
			require.NoError(t, err)
			select {
			case <-trace.first:
			case <-time.After(12 * time.Second):
				t.Fatal("не наблюдался actual Commit 40001 carrier revision is busy")
			}
			require.Equal(t, before, carrierDurableCounts(t, w.r), "первая попытка должна откатить весь body/projection/ledger/audit")
			var pending int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.authority_policy_carrier_pending`).Scan(&pending))
			require.Zero(t, pending)
			if outcome != "abort" {
				grantPreflightPassDeadline(t, w, deadline, outcome == "expired")
				require.NoError(t, blocker.Rollback(w.r.ctx))
			}
			trace.resume()
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			require.False(t, trace.timedOut.Load(), "барьер не должен освобождаться по таймеру")
			var bindings int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND subject_type='service_account' AND subject_id=$2`, template.RoleID, w.input.DelegateID).Scan(&bindings))
			after := carrierDurableCounts(t, w.r)
			switch outcome {
			case "live":
				require.Nil(t, done.Error)
				require.Equal(t, int32(1), trace.conflicts.Load())
				require.Equal(t, 1, bindings)
				require.Equal(t, before[0]+1, after[0])
				require.Equal(t, before[1]+1, after[1])
				require.Equal(t, before[5]+1, after[5], "одна durable audit запись для одного получателя")
			case "expired":
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
				require.Equal(t, int32(1), trace.conflicts.Load())
				require.Zero(t, bindings)
				require.Equal(t, before, after)
			case "abort":
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.Aborted), done.Error.Code)
				require.Equal(t, int32(3), trace.conflicts.Load(), "все три целые попытки достигают actual Commit")
				require.Zero(t, bindings)
				require.Equal(t, before, after)
				require.NoError(t, blocker.Rollback(w.r.ctx))
			}
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.authority_policy_carrier_pending`).Scan(&pending))
			require.Zero(t, pending)
			authorityWaitReleased(t, pool)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// Проверка частной metadata функции от migration owner не выдаёт business
// authority. Граница проверяется полным набором, а не усечённой первой страницей.
func TestPolicyCarrierDeferredFullSetBudget(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := writerProtocolRig(t)
			tx, err := r.admin.Begin(r.ctx)
			defer policyFixtureRollback(tx)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_policy_epoch(key) SELECT 'carriers:role:budget_'||lpad(i::text,4,'0') FROM generate_series(1,$1::integer) i`, count)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id) SELECT pg_current_xact_id(),pg_backend_pid(),'budget_'||lpad(i::text,4,'0') FROM generate_series($1::integer,1,-1) i`, count)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SET CONSTRAINTS kaname.policy_carrier_flush IMMEDIATE`)
			if count == 4097 {
				var overflow *pgconn.PgError
				require.ErrorAs(t, err, &overflow)
				require.Equal(t, "54000", overflow.Code)
				require.Equal(t, "carrier revision budget exceeded", overflow.Message)
			} else {
				require.NoError(t, err)
				var bumped, pending int
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_policy_epoch WHERE key LIKE 'carriers:role:budget_%' AND revision=1`).Scan(&bumped))
				require.Equal(t, count, bumped)
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_policy_carrier_pending WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid()`).Scan(&pending))
				require.Zero(t, pending)
			}
			require.NoError(t, tx.Rollback(r.ctx))
			var residual int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_policy_carrier_pending`).Scan(&residual))
			require.Zero(t, residual)
		})
	}
}
