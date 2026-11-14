// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func delegationRevokeParticipant(t *testing.T, w delegationUCWorld) *kanamepg.GrantDelegationRevokeParticipant {
	t.Helper()
	groups, err := kanamepg.NewGroupMembershipParticipant(w.r.ctx, w.r.repo, w.r.bundle)
	require.NoError(t, err)
	bindings, err := groups.NewBindingStageParticipant(w.r.ctx, nil)
	require.NoError(t, err)
	p, err := kanamepg.NewGrantDelegationRevokeParticipant(w.r.ctx, bindings)
	require.NoError(t, err)
	return p
}

// Источник fixture пишет настоящий carrier/subjects/ledger/outbox/fold. Права
// вызывающего проверяет native checker; результатов checker эта проба не задаёт.
func delegationRevokeBindings(t *testing.T, w delegationUCWorld, id string, n int) []string {
	t.Helper()
	ga := seedGroupID(t, w.r.ctx, w.r.admin, w.r.a, "revoke-a-"+ids.NewID("grp"))
	gb := seedGroupID(t, w.r.ctx, w.r.admin, w.r.b, "revoke-b-"+ids.NewID("grp"))
	var out []string
	for i := 0; i < n; i++ {
		sa := seedSAID(t, w.r.ctx, w.r.admin, w.r.a, fmt.Sprintf("revoke-%d-%s", i, ids.NewID("sva")))
		writer, err := lifecycleOwner(w.r).Writer(w.r.ctx)
		require.NoError(t, err)
		b, err := bindingset.Insert(w.r.ctx, writer.AccessBindingsW(), domain.AccessBinding{
			ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeServiceAccount, SubjectID: domain.SubjectID(sa),
			RoleID: domain.RoleID(w.input.RoleIDs[0]), ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount,
			Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}, DelegationID: domain.GrantDelegationID(id),
		})
		require.NoError(t, err)
		tuples := []abrepo.RelationTuple{{User: "service_account:" + sa, Relation: "member", Object: "iam_group:" + ga}, {User: "service_account:" + sa, Relation: "member", Object: "iam_group:" + gb}}
		require.NoError(t, writer.AccessBindingsW().InsertEmittedTuples(w.r.ctx, b.ID, tuples))
		require.NoError(t, writer.AccessBindingsW().EmitRelationWrite(w.r.ctx, tuples))
		require.NoError(t, writer.Commit(w.r.ctx))
		out = append(out, string(b.ID))
	}
	slices.Sort(out)
	return out
}
func delegationRevokeCounts(t *testing.T, w delegationUCWorld, id string) (active, revoked, audit int) {
	t.Helper()
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FILTER(WHERE status='ACTIVE'),count(*) FILTER(WHERE status='REVOKED') FROM kaname.access_bindings WHERE delegation_id=$1`, id).Scan(&active, &revoked))
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.revoked' AND event_payload->>'delegation_id'=$1`, id).Scan(&audit))
	return
}

func TestGrantDelegationStagedRevokeLastPageAtomicRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "last_page_failure"}[fail], func(t *testing.T) {
			w := delegationUCFixture(t)
			id := w.create(t, w.owner, false)
			bs := delegationRevokeBindings(t, w, id, 257)
			var producedBefore []byte
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_agg(jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id)) FROM kaname.relation_fact f JOIN kaname.access_binding_emitted_tuples e ON f.subject=e.fga_user AND f.relation=e.relation AND f.object_type||':'||f.object_id=e.object WHERE e.binding_id=ANY($1::text[])`, bs).Scan(&producedBefore))
			require.NotEmpty(t, producedBefore)
			var projectedBefore int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_array_length($1::jsonb)`, producedBefore).Scan(&projectedBefore))
			require.Equal(t, 514, projectedBefore, "Дано: обе проекции всех 257 carriers существуют")
			var factsBefore int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact`).Scan(&factsBefore))
			require.GreaterOrEqual(t, factsBefore, 514, "положительная предпосылка: обе projection существуют до отзыва")
			if fail {
				_, err := w.r.admin.Exec(w.r.ctx, `CREATE FUNCTION kaname.test_revoke_last_page() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id=`+"'"+bs[len(bs)-1]+"'"+` AND NEW.status='REVOKED' THEN RAISE EXCEPTION 'test staged last-page rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_revoke_last_page BEFORE UPDATE ON kaname.access_bindings FOR EACH ROW EXECUTE FUNCTION kaname.test_revoke_last_page()`)
				require.NoError(t, err)
			}
			p := delegationRevokeParticipant(t, w)
			w.r.strict(t)
			uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(p)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
			require.NoError(t, err)
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			active, revoked, audit := delegationRevokeCounts(t, w, id)
			var st string
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.grant_delegations WHERE id=$1`, id).Scan(&st))
			if fail {
				require.NotNil(t, done.Error)
				require.Equal(t, "ACTIVE", st)
				require.Equal(t, 257, active)
				require.Zero(t, revoked)
				require.Zero(t, audit)
				var factsAfter int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact`).Scan(&factsAfter))
				require.Equal(t, factsBefore, factsAfter)
			} else {
				require.Nil(t, done.Error)
				require.Equal(t, "REVOKED", st)
				require.Zero(t, active)
				require.Equal(t, 257, revoked)
				require.Equal(t, 1, audit)
				var residual int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact f JOIN kaname.access_binding_emitted_tuples e ON f.subject=e.fga_user AND f.relation=e.relation AND f.object_type||':'||f.object_id=e.object WHERE e.binding_id=ANY($1::text[])`, bs).Scan(&residual))
				require.Zero(t, residual, "обе account projection сняты включая последнюю страницу")
				// Удалённый ledger не должен делать проверку остатка пустой.
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact f WHERE jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id) IN (SELECT value FROM jsonb_array_elements($1::jsonb))`, producedBefore).Scan(&residual))
				require.Zero(t, residual, "сами факты отсутствуют по ключам до отзыва")
			}
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// kaname#1034: прежний explicit cascade снимает все nonrevoked carriers,
// включая PENDING за первой страницей, вместе с их фактической проекцией.
func TestGrantDelegationStagedRevokeIncludesPendingLastPage(t *testing.T) {
	w := delegationUCFixture(t)
	t.Cleanup(func() { authorityWaitReleased(t, w.r.runtime) })
	id := w.create(t, w.owner, false)
	bindings := delegationRevokeBindings(t, w, id, 257)
	tail := bindings[len(bindings)-1]
	_, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET status='PENDING' WHERE id=$1`, tail)
	require.NoError(t, err)
	var produced []byte
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_agg(jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id)) FROM kaname.relation_fact f JOIN kaname.access_binding_emitted_tuples e ON f.subject=e.fga_user AND f.relation=e.relation AND f.object_type||':'||f.object_id=e.object WHERE e.binding_id=$1`, tail).Scan(&produced))
	require.NotEmpty(t, produced, "Дано: PENDING carrier удерживает настоящую проекцию")
	var projected int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_array_length($1::jsonb)`, produced).Scan(&projected))
	require.Equal(t, 2, projected)
	// Soft revoke сохраняет исторический ledger: revokeEmittedOf в
	// access_binding/unregistered_key.go и binding_withdrawal.go. Проверяем
	// весь состав, а не только count: исчезновение или замена строки — ошибка.
	ledgerBefore, ledgerCountBefore := delegationRevokeLedgerSnapshot(t, w, bindings)
	tailBefore, tailCountBefore := delegationRevokeLedgerSnapshot(t, w, []string{tail})
	require.Equal(t, 514, ledgerCountBefore, "Дано: полный ledger всех 257 carriers")
	require.Equal(t, 2, tailCountBefore, "Дано: два исторических tuples PENDING tail")
	participant := delegationRevokeParticipant(t, w)
	w.r.strict(t)
	uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(participant)
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
	active, revoked, audit := delegationRevokeCounts(t, w, id)
	require.Zero(t, active)
	require.Equal(t, 257, revoked)
	require.Equal(t, 1, audit)
	var state, reason string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status,revocation_reason FROM kaname.access_bindings WHERE id=$1`, tail).Scan(&state, &reason))
	require.Equal(t, "REVOKED", state)
	require.Equal(t, "DELEGATION_REVOKED", reason)
	var facts, effectiveHolders int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact f WHERE jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id) IN (SELECT value FROM jsonb_array_elements($1::jsonb))`, produced).Scan(&facts))
	ledgerAfter, ledgerCountAfter := delegationRevokeLedgerSnapshot(t, w, bindings)
	tailAfter, tailCountAfter := delegationRevokeLedgerSnapshot(t, w, []string{tail})
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples e JOIN kaname.access_bindings b ON b.id=e.binding_id
 WHERE jsonb_build_array(e.fga_user,e.relation,split_part(e.object,':',1),substr(e.object,strpos(e.object,':')+1)) IN (SELECT value FROM jsonb_array_elements($1::jsonb))
 AND b.status='ACTIVE' AND b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at>clock_timestamp())`, produced).Scan(&effectiveHolders))
	// Оба исхода именуются отдельно: retained ledger не является native фактом.
	t.Logf("pending-tail revoke: carriers=%d native_facts=%d effective_holders=%d ledger_before=%d ledger_after=%d tail_before=%d tail_after=%d ledger_sha256_before=%x ledger_sha256_after=%x",
		revoked, facts, effectiveHolders, ledgerCountBefore, ledgerCountAfter, tailCountBefore, tailCountAfter, sha256.Sum256(ledgerBefore), sha256.Sum256(ledgerAfter))
	if facts != 0 || effectiveHolders != 0 || string(ledgerBefore) != string(ledgerAfter) {
		delegationRevokeTailDiagnostics(t, w, produced)
	}
	require.Zero(t, facts, "native facts по двум сохранённым ключам PENDING tail")
	require.Zero(t, effectiveHolders, "исторический ledger не держит действующую выдачу")
	require.Equal(t, tailCountBefore, tailCountAfter, "soft revoke сохраняет две строки ledger PENDING tail")
	require.Equal(t, tailBefore, tailAfter, "сохраняется полный состав исторического ledger PENDING tail")
	require.Equal(t, ledgerCountBefore, ledgerCountAfter, "soft revoke сохраняет ledger всех 257 carriers")
	require.Equal(t, ledgerBefore, ledgerAfter, "сохраняются все поля 514 исторических ledger rows")
}

func TestGrantDelegationStagedRevokeNativeExpiryAfterLegacyWait(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			w := delegationUCFixture(t)
			id := w.create(t, w.owner, false)
			authority := w.grantAdmin(t)
			var deadline time.Time
			interval := "1 hour"
			if expired {
				interval = "1 second"
			}
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(authority), interval).Scan(&deadline))
			p := delegationRevokeParticipant(t, w)
			blocker, err := w.r.admin.Begin(w.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR UPDATE`, id).Scan(new(string)))
			var xid string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(p)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), domain.GrantDelegationID(id))
			require.NoError(t, err)
			semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
			if expired {
				require.Eventually(t, func() bool {
					var passed bool
					e := w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()>$1`, deadline).Scan(&passed)
					return e == nil && passed
				}, 5*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, blocker.Commit(w.r.ctx))
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			if expired {
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
			} else {
				require.Nil(t, done.Error)
			}
			var st string
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.grant_delegations WHERE id=$1`, id).Scan(&st))
			require.Equal(t, map[bool]string{false: "REVOKED", true: "ACTIVE"}[expired], st)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

type delegationRevokeObserved struct {
	factory kaname.GrantDelegationRevokeWriterFactory
	after   func() error
}

func (f delegationRevokeObserved) GrantDelegationRevokeWriter(ctx context.Context, id domain.GrantDelegationID) (kaname.GrantDelegationRevokeWriter, error) {
	w, err := f.factory.GrantDelegationRevokeWriter(ctx, id)
	if err == nil && f.after != nil {
		if hookErr := f.after(); hookErr != nil {
			_ = w.Rollback(context.WithoutCancel(ctx))
			return nil, hookErr
		}
	}
	return w, err
}

func TestGrantDelegationStagedRevokeNativeBackendError(t *testing.T) {
	w := delegationUCFixture(t)
	id := w.create(t, w.owner, false)
	p := delegationRevokeParticipant(t, w)
	f := delegationRevokeObserved{factory: p, after: func() error {
		_, err := w.r.admin.Exec(w.r.ctx, "REVOKE SELECT ON kaname.relation_fact FROM "+pgx.Identifier{w.r.role}.Sanitize())
		return err
	}}
	uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(f)
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
	require.NoError(t, err)
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.NotNil(t, done.Error)
	require.Equal(t, int32(codes.Unavailable), done.Error.Code)
	var st string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.grant_delegations WHERE id=$1`, id).Scan(&st))
	require.Equal(t, "ACTIVE", st)
	authorityWaitReleased(t, w.r.runtime)
}

// Реальный Execute с единственным slot: preflight завершён до staged worker.
// Достижение GD row wait доказывает, что RC entry не просит вторую connection.
func TestGrantDelegationStagedRevokeOneSlotCompleteOrCancel(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancel"}[cancelled], func(t *testing.T) {
			w := delegationUCFixture(t)
			id := w.create(t, w.owner, false)
			cfg := w.r.runtime.Config()
			cfg.MaxConns = 1
			cfg.MinConns = 0
			pool, err := pgxpool.NewWithConfig(w.r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			w.r.runtime = pool
			w.r.repo = kanamepg.New(pool, nil)
			w.door = delegationNativeDoor{r: w.r}
			p := delegationRevokeParticipant(t, w)
			ctx, cancel := context.WithTimeout(w.r.ctx, 10*time.Second)
			defer cancel()
			f := delegationRevokeBounded{factory: p, ctx: ctx}
			blocker, err := w.r.admin.Begin(w.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR UPDATE`, id).Scan(new(string)))
			var xid string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(f)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
			require.NoError(t, err)
			semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
			require.EqualValues(t, 1, pool.Stat().AcquiredConns())
			if cancelled {
				cancel()
			}
			require.NoError(t, blocker.Commit(w.r.ctx))
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			if cancelled {
				require.NotNil(t, done.Error)
			} else {
				require.Nil(t, done.Error)
			}
			require.Eventually(t, func() bool { return pool.Stat().AcquiredConns() == 0 }, 5*time.Second, 10*time.Millisecond)
			var clean bool
			require.NoError(t, pool.QueryRow(w.r.ctx, `SELECT to_regclass('pg_temp.kaname_binding_withdrawal_headers') IS NULL AND to_regclass('pg_temp.kaname_binding_withdrawal_tuples') IS NULL`).Scan(&clean))
			require.True(t, clean)
			var st string
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.grant_delegations WHERE id=$1`, id).Scan(&st))
			require.Equal(t, map[bool]string{false: "REVOKED", true: "ACTIVE"}[cancelled], st)
		})
	}
}

type delegationRevokeBounded struct {
	factory kaname.GrantDelegationRevokeWriterFactory
	ctx     context.Context
}

func (f delegationRevokeBounded) GrantDelegationRevokeWriter(ctx context.Context, id domain.GrantDelegationID) (kaname.GrantDelegationRevokeWriter, error) {
	bounded, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(f.ctx, cancel)
	defer stop()
	defer cancel()
	return f.factory.GrantDelegationRevokeWriter(bounded, id)
}

// Новый carrier после последней RR страницы обязан целиком перестроить stage.
// Параллельный источник здесь — настоящий DB writer; actual delegated Create
// отдельно покрывается integration-полосой AccessBinding.
func TestGrantDelegationStagedRevokeMembershipPhantomRestages(t *testing.T) {
	w := delegationUCFixture(t)
	id := w.create(t, w.owner, false)
	delegationRevokeBindings(t, w, id, 1)
	p := delegationRevokeParticipant(t, w)
	gate := delegationQueueFence(t, w.r)
	gate.acquired(t)
	uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(p)
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
	require.NoError(t, err)
	authorityWaitLock(t, w.r.ctx, w.r.admin)
	// Global coordinator ждёт, значит RR inventory уже закончен.
	added := delegationRevokeBindings(t, w, id, 1)
	require.NoError(t, gate.tx.Commit(w.r.ctx))
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.Nil(t, done.Error)
	active, revoked, audit := delegationRevokeCounts(t, w, id)
	require.Zero(t, active)
	require.Equal(t, 2, revoked)
	require.Equal(t, 1, audit)
	var status string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.access_bindings WHERE id=$1`, added[0]).Scan(&status))
	require.Equal(t, "REVOKED", status)
	authorityWaitReleased(t, w.r.runtime)
}

// Legacy direct-fact row lock ждёт именно staged fold prelock. Если participant
// откладывает этот lock до EmitRelationDelete, истёкший actor ошибочно отзывает
// делегирование: эта отрицательная ветка обязана выявить такой порядок.
func TestGrantDelegationStagedRevokeNativeExpiryAfterFoldWait(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			w := delegationUCFixture(t)
			id := w.create(t, w.owner, false)
			bs := delegationRevokeBindings(t, w, id, 1)
			authority := w.grantAdmin(t)
			var deadline time.Time
			interval := "1 hour"
			if expired {
				interval = "1 second"
			}
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(authority), interval).Scan(&deadline))
			p := delegationRevokeParticipant(t, w)
			blocker, err := w.r.admin.Begin(w.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			var subject string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT f.subject FROM kaname.relation_fact f JOIN kaname.access_binding_emitted_tuples e ON f.subject=e.fga_user AND f.relation=e.relation AND f.object_type||':'||f.object_id=e.object WHERE e.binding_id=$1 ORDER BY f.object_type,f.object_id,f.relation,f.subject LIMIT 1 FOR UPDATE OF f`, bs[0]).Scan(&subject))
			require.NotEmpty(t, subject, "Дано: настоящий folded fact удерживается legacy row locker")
			var xid string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(p)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), domain.GrantDelegationID(id))
			require.NoError(t, err)
			semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
			if expired {
				require.Eventually(t, func() bool {
					var passed bool
					e := w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()>$1`, deadline).Scan(&passed)
					return e == nil && passed
				}, 5*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, blocker.Commit(w.r.ctx))
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			if expired {
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
			} else {
				require.Nil(t, done.Error)
			}
			active, revoked, audit := delegationRevokeCounts(t, w, id)
			if expired {
				require.Equal(t, 1, active)
				require.Zero(t, revoked)
				require.Zero(t, audit)
			} else {
				require.Zero(t, active)
				require.Equal(t, 1, revoked)
				require.Equal(t, 1, audit)
			}
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

func TestGrantDelegationStagedRevokeDoesNotRequireCreatorAuthority(t *testing.T) {
	w := delegationUCFixture(t)
	authority := w.grantAdmin(t)
	id := w.create(t, w.member, false)
	bs := delegationRevokeBindings(t, w, id, 1)
	_, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, string(authority))
	require.NoError(t, err)
	// Потеря права creator сама по себе не отзывает прежнюю выдачу.
	var before string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT status FROM kaname.access_bindings WHERE id=$1`, bs[0]).Scan(&before))
	require.Equal(t, "ACTIVE", before)
	p := delegationRevokeParticipant(t, w)
	uc := gdapp.NewRevokeGrantDelegationUseCase(w.r.repo, w.ops).WithRelationStore(w.door, nil).WithRevokeAuthorityWriter(p)
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.GrantDelegationID(id))
	require.NoError(t, err)
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.Nil(t, done.Error)
	var creator, actor string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT delegated_by_id,revoked_by_id FROM kaname.grant_delegations WHERE id=$1`, id).Scan(&creator, &actor))
	require.Equal(t, w.member, creator)
	require.Equal(t, w.owner, actor)
	active, revoked, audit := delegationRevokeCounts(t, w, id)
	require.Zero(t, active)
	require.Equal(t, 1, revoked)
	require.Equal(t, 1, audit)
}

// Диагностика ограничена двумя заранее сохранёнными ключами, без inventory под
// authority fence. Показывает реальные holders и версии последних событий,
// сохраняя исходные zero assertions и различая ledger от native projection.
func delegationRevokeTailDiagnostics(t *testing.T, w delegationUCWorld, produced []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
	defer cancel()
	var data []byte
	err := w.r.admin.QueryRow(ctx, `WITH keys AS (
 SELECT value->>0 AS subject,value->>1 AS relation,value->>2 AS object_type,value->>3 AS object_id
 FROM jsonb_array_elements($1::jsonb) LIMIT 2
)
SELECT coalesce(jsonb_agg(jsonb_build_object(
 'key',jsonb_build_array(k.subject,k.relation,k.object_type,k.object_id),
 'fact',(SELECT to_jsonb(f) FROM kaname.relation_fact f WHERE f.subject=k.subject AND f.relation=k.relation AND f.object_type=k.object_type AND f.object_id=k.object_id),
 'holders',(SELECT coalesce(jsonb_agg(to_jsonb(h)),'[]'::jsonb) FROM (
   SELECT e.binding_id,b.status,b.revoked_at,b.expires_at,b.delegation_id
   FROM kaname.access_binding_emitted_tuples e JOIN kaname.access_bindings b ON b.id=e.binding_id
   WHERE e.fga_user=k.subject AND e.relation=k.relation AND e.object=k.object_type||':'||k.object_id
   ORDER BY e.binding_id LIMIT 32) h),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(o)),'[]'::jsonb) FROM (
   SELECT id,event_type,payload,created_at FROM kaname.fga_outbox
   WHERE payload->>'user'=k.subject AND payload->>'object'=k.object_type||':'||k.object_id
     AND (payload->>'relation'=k.relation OR payload->'relations' @> to_jsonb(k.relation))
   ORDER BY id DESC LIMIT 8) o)
)),'[]'::jsonb) FROM keys k`, produced).Scan(&data)
	if err != nil {
		t.Errorf("pending-tail diagnostic query: %v", err)
		return
	}
	t.Logf("pending-tail saved-key census (holders<=32, events<=8 per key): %s", data)
}

// Упорядоченный снимок всех полей ledger до/после отзыва: независимый от facts
// oracle не становится пустым вслед за случайным удалением исторического реестра.
func delegationRevokeLedgerSnapshot(t *testing.T, w delegationUCWorld, bindings []string) ([]byte, int) {
	t.Helper()
	var rows []byte
	var count int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY binding_id,member_object_type,member_object_id,fga_user,relation,object),'[]'::jsonb),count(*) FROM kaname.access_binding_emitted_tuples e WHERE binding_id=ANY($1::text[])`, bindings).Scan(&rows, &count))
	return rows, count
}
