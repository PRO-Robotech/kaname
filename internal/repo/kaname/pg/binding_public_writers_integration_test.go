// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func withdrawalParticipant(t *testing.T, r protocolRig, tracer pgx.QueryTracer) *kanamepg.BindingStageParticipant {
	t.Helper()
	if tracer != nil {
		cfg := r.runtime.Config()
		cfg.ConnConfig.Tracer = tracer
		pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		r.runtime = pool
		r.repo = kanamepg.New(pool, nil)
	}
	p, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	staged, err := p.NewBindingStageParticipant(r.ctx, slog.Default())
	require.NoError(t, err)
	return staged
}
func bindingPublicOwner(t *testing.T, r protocolRig) string {
	t.Helper()
	var uid string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&uid))
	return uid
}
func bindingRow(t *testing.T, r protocolRig, id domain.AccessBindingID) domain.AccessBinding {
	t.Helper()
	rd, err := r.repo.Reader(r.ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(context.WithoutCancel(r.ctx)) }()
	b, err := rd.AccessBindings().Get(r.ctx, id)
	require.NoError(t, err)
	b.Subjects, err = rd.AccessBindings().ListSubjects(r.ctx, id)
	require.NoError(t, err)
	return b
}

// Срок задаётся после created_at и дожидается истечения по часам базы:
// constraint остаётся включён, а исходное время создания не переписывается.
func expireBindingFixture(t *testing.T, r protocolRig, ids ...domain.AccessBindingID) {
	t.Helper()
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = string(id)
	}
	tag, err := r.runtime.Exec(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '50 milliseconds' WHERE id=ANY($1::text[])`, keys)
	require.NoError(t, err)
	require.EqualValues(t, len(keys), tag.RowsAffected())
	require.Eventually(t, func() bool {
		var expired bool
		err := r.runtime.QueryRow(r.ctx, `SELECT count(*)=$2 AND bool_and(created_at<expires_at AND expires_at<clock_timestamp()) FROM kaname.access_bindings WHERE id=ANY($1::text[])`, keys, len(keys)).Scan(&expired)
		return err == nil && expired
	}, 5*time.Second, 10*time.Millisecond)
}

// kaname#1034: настоящий API/LRO, ordinary LOGIN и actual native checker;
// owner передан production source, не fake allow checker или invented tuple.
func TestBindingPublicActualCreateMetadataUpdateRevokeDelete(t *testing.T) {
	r := writerProtocolRig(t)
	owner := bindingPublicOwner(t, r)
	recipient := seedMemberUser(t, r.ctx, r.admin, r.a, "binding-public-recipient-"+ids.NewID("usr"))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, recipient)
	require.NoError(t, err)
	seed := stageBinding(t, r, r.a, false)
	template := bindingRow(t, r, seed)
	// Реальная роль доступа к объекту выдачи сохраняет прежний v_delete method gate.
	groupLifecycleBinding(t, r, r.a, owner, "binding_public_method", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "delete"}})
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	staged := withdrawalParticipant(t, r, nil)
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	relations := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	ops := operations.NewRepo(r.runtime, "kaname")
	create := bindingapp.NewCreateAccessBindingUseCase(r.repo, ops, rolePolicyCatalog(t, r)).WithBindingDecisions(writers)
	update := bindingapp.NewUpdateAccessBindingUseCase(r.repo, ops).WithBindingDecisions(writers)
	revoke := bindingapp.NewRevokeAccessBindingUseCase(r.repo, ops).WithBindingWithdrawal(staged).WithRelationStore(relations, slog.Default())
	remove := bindingapp.NewDeleteAccessBindingUseCase(r.repo, ops).WithBindingWithdrawal(staged).WithRelationStore(relations, slog.Default())
	input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(recipient)}}, Target: domain.AccessTarget{AllInScope: true}}
	ctx := declarerCtx(r.ctx, owner)
	_, err = create.Execute(ctx, input)
	require.Error(t, err, "prepared не включает decision mode")
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	op, err := create.Execute(ctx, input)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	var id string
	var version int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT id,grant_capability_version FROM kaname.access_bindings WHERE role_id=$1 AND subject_id=$2`, string(template.RoleID), recipient).Scan(&id, &version))
	require.Equal(t, 1, version)
	// Не-владелец не получает права от собственного proposed binding.
	outsider := string(template.Subjects[0].ID)
	_, err = create.Execute(declarerCtx(r.ctx, outsider), input)
	require.Error(t, err)
	// Старый v0 carrier обновляет только metadata, без неявной выдачи meta.
	op, err = update.Execute(ctx, seed, []string{"labels"}, false, domain.Labels{"purpose": "metadata"})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT grant_capability_version FROM kaname.access_bindings WHERE id=$1`, string(seed)).Scan(&version))
	require.Zero(t, version)
	op, err = revoke.Execute(ctx, domain.AccessBindingID(id))
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.Equal(t, domain.AccessBindingStatusRevoked, bindingRow(t, r, domain.AccessBindingID(id)).Status)
	op, err = remove.Execute(ctx, domain.AccessBindingID(id))
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	var exists bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1)`, id).Scan(&exists))
	require.False(t, exists)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingWithdrawalLastPageRollbackAndHeldFold(t *testing.T) {
	r := writerProtocolRig(t)
	groups := stageSeedGroups(t, r, r.a, 259, "blue")
	id := stageBinding(t, r, r.a, false)
	engine := bindingStageEngine(t, r, nil)
	require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	require.Equal(t, 259, stageCount(t, r, id))
	b := bindingRow(t, r, id)
	p := withdrawalParticipant(t, r, nil)
	var ledgerBefore, auditBefore int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1),(SELECT count(*) FROM kaname.audit_outbox)`, string(id)).Scan(&ledgerBefore, &auditBefore))
	require.Greater(t, ledgerBefore, 256)
	ctx := declarerCtx(r.ctx, bindingPublicOwner(t, r))
	// Atomicity probe: production authority callback проверен отдельным API/LRO
	// сценарием выше; здесь убеждаемся, что runner передал native SAME-TX порт.
	before := func(_ context.Context, w kaname.Writer, native clients.RelationStore, _ domain.AccessBinding) error {
		require.NotNil(t, w)
		require.NotNil(t, native)
		return nil
	}
	failure := errors.New("audit callback failed")
	_, err := p.WithdrawBinding(ctx, id, kaname.BindingWithdrawalRevoke, "system:test", before, func(context.Context, kaname.Writer, domain.AccessBinding) error { return failure })
	require.ErrorIs(t, err, failure)
	require.Equal(t, domain.AccessBindingStatusActive, bindingRow(t, r, id).Status)
	var ledgerAfter, auditAfter int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1),(SELECT count(*) FROM kaname.audit_outbox)`, string(id)).Scan(&ledgerAfter, &auditAfter))
	require.Equal(t, ledgerBefore, ledgerAfter)
	require.Equal(t, auditBefore, auditAfter)
	// Второй действующий producer держит тот же folded viewer после первого revoke.
	held := groupLifecycleBinding(t, r, r.a, string(b.Subjects[0].ID), "binding_withdraw_held", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get", "list"}})
	require.NoError(t, engine.ReconcileBinding(r.ctx, held))
	noAudit := func(context.Context, kaname.Writer, domain.AccessBinding) error { return nil }
	_, err = p.WithdrawBinding(ctx, id, kaname.BindingWithdrawalRevoke, "system:test", before, noAudit)
	require.NoError(t, err)
	for _, gid := range []string{groups[0], groups[len(groups)-1]} {
		var present bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND relation='viewer' AND subject=$2)`, gid, "user:"+string(b.Subjects[0].ID)).Scan(&present))
		require.True(t, present)
	}
	_, err = p.WithdrawBinding(ctx, held, kaname.BindingWithdrawalRevoke, "system:test", before, noAudit)
	require.NoError(t, err)
	for _, gid := range []string{groups[0], groups[len(groups)-1]} {
		var present bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND relation='viewer' AND subject=$2)`, gid, "user:"+string(b.Subjects[0].ID)).Scan(&present))
		require.False(t, present)
	}
	authorityWaitReleased(t, r.runtime)
}

func TestBindingWithdrawalExpiryAfterActualFoldWaitAndLiveTwin(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			r := writerProtocolRig(t)
			groups := stageSeedGroups(t, r, r.a, 1, "blue")
			id := stageBinding(t, r, r.a, false)
			require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(r.ctx, id))
			b := bindingRow(t, r, id)
			interval := "1 hour"
			if expired {
				interval = "3 seconds"
			}
			var until time.Time
			require.NoError(t, r.runtime.QueryRow(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(id), interval).Scan(&until))
			blocker, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			tag, err := blocker.Exec(r.ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='viewer' FOR UPDATE`, groups[0], "user:"+string(b.Subjects[0].ID))
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			trace := stageBarrier(t, "SELECT 1 FROM kaname.relation_fact WHERE object_type=$1")
			p := withdrawalParticipant(t, r, trace)
			t.Cleanup(trace.releaseStage)
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- p.ExpireStagedBinding(ctx, id) }()
			stageWait(t, r, trace.reached)
			trace.releaseStage()
			require.Eventually(t, func() bool {
				var waiting bool
				e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, trace.pid.Load()).Scan(&waiting)
				return e == nil && waiting
			}, 5*time.Second, 10*time.Millisecond)
			if expired {
				require.Eventually(t, func() bool {
					var past bool
					e := r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()>$1`, until).Scan(&past)
					return e == nil && past
				}, 5*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, blocker.Rollback(r.ctx))
			select {
			case err = <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			got := bindingRow(t, r, id)
			if expired {
				require.Equal(t, domain.AccessBindingStatusRevoked, got.Status)
				require.Zero(t, stageCount(t, r, id))
			} else {
				require.Equal(t, domain.AccessBindingStatusActive, got.Status)
				require.Equal(t, 1, stageCount(t, r, id))
			}
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// kaname#1034: старый синхронный precheck прошёл, но источник owner сменился
// до guarded worker. Настоящая дверь v_delete остаётся, admin/owner — уже нет.
func TestBindingPublicRevokeRechecksOwnerBeforeCAS(t *testing.T) {
	r := writerProtocolRig(t)
	owner := bindingPublicOwner(t, r)
	replacement := seedMemberUser(t, r.ctx, r.admin, r.a, "binding-new-owner-"+ids.NewID("usr"))
	id := stageBinding(t, r, r.a, false)
	groupLifecycleBinding(t, r, r.a, owner, "binding_removal_method", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "delete"}})
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	native := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	trace := stageBarrier(t, "SELECT kaname.authority_policy_epoch_lock_for_write")
	participant := withdrawalParticipant(t, r, trace)
	t.Cleanup(trace.releaseStage)
	ops := operations.NewRepo(r.runtime, "kaname")
	revoke := bindingapp.NewRevokeAccessBindingUseCase(r.repo, ops).WithRelationStore(native, slog.Default()).WithBindingWithdrawal(participant)
	op, err := revoke.Execute(declarerCtx(r.ctx, owner), id)
	require.NoError(t, err)
	stageWait(t, r, trace.reached)
	tag, err := r.admin.Exec(r.ctx, `UPDATE kaname.accounts SET owner_user_id=$2 WHERE id=$1 AND owner_user_id=$3`, r.a, replacement, owner)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	trace.releaseStage()
	require.NotNil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.Equal(t, domain.AccessBindingStatusActive, bindingRow(t, r, id).Status)
	// Positive twin: текущий owner с настоящим method carrier проходит тот же LRO.
	groupLifecycleBinding(t, r, r.a, replacement, "binding_removal_new_owner", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "delete"}})
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, replacement)
	require.NoError(t, err)
	op, err = revoke.Execute(declarerCtx(r.ctx, replacement), id)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.Equal(t, domain.AccessBindingStatusRevoked, bindingRow(t, r, id).Status)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingMutationBackstopRequiresBothOldNewAccounts(t *testing.T) {
	r := writerProtocolRig(t)
	id := stageBinding(t, r, r.a, false)
	// Пользовательская роль A не назначается на B даже при верном fence.
	// Настоящий системный ярус допустим на обеих областях; constraint не снимаем.
	role := seedSystemRulesRole(t, r.ctx, kanamepg.New(r.admin, nil), "binding.backstop", domain.Rules{{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get", "list"}}})
	tag, err := r.runtime.Exec(r.ctx, `UPDATE kaname.access_bindings SET role_id=$2 WHERE id=$1`, string(id), string(role))
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	// Настоящий canonical emitter, а не только parser unit: lineage совпадает
	// с существующим carrier. Ложный parent на B не становится account-local.
	local := r.intent(r.a)
	local.Kind = kaname.AuthorityBinding
	w, err := r.repo.ParticipantAuthorityWriter(r.ctx, local)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(r.ctx, []ab.RelationTuple{{User: "account:" + r.a, Relation: "account", Object: "iam_access_binding:" + string(id)}}))
	require.NoError(t, w.Commit(r.ctx))
	var parent string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type='iam_access_binding' AND object_id=$1 AND relation='account'`, string(id)).Scan(&parent))
	require.Equal(t, "account:"+r.a, parent)
	forged, err := r.repo.ParticipantAuthorityWriter(r.ctx, local)
	require.NoError(t, err)
	defer func() { _ = forged.Rollback(context.WithoutCancel(r.ctx)) }()
	require.Error(t, forged.AccessBindingsW().EmitRelationWrite(r.ctx, []ab.RelationTuple{{User: "account:" + r.b, Relation: "account", Object: "iam_access_binding:" + string(id)}}))
	require.NoError(t, forged.Rollback(r.ctx))
	for _, accounts := range [][]string{{r.a}, {r.b}, {r.a, r.b}} {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		in := r.intent(accounts...)
		in.Kind = kaname.AuthorityBinding
		r.enter(t, tx, in, "participant")
		tag, err := tx.Exec(r.ctx, `UPDATE kaname.access_bindings SET resource_id=$2 WHERE id=$1 AND resource_id=$3`, string(id), r.b, r.a)
		if len(accounts) == 1 {
			require.Error(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
		} else {
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			require.NoError(t, tx.Commit(r.ctx))
		}
	}
	require.Equal(t, r.b, bindingRow(t, r, id).ResourceID)
	authorityWaitReleased(t, r.runtime)
}

// Обычные anchor carriers разных аккаунтов не превращаются в GLOBAL:
// A уже ждёт реальную folded row, а B заканчивает expiry независимо от него.
func TestBindingWithdrawalIndependentAccountsWhileFoldLocked(t *testing.T) {
	r := writerProtocolRig(t)
	groups := stageSeedGroups(t, r, r.a, 1, "blue")
	stageSeedGroups(t, r, r.b, 1, "other")
	a, b := stageBinding(t, r, r.a, false), stageBinding(t, r, r.b, false)
	engine := bindingStageEngine(t, r, nil)
	require.NoError(t, engine.ReconcileBinding(r.ctx, a))
	require.NoError(t, engine.ReconcileBinding(r.ctx, b))
	expireBindingFixture(t, r, a, b)
	subject := bindingRow(t, r, a).SubjectID
	blocker, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, blocker)
	tag, err := blocker.Exec(r.ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND relation='viewer' AND subject=$2 FOR UPDATE`, groups[0], "user:"+string(subject))
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	trace := stageBarrier(t, "SELECT 1 FROM kaname.relation_fact WHERE object_type=$1")
	p := withdrawalParticipant(t, r, trace)
	t.Cleanup(trace.releaseStage)
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.ExpireStagedBinding(ctx, a) }()
	stageWait(t, r, trace.reached)
	trace.releaseStage()
	require.Eventually(t, func() bool {
		var waiting bool
		e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, trace.pid.Load()).Scan(&waiting)
		return e == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	independent, cancelIndependent := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancelIndependent()
	require.NoError(t, withdrawalParticipant(t, r, nil).ExpireStagedBinding(independent, b))
	require.Equal(t, domain.AccessBindingStatusRevoked, bindingRow(t, r, b).Status)
	require.Equal(t, domain.AccessBindingStatusActive, bindingRow(t, r, a).Status)
	require.NoError(t, blocker.Rollback(r.ctx))
	select {
	case err = <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, domain.AccessBindingStatusRevoked, bindingRow(t, r, a).Status)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingWithdrawalRestagesActualLastPageAndCancellationIsAtomic(t *testing.T) {
	t.Run("late-ledger", func(t *testing.T) {
		r := writerProtocolRig(t)
		owner := bindingPublicOwner(t, r)
		groups := stageSeedGroups(t, r, r.a, 257, "blue")
		id := stageBinding(t, r, r.a, false)
		engine := bindingStageEngine(t, r, nil)
		require.NoError(t, engine.ReconcileBinding(r.ctx, id))
		require.Equal(t, 257, stageCount(t, r, id))
		groupLifecycleBinding(t, r, r.a, owner, "binding_late_method", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "delete"}})
		plans, err := authzmodel.New(r.bundle.ModelSource())
		require.NoError(t, err)
		native := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
		// RR уже закончен; callback tracer останавливает вход ДО любых fences.
		trace := stageBarrier(t, "SELECT kaname.authority_protocol_enter")
		ops := operations.NewRepo(r.runtime, "kaname")
		revoke := bindingapp.NewRevokeAccessBindingUseCase(r.repo, ops).WithRelationStore(native, slog.Default()).WithBindingWithdrawal(withdrawalParticipant(t, r, trace))
		t.Cleanup(trace.releaseStage)
		op, err := revoke.Execute(declarerCtx(r.ctx, owner), id)
		require.NoError(t, err)
		stageWait(t, r, trace.reached)
		late := stageSeedGroups(t, r, r.a, 1, "late")
		require.NoError(t, engine.ReconcileBinding(r.ctx, id))
		require.Equal(t, 258, stageCount(t, r, id))
		trace.releaseStage()
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
		subject := bindingRow(t, r, id).SubjectID
		for _, gid := range []string{groups[0], groups[len(groups)-1], late[0]} {
			var exists bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND relation='viewer' AND subject=$2)`, gid, "user:"+string(subject)).Scan(&exists))
			require.False(t, exists)
		}
		authorityWaitReleased(t, r.runtime)
	})
	t.Run("cancel", func(t *testing.T) {
		r := writerProtocolRig(t)
		groups := stageSeedGroups(t, r, r.a, 1, "blue")
		id := stageBinding(t, r, r.a, false)
		require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(r.ctx, id))
		expireBindingFixture(t, r, id)
		subject := bindingRow(t, r, id).SubjectID
		blocker, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, blocker)
		tag, err := blocker.Exec(r.ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND relation='viewer' AND subject=$2 FOR UPDATE`, groups[0], "user:"+string(subject))
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
		trace := stageBarrier(t, "SELECT 1 FROM kaname.relation_fact WHERE object_type=$1")
		p := withdrawalParticipant(t, r, trace)
		t.Cleanup(trace.releaseStage)
		ctx, cancel := context.WithCancel(r.ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.ExpireStagedBinding(ctx, id) }()
		stageWait(t, r, trace.reached)
		trace.releaseStage()
		require.Eventually(t, func() bool {
			var waiting bool
			e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, trace.pid.Load()).Scan(&waiting)
			return e == nil && waiting
		}, 5*time.Second, 10*time.Millisecond)
		cancel()
		select {
		case err = <-done:
			require.Error(t, err)
		case <-r.ctx.Done():
			t.Fatal(r.ctx.Err())
		}
		require.Equal(t, domain.AccessBindingStatusActive, bindingRow(t, r, id).Status)
		require.Equal(t, 1, stageCount(t, r, id))
		require.NoError(t, blocker.Rollback(r.ctx))
		require.NoError(t, p.ExpireStagedBinding(r.ctx, id))
		require.Equal(t, domain.AccessBindingStatusRevoked, bindingRow(t, r, id).Status)
		require.Zero(t, stageCount(t, r, id))
		authorityWaitReleased(t, r.runtime)
	})
}
