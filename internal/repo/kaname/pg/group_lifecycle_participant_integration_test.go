// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Реальные RolesW/selector projection/bindingset, с фактом того же bundle.
func groupLifecycleBinding(t *testing.T, r protocolRig, account, uid, name string, rule domain.Rule) domain.AccessBindingID {
	t.Helper()
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	w, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
	rules := domain.Rules{rule}
	permissions, err := domain.CompileRules(rules)
	require.NoError(t, err)
	role, err := w.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(account), Name: domain.RoleName(name), Rules: rules, Permissions: permissions})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, facts.GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
	// kaname#1034: native binding arm требует обе реальные ordinary проекции,
	// как Role.Create; один ledger/selector не заменяет role_verb.
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, facts.RoleVerbsFromSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
	b, err := bindingset.Insert(r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid), RoleID: role.ID, ResourceType: "account", ResourceID: account, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive})
	require.NoError(t, err)
	require.NoError(t, w.Commit(r.ctx))
	return b.ID
}

type observedGroupObject struct {
	*reconcile.Reconciler
	done chan error
}

func (o *observedGroupObject) ReconcileObjectForward(ctx context.Context, typ, id string) error {
	err := o.Reconciler.ReconcileObjectForward(ctx, typ, id)
	o.done <- err
	return err
}
func groupLifecycleEngine(t *testing.T, r protocolRig, p *kanamepg.GroupMembershipParticipant) (*reconcile.Reconciler, *kanamepg.ReconcileAdapter) {
	t.Helper()
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	a := kanamepg.NewReconcileAdapter(r.runtime, catalog.Fixed{F: facts})
	engine := reconcile.New(a, slog.Default(), catalog.Fixed{F: facts})
	scoped, err := p.NewGroupObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, engine.WithGroupObjectReconciler(scoped))
	return engine, a
}
func groupLifecycleFacts(t *testing.T, r protocolRig, gid, uid string, want bool) {
	t.Helper()
	var exists bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='v_get')`, gid, "user:"+uid).Scan(&exists))
	require.Equal(t, want, exists)
}

// kaname#1034: ordinary v_* выводится native checker, а не хранится копией
// в relation_fact. Bundle остаётся тем же в prepared и strict; это читающая
// проверка результата, а не допуск semantic decision в prepared.
func groupLifecycleAccess(t *testing.T, r protocolRig, gid, uid string, want bool) {
	t.Helper()
	groupLifecycleFacts(t, r, gid, uid, false)
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	var decisionAt time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&decisionAt))
	asker := relverdict.NewSemanticTransactionAsker(tx, r.bundle, decisionAt)
	allowed, err := asker.Allowed(r.ctx, "user:"+uid, "iam_group", gid, "v_get", nil)
	require.NoError(t, err)
	require.Equal(t, want, allowed)
	if want {
		_, direct, _ := asker.LabelArmGrounds()
		require.Equal(t, int64(1), direct, "допуск должен прийти из реального IAM label selector")
	}
	require.NoError(t, tx.Rollback(r.ctx))
}
func TestGroupLifecycleParticipantActualCRUDAndObjectEndpoints(t *testing.T) {
	r := writerProtocolRig(t)
	_, uid, _ := membershipFixture(t, r)
	owner := lifecycleOwner(r)
	// Получатели не владеют аккаунтом и не имеют других источников admin.
	blueUID := seedMemberUser(t, r.ctx, r.admin, r.a, "lifecycle-blue")
	redUID := seedMemberUser(t, r.ctx, r.admin, r.a, "lifecycle-red")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{blueUID, redUID})
	require.NoError(t, err)
	for _, recipient := range []string{blueUID, redUID} {
		var owns, facts, bindings, groups int
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
   (SELECT count(*) FROM kaname.accounts WHERE owner_user_id=$1),
   (SELECT count(*) FROM kaname.relation_fact WHERE subject='user:'||$1),
   (SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='user' AND subject_id=$1),
   (SELECT count(*) FROM kaname.group_members WHERE member_type='user' AND member_id=$1)`, recipient).Scan(&owns, &facts, &bindings, &groups))
		require.Zero(t, owns)
		require.Zero(t, facts)
		require.Zero(t, bindings)
		require.Zero(t, groups)
	}
	blue := groupLifecycleBinding(t, r, r.a, blueUID, "group_lifecycle_blue", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get", "list"}, MatchLabels: map[string]string{"tier": "blue"}})
	red := groupLifecycleBinding(t, r, r.a, redUID, "group_lifecycle_red", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get", "list"}, MatchLabels: map[string]string{"tier": "red"}})
	p := membershipParticipant(t, r)
	engine, queue := groupLifecycleEngine(t, r, p)
	observed := &observedGroupObject{engine, make(chan error, 1)}
	ops := operations.NewRepo(r.runtime, "kaname")
	create := groupapp.NewCreateGroupUseCase(r.repo, ops).WithLifecycleWriter(p).WithObjectReconciler(engine)
	update := groupapp.NewUpdateGroupUseCase(r.repo, ops).WithLifecycleWriter(p).WithObjectReconciler(observed, slog.Default())
	remove := groupapp.NewDeleteGroupUseCase(r.repo, ops).WithLifecycleWriter(p)
	for _, phase := range []string{"prepared", "strict"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "strict" {
				require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			ctx := declarerCtx(r.ctx, uid)
			op, err := create.Execute(ctx, domain.Group{AccountID: domain.AccountID(r.a), Name: domain.GroupName("lifecycle-" + phase), Labels: domain.Labels{"tier": "blue"}})
			require.NoError(t, err)
			require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
			var gid string
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT id FROM kaname.groups WHERE account_id=$1 AND name=$2`, r.a, "lifecycle-"+phase).Scan(&gid))
			groupLifecycleAccess(t, r, gid, blueUID, true)
			groupLifecycleAccess(t, r, gid, redUID, false)
			require.True(t, ledgerHasTuple(t, r.ctx, r.runtime, blue, "user:"+blueUID, "v_get", "iam_group:"+gid))
			require.False(t, ledgerHasTuple(t, r.ctx, r.runtime, red, "user:"+redUID, "v_get", "iam_group:"+gid))
			var folded bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE payload->>'object'=$1 AND jsonb_array_length(payload->'relations')>1)`, "iam_group:"+gid).Scan(&folded))
			require.True(t, folded, "настоящий emitter должен пройти multi-relations classifier")
			op, err = update.Execute(ctx, groupapp.UpdateGroupInput{ID: domain.GroupID(gid), Labels: domain.Labels{"tier": "red"}, UpdateMask: []string{"labels"}})
			require.NoError(t, err)
			require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
			select {
			case err = <-observed.done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("detached object reconcile did not finish")
			}
			require.False(t, ledgerHasTuple(t, r.ctx, r.runtime, blue, "user:"+blueUID, "v_get", "iam_group:"+gid))
			require.True(t, ledgerHasTuple(t, r.ctx, r.runtime, red, "user:"+redUID, "v_get", "iam_group:"+gid))
			groupLifecycleAccess(t, r, gid, blueUID, false)
			groupLifecycleAccess(t, r, gid, redUID, true)
			op, err = remove.Execute(ctx, domain.GroupID(gid))
			require.NoError(t, err)
			require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
			// Те же production queue endpoints, что вызывает worker.drain; периодический
			// full-binding sweep здесь не маскируется под подключённого participant.
			events, err := queue.ClaimReconcileEvents(r.ctx, 256)
			require.NoError(t, err)
			found := false
			for _, e := range events {
				if e.ObjectType != "iam.group" || e.ObjectID != gid {
					continue
				}
				found = found || e.EventType == shared.ReconcileEventDelete
				require.NoError(t, engine.ReconcileObject(r.ctx, e.ObjectType, e.ObjectID))
				require.NoError(t, queue.MarkReconcileEventSent(r.ctx, e.ID))
			}
			require.True(t, found)
			groupLifecycleAccess(t, r, gid, blueUID, false)
			groupLifecycleAccess(t, r, gid, redUID, false)
			require.False(t, ledgerHasTuple(t, r.ctx, r.runtime, red, "user:"+redUID, "v_get", "iam_group:"+gid))
		})
	}
	authorityWaitReleased(t, r.runtime)
}
func TestGroupLifecycleParticipantRollbackClosedAndIndependentAccounts(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	groupLifecycleBinding(t, r, r.a, uid, "group_independent_a", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
	groupLifecycleBinding(t, r, r.b, uid, "group_independent_b", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
	other := seedGroup(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.b), "lifecycle-other")
	p := membershipParticipant(t, r)
	wa, err := p.GroupLifecycleWriter(r.ctx, kaname.GroupUpdate, g)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wa.(kaname.AuthorityWriter))
	independent, stop := context.WithTimeout(r.ctx, 2*time.Second)
	defer stop()
	wb, err := p.GroupLifecycleWriter(independent, kaname.GroupUpdate, other)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wb.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceAccounts, wb.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.NoError(t, wb.Rollback(r.ctx))
	g.Name = "lifecycle-rollback"
	_, err = wa.GroupsW().Update(r.ctx, g, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, wa.Rollback(r.ctx))
	var name string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT name FROM kaname.groups WHERE id=$1`, g.ID).Scan(&name))
	require.Equal(t, "participant-group", name)
	absent, err := p.GroupLifecycleWriter(r.ctx, kaname.GroupMutation("unknown"), g)
	require.Error(t, err)
	require.Nil(t, absent)
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	absent, err = p.GroupLifecycleWriter(r.ctx, kaname.GroupUpdate, g)
	require.Error(t, err)
	require.Nil(t, absent)
	engine, err := p.NewGroupObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.Error(t, engine.ReconcileObject(r.ctx, "iam.group", string(g.ID)))
	require.Error(t, engine.ReconcileBinding(r.ctx, domain.AccessBindingID("acb-no-whole-scan")))
	authorityWaitReleased(t, r.runtime)
}
func TestGroupObjectParticipantWaitReclassifiesAndCancellationReleases(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	p := membershipParticipant(t, r)
	hold, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, hold)
	r.enter(t, hold, r.intent(r.a), "participant")
	var blocker int
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	var fence kaname.AuthorityFence
	done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		w, e := p.GroupLifecycleWriter(ctx, kaname.GroupUpdate, g)
		if e != nil {
			return e
		}
		fence = w.(kaname.AuthorityWriter).AuthorityFence()
		return w.Rollback(context.WithoutCancel(ctx))
	})
	receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
	// Настоящий совместимый producer добавляет потенциальный NEW names carrier,
	// пока entry ждёт. Первый fence недостаточен: нужен полный rollback/restart.
	bid := groupLifecycleBinding(t, r, r.b, uid, "group_lifecycle_foreign", domain.Rule{Module: "iam", Resources: []string{"group"}, ResourceNames: []string{string(g.ID)}, Verbs: []string{"get"}})
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET status='PENDING' WHERE id=$1`, bid)
	require.NoError(t, err)
	var released time.Time
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&released))
	require.NoError(t, hold.Commit(r.ctx))
	require.NoError(t, lifecycleResult(t, r.ctx, done))
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, fence.Accounts())
	require.False(t, fence.DecisionAt().Before(released))
	hold, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, hold)
	r.enter(t, hold, r.intent(r.a, r.b), "participant")
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	engine, _ := groupLifecycleEngine(t, r, p)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	done = lifecycleAsync(t, ctx, func(ctx context.Context) error { return engine.ReconcileObject(ctx, "iam.group", string(g.ID)) })
	receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
	cancel()
	require.Error(t, lifecycleResult(t, r.ctx, done))
	require.NoError(t, hold.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
func TestGroupObjectParticipantExpiryAfterFenceWait(t *testing.T) {
	for _, forward := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "forward_batch"}[forward], func(t *testing.T) {
			r := writerProtocolRig(t)
			g, uid, _ := membershipFixture(t, r)
			bid := groupLifecycleBinding(t, r, r.a, uid, "group_lifecycle_expiry", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
			p := membershipParticipant(t, r)
			engine, _ := groupLifecycleEngine(t, r, p)
			hold, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, hold)
			r.enter(t, hold, r.intent(r.a), "participant")
			var blocker int
			require.NoError(t, hold.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
			done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
				if forward {
					return engine.ReconcileObjectForwardNoStale(ctx, "iam.group", string(g.ID))
				}
				return engine.ReconcileObject(ctx, "iam.group", string(g.ID))
			})
			receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
			_, err = hold.Exec(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, bid)
			require.NoError(t, err)
			require.NoError(t, hold.Commit(r.ctx))
			require.NoError(t, lifecycleResult(t, r.ctx, done))
			groupLifecycleFacts(t, r, string(g.ID), uid, false)
			require.False(t, ledgerHasTuple(t, r.ctx, r.runtime, bid, "user:"+uid, "v_get", "iam_group:"+string(g.ID)))
			authorityWaitReleased(t, r.runtime)
		})
	}
}
func TestGroupObjectBackstopCanonicalEmitterAndTypedOldNew(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	sa := seedSAID(t, r.ctx, r.admin, r.b, "lifecycleforeign")
	p := membershipParticipant(t, r)
	// Проверка источника получателя: user:<SA id> не является service_account.
	for _, subject := range []string{"user:" + sa, "service_account:" + uid, "group:" + string(g.ID), "group:" + string(g.ID) + "#admin", "user:*"} {
		var global bool
		var account *string
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT account_id,global_scope FROM kaname.authority_group_object_subject($1)`, subject).Scan(&account, &global))
		require.True(t, global)
	}
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	factCount := func(subject string) int {
		var count int
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='viewer'`, g.ID, subject).Scan(&count))
		return count
	}
	for _, subject := range []string{"user:" + uid, "service_account:" + sa, "group:" + string(g.ID) + "#member"} {
		accounts := []string{r.a}
		if subject == "service_account:"+sa {
			accounts = append(accounts, r.b)
		}
		w, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(accounts...))
		require.NoError(t, err)
		lifecycleWriterCleanup(t, w)
		tuples := []service.RelationTuple{{User: subject, Relation: "viewer", Object: "iam_group:" + string(g.ID)}, {User: subject, Relation: "v_get", Object: "iam_group:" + string(g.ID)}, {User: subject, Relation: "v_list", Object: "iam_group:" + string(g.ID)}}
		require.NoError(t, w.EmitFGARelationWrite(r.ctx, tuples))
		require.NoError(t, w.EmitFGARelationDelete(r.ctx, tuples))
		require.NoError(t, w.Commit(r.ctx))
		require.Zero(t, factCount(subject))
	}
	for _, payload := range []string{
		`{"user":"user:` + uid + `","object":"iam_group:` + string(g.ID) + `","relation":"v_get","relations":["v_get","v_get"]}`,
		`{"user":"user:` + uid + `","object":"iam_group:` + string(g.ID) + `","relation":"v_list","relations":["v_get","v_list"]}`,
		`{"user":"user:` + uid + `","object":"iam_group:` + string(g.ID) + `","relation":"v_get","source_version":"infinity"}`,
		`{"user":"user:` + uid + `","object":"iam_group:` + string(g.ID) + `","relation":"super_admin"}`,
	} {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		r.enter(t, tx, r.intent(r.a), "participant")
		_, err = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write',$1::jsonb)`, payload)
		require.Error(t, err)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	// NEW recipient account недостаточен без OLD; настоящий folded emitter,
	// а не ручная вставка relation_fact, создаёт исходный факт.
	w, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a, r.b))
	require.NoError(t, err)
	lifecycleWriterCleanup(t, w)
	require.NoError(t, w.EmitFGARelationWrite(r.ctx, []service.RelationTuple{{User: "service_account:" + sa, Relation: "viewer", Object: "iam_group:" + string(g.ID)}}))
	require.NoError(t, w.Commit(r.ctx))
	require.Equal(t, 1, factCount("service_account:"+sa), "предпосылка OLD: настоящий folded viewer существует")
	require.Zero(t, factCount("user:"+uid))
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a), "participant")
	_, err = tx.Exec(r.ctx, `UPDATE kaname.relation_fact SET subject=$3 WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='viewer'`, g.ID, "service_account:"+sa, "user:"+uid)
	require.ErrorContains(t, err, "authority OLD scope not covered")
	require.NoError(t, tx.Rollback(r.ctx))
	require.Equal(t, 1, factCount("service_account:"+sa))
	// Полный OLD+NEW набор действительно меняет одну строку и фиксирует её.
	tx, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a, r.b), "participant")
	tag, err := tx.Exec(r.ctx, `UPDATE kaname.relation_fact SET subject=$3 WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='viewer'`, g.ID, "service_account:"+sa, "user:"+uid)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
	require.NoError(t, tx.Commit(r.ctx))
	require.Equal(t, 1, factCount("user:"+uid))
	require.Zero(t, factCount("service_account:"+sa))
	// Обратный переход: теперь A покрывает OLD, но не NEW service_account из B.
	tx, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a), "participant")
	_, err = tx.Exec(r.ctx, `UPDATE kaname.relation_fact SET subject=$3 WHERE object_type='iam_group' AND object_id=$1 AND subject=$2 AND relation='viewer'`, g.ID, "user:"+uid, "service_account:"+sa)
	require.ErrorContains(t, err, "authority NEW scope not covered")
	require.NoError(t, tx.Rollback(r.ctx))
	require.Equal(t, 1, factCount("user:"+uid))
	tx, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a), "participant")
	_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET account_id=$2 WHERE id=$1`, g.ID, r.b)
	require.Error(t, err)
	require.NoError(t, tx.Rollback(r.ctx))
	// DELETE родителя по-прежнему требует global ДО каскадов.
	wd, err := p.GroupLifecycleWriter(r.ctx, kaname.GroupDelete, g)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wd.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceGlobal, wd.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.NoError(t, wd.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}

func TestGroupObjectParticipantRecipientScopesAndBudgetBoundary(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	other := seedGroup(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.b), "lifecycle-recipient")
	sa := seedSAID(t, r.ctx, r.admin, r.b, "lifecyclescopes")
	bid := groupLifecycleBinding(t, r, r.a, uid, "group_lifecycle_budget", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
	w, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
	require.NoError(t, w.AccessBindingsW().InsertSubjects(r.ctx, bid, []domain.Subject{{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(other.ID)}, {Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(sa)}}))
	require.NoError(t, w.Commit(r.ctx))
	p := membershipParticipant(t, r)
	selected, err := p.GroupLifecycleWriter(r.ctx, kaname.GroupUpdate, g)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, selected.(kaname.AuthorityWriter))
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, selected.(kaname.AuthorityWriter).AuthorityFence().Accounts())
	require.NoError(t, selected.Rollback(r.ctx))
	// 1 carrier + lead + три физических subject rows = 5, ещё 83*3 = 249;
	// 254 допускаются, следующий carrier+lead+subject пересекает 256.
	for i := 0; i < 83; i++ {
		groupLifecycleBinding(t, r, r.a, uid, fmt.Sprintf("group_budget_%d", i), domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
	}
	selected, err = p.GroupLifecycleWriter(r.ctx, kaname.GroupUpdate, g)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, selected.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceAccounts, selected.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.NoError(t, selected.Rollback(r.ctx))
	groupLifecycleBinding(t, r, r.a, uid, "group_budget_boundary", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
	selected, err = p.GroupLifecycleWriter(r.ctx, kaname.GroupUpdate, g)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, selected.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceGlobal, selected.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.NoError(t, selected.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
