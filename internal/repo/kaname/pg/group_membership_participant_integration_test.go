// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

func membershipParticipant(t *testing.T, r protocolRig) *kanamepg.GroupMembershipParticipant {
	t.Helper()
	b, err := r.repo.LoadAuthorityBundle(r.ctx, r.bundle.ModelSource())
	require.NoError(t, err)
	p, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, b)
	require.NoError(t, err)
	return p
}
func membershipFixture(t *testing.T, r protocolRig) (domain.Group, string, string) {
	t.Helper()
	g := seedGroup(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.a), "participant-group")
	var uid string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&uid))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.memberships(id,user_id,account_id,state) VALUES(kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE') ON CONFLICT(user_id,account_id) DO UPDATE SET state='ACTIVE'`, uid, r.a)
	require.NoError(t, err)
	sa := seedSAID(t, r.ctx, r.admin, r.a, "participant")
	return g, uid, sa
}
func membershipCounts(t *testing.T, r protocolRig, gid, subject string, want int) {
	t.Helper()
	var rows, facts int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.group_members WHERE group_id=$1 AND member_type=split_part($2,':',1) AND member_id=split_part($2,':',2)),(SELECT count(*) FROM kaname.relation_fact WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject=$2)`, gid, subject).Scan(&rows, &facts))
	require.Equal(t, want, rows)
	require.Equal(t, want, facts)
}
func TestGroupMembershipParticipantActualWorkersPreparedAndStrict(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, sa := membershipFixture(t, r)
	require.Error(t, lifecycleOwner(r).ValidateAuthorityRuntime(r.ctx))
	bad, err := kanamepg.NewGroupMembershipParticipant(r.ctx, lifecycleOwner(r), r.bundle)
	require.Error(t, err)
	require.Nil(t, bad)
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	// Другая модель должна пройти настоящий допуск композиции. Пустая строка
	// после канона не добавляет ни одного нового типа и допуском отвергается.
	extra, err := manifest.Load([]byte(`apiVersion: iam/v1
module: vpc
resources:
  - name: widget
    objectType: vpc_group_member_probe
    parents: [project]
    producer: derived
    verbs: [get, list, update, delete]
`))
	require.NoError(t, err)
	otherModel, report, err := modelcompose.Compose(r.bundle.ModelSource(), []*manifest.Manifest{extra})
	require.NoError(t, err)
	changed, err := granteffect.NewBundle(r.ctx, otherModel, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	require.NotEqual(t, r.bundle.Identity().ModelID, changed.Identity().ModelID)
	require.Equal(t, r.bundle.Identity().CatalogID, changed.Identity().CatalogID)
	foreign, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, changed)
	require.NoError(t, err)
	absent, err := foreign.GroupMembershipWriter(r.ctx, domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)})
	require.Error(t, err)
	require.Nil(t, absent)
	p := membershipParticipant(t, r)
	ops := operations.NewRepo(r.runtime, "kaname")
	add := groupapp.NewAddMemberUseCase(r.repo, ops).WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(r.repo, nil)).WithMembershipWriter(p)
	remove := groupapp.NewRemoveMemberUseCase(r.repo, ops).WithMembershipWriter(p)
	for _, phase := range []string{"prepared", "active"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "active" {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			for _, member := range []struct {
				typ domain.SubjectType
				id  string
			}{{domain.SubjectTypeUser, uid}, {domain.SubjectTypeServiceAccount, sa}} {
				ctx := declarerCtx(r.ctx, uid)
				op, err := add.Execute(ctx, groupapp.AddMemberInput{GroupID: g.ID, MemberType: member.typ, MemberID: domain.SubjectID(member.id)})
				require.NoError(t, err)
				require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
				membershipCounts(t, r, string(g.ID), string(member.typ)+":"+member.id, 1)
				var payload string
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT payload->>'relation' FROM kaname.fga_outbox WHERE payload->>'object'=$1 AND payload->>'user'=$2 AND event_type='fga.tuple.write' ORDER BY id DESC LIMIT 1`, "group:"+string(g.ID), string(member.typ)+":"+member.id).Scan(&payload))
				require.Equal(t, "member", payload)
				op, err = remove.Execute(ctx, groupapp.RemoveMemberInput{GroupID: g.ID, MemberType: member.typ, MemberID: domain.SubjectID(member.id)})
				require.NoError(t, err)
				require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
				membershipCounts(t, r, string(g.ID), string(member.typ)+":"+member.id, 0)
			}
		})
	}
	// Настоящий body и emitter откатываются вместе; returned writer не decision API.
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	w, err := p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	aw := w.(kaname.AuthorityWriter)
	lifecycleWriterCleanup(t, aw)
	_, semantic := w.(kaname.SemanticAuthorityWriter)
	require.False(t, semantic)
	require.NoError(t, w.GroupsW().AddMember(r.ctx, m))
	require.NoError(t, w.EmitFGARelationWrite(r.ctx, []service.RelationTuple{groupMemberFGATuple("user", uid, string(g.ID))}))
	require.NoError(t, w.Rollback(r.ctx))
	membershipCounts(t, r, string(g.ID), "user:"+uid, 0)
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	op, err := add.Execute(declarerCtx(r.ctx, uid), groupapp.AddMemberInput{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)})
	require.NoError(t, err)
	require.NotNil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	membershipCounts(t, r, string(g.ID), "user:"+uid, 0)
	authorityWaitReleased(t, r.runtime)
}

// Реальный deferred carrier+subjects посев в одной TX; никакого fixture-only
// обхода CHECK. Вторая группа в set проверяет не только ведущую пару carrier.
func membershipBinding(t *testing.T, r protocolRig, gid, account, status string, secondary bool) string {
	t.Helper()
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	role, id := ids.NewID("rol"), ids.NewID("acb")
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) VALUES($1,$2,$3,'[]','[{"module":"iam","resources":["account"],"verbs":["get"]}]')`, role, account, "member_"+strings.ReplaceAll(role, "-", "_"))
	require.NoError(t, err)
	typ, subject := "group", gid
	if secondary {
		typ = "user"
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, account).Scan(&subject))
	}
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) VALUES($1,$2,$3,$4,'account',$5,$6)`, id, typ, subject, role, account, status)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES($1,$2,$3)`, id, typ, subject)
	require.NoError(t, err)
	if secondary {
		_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES($1,'group',$2)`, id, gid)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(r.ctx))
	return id
}
func TestGroupMembershipParticipantFullScopesAndBackstop(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	pending := membershipBinding(t, r, string(g.ID), r.b, "PENDING", true)
	project := kac127SeedProject(t, r.ctx, r.admin, r.b, "participant")
	_, updateErr := r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET resource_type='project',resource_id=$2 WHERE id=$1`, pending, project)
	require.NoError(t, updateErr)
	membershipBinding(t, r, string(g.ID), r.a, "ACTIVE", false)
	p := membershipParticipant(t, r)
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	w, err := p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	aw := w.(kaname.AuthorityWriter)
	lifecycleWriterCleanup(t, aw)
	require.Equal(t, kaname.AuthorityFenceAccounts, aw.AuthorityFence().Mode())
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, aw.AuthorityFence().Accounts())
	require.NoError(t, w.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	// Неполный собственноручный intent отвергается не только на member row,
	// но и на реальном emitter -> fold, который раньше обходил scope группы.
	for _, kind := range []string{"membership", "emitter"} {
		t.Run(kind, func(t *testing.T) {
			wr, e := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
			require.NoError(t, e)
			lifecycleWriterCleanup(t, wr)
			if kind == "membership" {
				e = wr.GroupsW().AddMember(r.ctx, m)
			} else {
				e = wr.EmitFGARelationWrite(r.ctx, []service.RelationTuple{groupMemberFGATuple("user", uid, string(g.ID))})
			}
			require.Error(t, e)
			require.NoError(t, wr.Rollback(r.ctx))
			membershipCounts(t, r, string(g.ID), "user:"+uid, 0)
		})
	}
	// Полный participant проходит настоящий emitter, оставляет канонический факт.
	w, err = p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, w.(kaname.AuthorityWriter))
	require.NoError(t, w.GroupsW().AddMember(r.ctx, m))
	require.NoError(t, w.EmitFGARelationWrite(r.ctx, []service.RelationTuple{groupMemberFGATuple("user", uid, string(g.ID))}))
	require.NoError(t, w.Commit(r.ctx))
	membershipCounts(t, r, string(g.ID), "user:"+uid, 1)
	for name, payload := range map[string]string{
		"relations_override": fmt.Sprintf(`{"user":"user:%s","relation":"member","relations":["admin"],"object":"group:%s"}`, uid, g.ID),
		"userset":            fmt.Sprintf(`{"user":"user:%s#member","relation":"member","object":"group:%s"}`, uid, g.ID),
		"unknown_field":      fmt.Sprintf(`{"user":"user:%s","relation":"member","object":"group:%s","condition":"unknown"}`, uid, g.ID),
	} {
		t.Run(name, func(t *testing.T) {
			tx, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, tx)
			r.enter(t, tx, r.intent(r.a, r.b), "participant")
			_, e = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write',$1::jsonb)`, payload)
			require.Error(t, e)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
	// OLD scope обязателен при DELETE канонического outbox, NEW — при переносе.
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a), "participant")
	_, err = tx.Exec(r.ctx, `DELETE FROM kaname.fga_outbox WHERE payload->>'object'=$1`, "group:"+string(g.ID))
	require.Error(t, err)
	require.NoError(t, tx.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
func TestGroupMembershipParticipantReclassifiesAfterWaitAndCancels(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	p := membershipParticipant(t, r)
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	hold, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, hold)
	r.enter(t, hold, r.intent(r.a), "participant")
	var blocker int
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	var got kaname.AuthorityFence
	done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		opened, e := p.GroupMembershipWriter(ctx, m)
		if e != nil {
			return e
		}
		got = opened.(kaname.AuthorityWriter).AuthorityFence()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return opened.Rollback(cleanup)
	})
	receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
	// Настоящий unfenced compatibility producer меняет read-set во время
	// ожидания. Adapter обязан освободить первую TX и повторить полный entry.
	membershipBinding(t, r, string(g.ID), r.b, "PENDING", false)
	var released time.Time
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&released))
	require.NoError(t, hold.Commit(r.ctx))
	require.NoError(t, lifecycleResult(t, r.ctx, done))
	require.NotNil(t, got)
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, got.Accounts())
	require.False(t, got.DecisionAt().Before(released))
	hold, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, hold)
	r.enter(t, hold, r.intent(r.a), "participant")
	require.NoError(t, hold.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	cancelCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	done = lifecycleAsync(t, cancelCtx, func(ctx context.Context) error {
		opened, e := p.GroupMembershipWriter(ctx, m)
		if opened != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = opened.Rollback(cleanup)
		}
		return e
	})
	receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
	cancel()
	require.Error(t, lifecycleResult(t, r.ctx, done))
	require.NoError(t, hold.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}

func TestGroupMembershipBackstopOldNewAndTypedRecipient(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	other := seedGroup(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.b), "other-group")
	foreignSA := seedSAID(t, r.ctx, r.admin, r.b, "foreignparticipant")
	p := membershipParticipant(t, r)
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(foreignSA)}
	wr, err := p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wr.(kaname.AuthorityWriter))
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, wr.(kaname.AuthorityWriter).AuthorityFence().Accounts())
	require.Error(t, wr.GroupsW().RequireMemberOfGroupAccount(r.ctx, m), "полный scope не разрешает чужого участника")
	require.NoError(t, wr.Rollback(r.ctx))
	// Typed collision: существующий user ID не становится service_account.
	m.MemberID = domain.SubjectID(uid)
	wr, err = p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wr.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceGlobal, wr.(kaname.AuthorityWriter).AuthorityFence().Mode())
	require.Error(t, wr.GroupsW().AddMember(r.ctx, m))
	require.NoError(t, wr.Rollback(r.ctx))
	// Две настоящие строки членства; затем каждый старый/новый anchor проверяется
	// отдельно, при неполном account intent без расширения locks в trigger.
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'user',$3),($2,'user',$3)`, g.ID, other.ID, uid)
	require.NoError(t, err)
	emitted, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer emitted.Rollback(context.Background())
	require.NoError(t, emitted.EmitFGARelationWrite(r.ctx, []service.RelationTuple{groupMemberFGATuple("user", uid, string(g.ID)), groupMemberFGATuple("user", uid, string(other.ID))}))
	require.NoError(t, emitted.Commit(r.ctx))

	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	for _, oldFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("old_%t", oldFirst), func(t *testing.T) {
			tx, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, tx)
			r.enter(t, tx, r.intent(r.a), "participant")
			from, to := g.ID, other.ID
			if oldFirst {
				from, to = other.ID, g.ID
			}
			_, e = tx.Exec(r.ctx, `UPDATE kaname.group_members SET group_id=$2 WHERE group_id=$1 AND member_type='user' AND member_id=$3`, from, to, uid)
			require.Error(t, e)
			var state string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity`).Scan(&state))
			require.Equal(t, "active", state)
			// 42501 доказывает scope guard раньше возможного duplicate PK.
			require.Contains(t, e.Error(), "42501")
			require.NoError(t, tx.Rollback(r.ctx))
			tx, e = r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, tx)
			r.enter(t, tx, r.intent(r.a), "participant")
			_, e = tx.Exec(r.ctx, `UPDATE kaname.relation_fact SET object_id=$2 WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject=$3`, from, to, "user:"+uid)
			require.Error(t, e)
			require.Contains(t, e.Error(), "42501")
			require.NoError(t, tx.Rollback(r.ctx))

		})
	}
	authorityWaitReleased(t, r.runtime)
}
func TestGroupMembershipPhysicalBudgetAndAccountIndependence(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	p := membershipParticipant(t, r)
	other := seedGroup(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.b), "budget-other")
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	wr, err := p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wr.(kaname.AuthorityWriter))
	independent := m
	independent.GroupID = other.ID
	nextCtx, cancel := context.WithTimeout(r.ctx, time.Second)
	defer cancel()
	second, err := p.GroupMembershipWriter(nextCtx, independent)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, second.(kaname.AuthorityWriter))
	require.NoError(t, second.Rollback(r.ctx))
	require.NoError(t, wr.Rollback(r.ctx))
	roles, bindings := make([]string, 257), make([]string, 257)
	for i := range roles {
		roles[i] = ids.NewID("rol")
		bindings[i] = ids.NewID("acb")
	}
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) SELECT x,$2,replace(x,'-','_'),'[]','[{"module":"iam","resources":["account"],"verbs":["get"]}]'::jsonb FROM unnest($1::text[]) x`, roles, r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) SELECT x,'group',$3,y,'account',$4,'PENDING' FROM unnest($1::text[],$2::text[]) u(x,y)`, bindings, roles, g.ID, r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) SELECT x,'group',$2 FROM unnest($1::text[]) x`, bindings, g.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
	m.MemberType = domain.SubjectTypeUser
	m.MemberID = domain.SubjectID(uid)
	wr, err = p.GroupMembershipWriter(r.ctx, m)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, wr.(kaname.AuthorityWriter))
	require.Equal(t, kaname.AuthorityFenceGlobal, wr.(kaname.AuthorityWriter).AuthorityFence().Mode(), "257 физических носителей не маскируются одним dedup account")
	require.NoError(t, wr.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
