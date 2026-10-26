// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_c_integration_test.go — группа C приёмки
// role-rights-stay-within-what-is-named.md: состав группы не шире права выдавать
// (Р3, Д-2, Д-3, Д-4; задача PRO-Robotech/kaname#1037). Мир — `newEscWorld`.

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// escAM — тело добавления AM (§4.1) с названным участником.
func escAM(group, memberType, memberID string) *iamv1.AddGroupMemberRequest {
	return &iamv1.AddGroupMemberRequest{GroupId: group, MemberType: memberType, MemberId: memberID}
}

// tryAddMember — `GroupService.AddMember` через обработчик `h`.
func (w *escWorld) tryAddMember(h *groupapp.Handler, ctx context.Context, req *iamv1.AddGroupMemberRequest) opOutcome {
	w.t.Helper()
	op, err := h.AddMember(ctx, req)
	if err != nil {
		return opOutcome{syncErr: err}
	}
	out := opOutcome{opID: op.GetId()}
	if done := awaitOp(w.t, w.ctx, w.ops, op.GetId()); done.Error != nil {
		out.opErr = status.New(codes.Code(done.Error.Code), done.Error.Message)
	}
	return out
}

// membersOf — участники группы по `ListMembers` от владельца, «вид:id», по порядку.
func (w *escWorld) membersOf(group string) []string {
	w.t.Helper()
	resp, err := w.groupsX.ListMembers(asUser(w.ctx, w.usrA), &iamv1.ListGroupMembersRequest{GroupId: group, PageSize: 100})
	require.NoErrorf(w.t, err, "ListMembers(%s) от usr-A", group)
	out := []string{}
	for _, m := range resp.GetMembers() {
		out = append(out, m.GetMemberType()+":"+m.GetMemberId())
	}
	sort.Strings(out)
	return out
}

// ESC-20 — участник в группу с выдачей — только с правом выдавать на её области.
func TestRoleRightsStayNamed_ESC20_AddMemberNeedsGrantAuthorityOnTheGroupScope(t *testing.T) {
	x := pcrRegType + ":" + pcrX
	for _, row := range []struct {
		name   string
		caller func(w *escWorld) domain.UserID
	}{
		{"b usr-GP (право выдавать на prj-A)", func(w *escWorld) domain.UserID { return w.usrGroupEdGrant }},
		{"c usr-E (администратор аккаунта)", func(w *escWorld) domain.UserID { return w.usrE }},
	} {
		w := newEscWorld(t)
		requireOpDoneOutcome(t, w.tryAddMember(w.groupsX, asUser(w.ctx, row.caller(w)),
			escAM(w.grpE1, "service_account", w.svaA2)), "ESC-20 "+row.name)
		assert.Equalf(t, []string{"service_account:" + w.svaA2}, w.membersOf(w.grpE1), "ESC-20 %s: участники grp-e1", row.name)
		w.pollRelation("service_account:"+w.svaA2, "v_get", x, true, "ESC-20 "+row.name+": участник получил выдачу группы")
	}

	w := newEscWorld(t)
	o := w.tryAddMember(w.groupsX, asUser(w.ctx, w.usrGroupEd), escAM(w.grpE1, "service_account", w.svaA2))
	assertSyncRefusalIs(t, o, authzguard.PermissionDenied(), "ESC-20 a usr-G")
	assert.Empty(t, w.membersOf(w.grpE1), "ESC-20 a: участников grp-e1 нет")
	assert.False(t, w.relation("service_account:"+w.svaA2, "v_get", x), "ESC-20 a: sva-A2 не получил v_get на X")
}

// ESC-21 — группа без выдач права выдавать не требует.
func TestRoleRightsStayNamed_ESC21_GroupWithoutBindingsNeedsNoGrantAuthority(t *testing.T) {
	w := newEscWorld(t)
	requireOpDoneOutcome(t, w.tryAddMember(w.groupsX, asUser(w.ctx, w.usrGroupEd),
		escAM(w.grpE0, "service_account", w.svaA2)), "ESC-21 usr-G в grp-e0")
	assert.Equal(t, []string{"service_account:" + w.svaA2}, w.membersOf(w.grpE0), "ESC-21: участники grp-e0")
}

// ESC-22 — право нужно на КАЖДОЙ области выдач группы.
func TestRoleRightsStayNamed_ESC22_GrantAuthorityOnEveryGroupScope(t *testing.T) {
	wb := newEscWorld(t)
	requireOpDoneOutcome(t, wb.tryAddMember(wb.groupsX, asUser(wb.ctx, wb.usrE),
		escAM(wb.grpE2, "service_account", wb.svaA2)), "ESC-22 b usr-E")
	assert.Equal(t, []string{"service_account:" + wb.svaA2}, wb.membersOf(wb.grpE2), "ESC-22 b: участники grp-e2")

	w := newEscWorld(t)
	o := w.tryAddMember(w.groupsX, asUser(w.ctx, w.usrGroupEdGrant), escAM(w.grpE2, "service_account", w.svaA2))
	assertSyncRefusalIs(t, o, authzguard.PermissionDenied(), "ESC-22 a usr-GP")
	assert.Empty(t, w.membersOf(w.grpE2), "ESC-22 a: участников grp-e2 нет")
}

// ESC-23 — участник — только из аккаунта группы (Д-3): чужой неотличим от несуществующего.
func TestRoleRightsStayNamed_ESC23_MemberOnlyFromTheGroupAccount(t *testing.T) {
	w := newEscWorld(t)
	absentSA := ids.NewID(domain.PrefixServiceAccount)
	type row struct {
		name, memberType, memberID string
		admitted                   bool
	}
	rows := []row{
		{"a sva-A2 (учётка acc-A)", "service_account", w.svaA2, true},
		{"c usr-M (членство ACTIVE)", "user", string(w.usrM), true},
		{"f учётки нет нигде", "service_account", absentSA, false},
		{"b sva-B (учётка acc-B)", "service_account", w.svaB, false},
		{"d usr-C (членства в acc-A нет)", "user", string(w.usrC), false},
		{"e usr-P (членство PENDING)", "user", string(w.usrP), false},
	}
	refusal := map[string]*status.Status{}
	for _, r := range rows {
		o := w.tryAddMember(w.groupsX, asUser(w.ctx, w.usrE), escAM(w.grpE0, r.memberType, r.memberID))
		if !assert.NoErrorf(t, o.syncErr, "ESC-23 %s: синхронный отказ", r.name) {
			continue
		}
		if r.admitted {
			assert.Nilf(t, o.opErr, "ESC-23 %s: операция завершилась ошибкой", r.name)
			continue
		}
		if !assert.NotNilf(t, o.opErr, "ESC-23 %s: участник принят", r.name) {
			continue
		}
		refusal[r.name] = o.opErr
		assert.Equalf(t, codes.FailedPrecondition, o.opErr.Code(), "ESC-23 %s: код (текст %q)", r.name, o.opErr.Message())
		assert.Equalf(t, escTextMemberMissing, o.opErr.Message(), "ESC-23 %s: текст T-нет", r.name)
	}
	assert.Equal(t, []string{"service_account:" + w.svaA2, "user:" + string(w.usrM)}, w.membersOf(w.grpE0),
		"ESC-23: в grp-e0 только участники a и c")

	// b против f и d против f: код, текст и детали — одни (В-4.1: идентификатора
	// участника в тексте нет, поэтому равенство — полное, без подстановки).
	shape := func(st *status.Status) string {
		if st == nil {
			return "<нет отказа>"
		}
		return fmt.Sprintf("%v %s деталей %d", st.Code(), st.Message(), len(st.Details()))
	}
	f := refusal["f учётки нет нигде"]
	assert.Equal(t, shape(f), shape(refusal["b sva-B (учётка acc-B)"]),
		"ESC-23: отказ по чужой учётке отличим от отказа по несуществующей")
	assert.Equal(t, shape(f), shape(refusal["d usr-C (членства в acc-A нет)"]),
		"ESC-23: отказ по человеку без членства отличим от отказа по несуществующему")
}

// escTextMemberMissing — T-нет: текст отказа «участника нет», измеренный на базе
// (§0.2, §11 приёмки; решение В-4.1).
const escTextMemberMissing = "referenced resource does not exist; create it or correct the reference before retrying"

// ESC-24 — убрать участника права выдавать не требует.
func TestRoleRightsStayNamed_ESC24_RemoveMemberNeedsNoGrantAuthority(t *testing.T) {
	w := newEscWorld(t)
	x := pcrRegType + ":" + pcrX
	requireOpDoneOutcome(t, w.tryAddMember(w.groupsX, asUser(w.ctx, w.usrE), escAM(w.grpE1, "service_account", w.svaA2)),
		"ESC-24 Дано: usr-E добавил sva-A2 в grp-e1")
	w.pollRelation("service_account:"+w.svaA2, "v_get", x, true, "ESC-24 Дано: sva-A2 читает X")

	op, err := w.groupsX.RemoveMember(asUser(w.ctx, w.usrGroupEd), &iamv1.RemoveGroupMemberRequest{
		GroupId: w.grpE1, MemberType: "service_account", MemberId: w.svaA2,
	})
	w.requireOpDone(op, err, "ESC-24: usr-G убирает sva-A2 из grp-e1")
	assert.Empty(t, w.membersOf(w.grpE1), "ESC-24: участников grp-e1 нет")
	assert.True(t, w.eventually("service_account:"+w.svaA2, "v_get", x, false), "ESC-24: sva-A2 больше не читает X")
}

// ESC-25 — хранилище отношений не отвечает — участник не добавляется (fail-closed).
func TestRoleRightsStayNamed_ESC25_RelationStoreOutageRefusesTheAdd(t *testing.T) {
	twin := newEscWorld(t)
	requireOpDoneOutcome(t, twin.tryAddMember(twin.groupsX, asUser(twin.ctx, twin.usrE),
		escAM(twin.grpE1, "service_account", twin.svaA2)), "ESC-25 близнец: хранилище отвечает")

	w := newEscWorld(t)
	fail := &ceFailFor{inner: w.door, subject: escUser(w.usrE)}
	h := groupapp.NewHandler(nil, nil, nil, nil, nil, w.escAddMemberOn(w.ops, fail), nil, nil)
	o := w.tryAddMember(h, asUser(w.ctx, w.usrE), escAM(w.grpE1, "service_account", w.svaA2))
	t.Logf("ESC-25: вопросов о субъекте usr-E к хранилищу — %d", fail.hits)
	assertSyncRefusalIs(t, o, authzguard.AuthzBackendUnavailable(), "ESC-25: неполадка на вопросе о праве выдавать")
	assert.Empty(t, w.membersOf(w.grpE1), "ESC-25: участников grp-e1 нет")
	assert.Positive(t, fail.hits, "ESC-25 контроль: вопрос о праве выдавать не задан — инъекция вакуумна")
}

// Гонка добавления участника и выдачи группе на новой области (DoD S1 п.5).
// Принудительное чередование: решение добавления (Р3) принято, пока выдачи
// группе на acc-A нет; затем выдача rol-g группе grp-e1 на acc-A доведена до
// `done`; затем добавление пишется. Исход — один из двух последовательных
// порядков: «добавление, затем выдача» (участник в группе, выдача действует)
// либо «выдача, затем добавление» (добавление отвергнуто, участника нет).
func TestRoleRightsStayNamed_AddMemberAndNewScopeGrantSerialize(t *testing.T) {
	w := newEscWorld(t)
	ops := &latchedOps{Repo: w.ops, entered: make(chan struct{}), release: make(chan struct{})}
	h := groupapp.NewHandler(nil, nil, nil, nil, nil, w.escAddMemberOn(ops, w.door), nil, nil)

	type res struct {
		op  string
		err error
	}
	done := make(chan res, 1)
	go func() {
		op, err := h.AddMember(asUser(w.ctx, w.usrGroupEdGrant), escAM(w.grpE1, "service_account", w.svaA2))
		r := res{err: err}
		if op != nil {
			r.op = op.GetId()
		}
		done <- r
	}()

	var r res
	select {
	case <-ops.entered:
		w.escGrant(groupSubject(w.grpE1), w.rolG, "iam.account", string(w.accA), "гонка: rol-g → grp-e1 на acc-A")
		close(ops.release)
		r = <-done
	case r = <-done:
		close(ops.release)
		w.escGrant(groupSubject(w.grpE1), w.rolG, "iam.account", string(w.accA), "гонка: rol-g → grp-e1 на acc-A")
	case <-time.After(30 * time.Second):
		close(ops.release)
		t.Fatal("гонка: добавление не дошло ни до решения, ни до заведения операции за 30 с")
	}

	added := false
	if r.err == nil {
		d := awaitOp(t, w.ctx, w.ops, r.op)
		added = d.Error == nil
	}
	members := w.membersOf(w.grpE1)
	t.Logf("гонка: добавление применено — %v; участники %v", added, members)
	if added {
		assert.Equal(t, []string{"service_account:" + w.svaA2}, members, "порядок «добавление, затем выдача»")
	} else {
		assert.Empty(t, members, "порядок «выдача, затем добавление»")
	}
}
