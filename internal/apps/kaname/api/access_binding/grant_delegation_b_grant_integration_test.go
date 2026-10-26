// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_b_grant_integration_test.go — группа B приёмки делегированных
// выдач (PRO-Robotech/kaname#986): выдача делегатом в пределах делегирования,
// GD-10…GD-16 (SRI-111 приёмки svc-registry).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// d2 — D2 (§4.1): делегат sva-iss2, `targetTypes: ["registry.registries"]`, от usr-A.
func (w *gdWorld) d2() string {
	w.t.Helper()
	return w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss2, "registry.registries"), "Дано: D2 от usr-A")
}

// dU — D-U (§4.1): делегат sva-iss2, `subjectTypes` — все четыре типа, от usr-A.
func (w *gdWorld) dU() string {
	w.t.Helper()
	body := w.delegationBody(w.accA, w.svaIss2,
		[]domain.RoleID{w.rolPuller, w.rolPusher, w.rolRegAdmin},
		[]string{"registry.registries", "registry.repositories"},
		[]string{"SUBJECT_TYPE_GROUP", "SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS", "SUBJECT_TYPE_USER"})
	return w.createDelegation(asUser(w.ctx, w.usrA), body, "Дано: D-U от usr-A")
}

// vWith — тело V с одной правкой.
func (w *gdWorld) vWith(edit func(r *iamv1.CreateAccessBindingRequest)) *iamv1.CreateAccessBindingRequest {
	r := proto.Clone(w.v()).(*iamv1.CreateAccessBindingRequest)
	edit(r)
	return r
}

// requireDelegatedBinding — выдача от usr-A: ACTIVE, `delegationId` = gdl, без `grantedByUserId`.
func (w *gdWorld) requireDelegatedBinding(id, gdl, sc string) *iamv1.AccessBinding {
	w.t.Helper()
	pb := w.getBinding(id)
	assert.Equalf(w.t, iamv1.AccessBinding_ACTIVE, pb.GetStatus(), "%s: status", sc)
	got, ok := delegationIDOf(w.t, pb)
	assert.Truef(w.t, ok, "%s: ключа delegationId нет", sc)
	assert.Equalf(w.t, gdl, got, "%s: delegationId", sc)
	assert.Emptyf(w.t, pb.GetGrantedByUserId(), "%s: grantedByUserId у выдачи учёткой", sc)
	return pb
}

// GD-10 — делегат выдаёт роль модуля на объект модуля учётке аккаунта.
func TestGrantDelegation_GD10_DelegateGrantsAModuleRoleOnAModuleObject(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-10")
	d1 := w.d1()

	for _, r := range []struct {
		name string
		req  *iamv1.CreateAccessBindingRequest
	}{
		{"a", w.v()},
		{"b", w.vWith(func(r *iamv1.CreateAccessBindingRequest) { r.ScopeType, r.ScopeId = "iam.account", string(w.accA) })},
	} {
		sc := "GD-10 " + r.name
		id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), r.req), sc)
		pb := w.requireDelegatedBinding(id, d1, sc)
		assert.Equalf(t, string(w.rolPusher), pb.GetRoleId(), "%s: роль", sc)
		require.Lenf(t, pb.GetSubjects(), 1, "%s: субъектов", sc)
		assert.Equalf(t, w.svaA, pb.GetSubjects()[0].GetId(), "%s: субъект", sc)
		refs := pb.GetTarget().GetResources().GetResources()
		require.Lenf(t, refs, 1, "%s: цель", sc)
		assert.Equalf(t, pcrX, refs[0].GetId(), "%s: объект цели", sc)
	}
	w.pollAsk(fmtSubject("service_account", w.svaA), "v_get", pcrRegType, pcrX, true,
		"GD-10: выдача делегатом материализуется в v_get на X")
}

// GD-11 — выдача за пределами делегирования отвергается; близнец каждой строки — GD-10 a.
func TestGrantDelegation_GD11_GrantBeyondTheDelegationIsRefused(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-11")
	d1 := w.d1()

	zTarget := resourcesTarget(&iamv1.ResourceRef{Type: pcrRegTgt, Id: gdZ})
	rows := []struct {
		name, axis string
		req        *iamv1.CreateAccessBindingRequest
	}{
		{"a", "набор ролей", w.vWith(func(r *iamv1.CreateAccessBindingRequest) { r.RoleId = string(w.rolRegGet) })},
		{"b", "набор ролей (SRI-111 b)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.RoleId, r.ScopeType, r.ScopeId = gdAdminRID, "iam.account", string(w.accA)
		})},
		{"c", "вид цели (SRI-111 c)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.RoleId, r.Target = string(w.rolPuller), allInScopeTarget()
		})},
		{"d", "тип субъекта (SRI-111 d)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
		})},
		{"e", "тип субъекта", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{groupSubject(w.grpA)}
		})},
		{"f", "область", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.ScopeId, r.Target = string(w.prjC), zTarget
		})},
		{"g", "объект вне аккаунта", w.vWith(func(r *iamv1.CreateAccessBindingRequest) { r.Target = zTarget })},
		{"h", "объект не существует (Д7)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Target = resourcesTarget(&iamv1.ResourceRef{Type: pcrRegTgt, Id: gdQ})
		})},
		{"i", "субъект вне аккаунта (Д6)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{svaSubject(w.svaB)}
		})},
		{"j", "себе (Д4)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{svaSubject(w.svaIss)}
		})},
		{"k", "область кластера", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.ScopeType, r.ScopeId = "iam.cluster", domain.ClusterSingletonID
		})},
		{"l", "системный класс (Д5)", w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{classSubject("authenticated")}
		})},
	}
	before := w.countDelegated(d1)
	auditBefore := w.auditCount("iam.access_binding.granted", w.svaIss)
	for _, r := range rows {
		requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss), r.req), "GD-11 "+r.name+" ("+r.axis+")")
	}
	assert.Equal(t, before, w.countDelegated(d1), "GD-11: выдач с delegationId D1 прибавилось")
	assert.Equal(t, auditBefore, w.auditCount("iam.access_binding.granted", w.svaIss), "GD-11: строк аудита granted от sva-iss прибавилось")

	// Близнец каждой строки — GD-10 a.
	id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-11 близнец (GD-10 a)")
	w.requireDelegatedBinding(id, d1, "GD-11 близнец (GD-10 a)")
}

// GD-12 — ось типов цели.
func TestGrantDelegation_GD12_TargetTypeAxis(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-12")
	d2 := w.d2()

	grant := func(target *iamv1.AccessTarget) grantOutcome {
		return w.tryGrant(asSA(w.ctx, w.svaIss2), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.RoleId, r.Target = string(w.rolPuller), target
		}))
	}
	requireDenied(t, grant(resourcesTarget(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp})), "GD-12 a")
	id := requireGranted(t, grant(pcrXTarget()), "GD-12 b")
	w.requireDelegatedBinding(id, d2, "GD-12 b")
}

// GD-13 — публичный режим: выдача классу anonymous (SRI-111 e, SRI-71).
func TestGrantDelegation_GD13_DelegateGrantsToAnonymous(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-13")
	d1 := w.d1()

	id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{classSubject("anonymous")}
	})), "GD-13")
	w.requireDelegatedBinding(id, d1, "GD-13")
	w.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "GD-13: anonymous получает v_get на X в окне")
}

// GD-14 — выдача на несколько объектов (SRI-86).
func TestGrantDelegation_GD14_GrantOnSeveralObjects(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-14")
	d1 := w.d1()

	grant := func(refs ...*iamv1.ResourceRef) grantOutcome {
		return w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects, r.Target = []*iamv1.Subject{svaSubject(w.svaA2)}, resourcesTarget(refs...)
		}))
	}
	// b первой: отказ ничего не пишет, и a идёт на чистом мире.
	requireDenied(t, grant(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp}, &iamv1.ResourceRef{Type: gdRepoTgt, Id: gdQ + "/app"}),
		"GD-14 b")
	id := requireGranted(t, grant(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp}, &iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrYApp}),
		"GD-14 a")
	pb := w.requireDelegatedBinding(id, d1, "GD-14 a")
	var got []string
	for _, ref := range pb.GetTarget().GetResources().GetResources() {
		got = append(got, ref.GetId())
	}
	assert.ElementsMatch(t, []string{pcrXApp, pcrYApp}, got, "GD-14 a: цель — оба объекта")
	for _, obj := range []string{pcrXApp, pcrYApp} {
		w.pollAsk(fmtSubject("service_account", w.svaA2), "v_update", pcrRepoType, obj, true,
			"GD-14 a: sva-A2 получает v_update на "+obj)
	}
}

// GD-15 — делегирование не даёт доступа к данным; близнец — sva-A по GD-10 a.
func TestGrantDelegation_GD15_DelegationGivesNoDataAccess(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-15")
	d1 := w.d1()
	id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-15 Дано: GD-10 a")
	w.requireDelegatedBinding(id, d1, "GD-15 Дано: GD-10 a")
	w.pollAsk(fmtSubject("service_account", w.svaA), "v_get", pcrRegType, pcrX, true, "GD-15 близнец: sva-A")

	w.requireAsk(fmtSubject("service_account", w.svaIss), "v_get", pcrRegType, pcrX, false, "GD-15: делегат")
	// Перечень выдач учётки читает держатель права на ЕЁ аккаунт — владелец acc-S
	// usr-S: sva-iss живёт в acc-S, и у владельца acc-A права читать выдачи чужой
	// учётки нет (прогон: PERMISSION_DENIED). Вызывающего приёмка не называет.
	resp, err := w.abx.ListBySubject(asUser(w.ctx, w.usrS), &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "service_account", SubjectId: w.svaIss})
	require.NoError(t, err, "GD-15: ListBySubject sva-iss")
	assert.Empty(t, resp.GetAccessBindings(), "GD-15: выдач с субъектом sva-iss")
}

// GD-16 — человек и группа — только из аккаунта делегирования (Д6). Каждая строка — на свежем мире.
func TestGrantDelegation_GD16_PersonAndGroupOnlyFromTheDelegationAccount(t *testing.T) {
	type row struct {
		name    string
		subject func(w *gdWorld) *iamv1.Subject
		granted bool
		person  func(w *gdWorld) domain.UserID
	}
	rows := []row{
		{name: "a: группа acc-A", subject: func(w *gdWorld) *iamv1.Subject { return groupSubject(w.grpA) }, granted: true},
		{name: "b: группа acc-B", subject: func(w *gdWorld) *iamv1.Subject { return groupSubject(w.grpB) }},
		{name: "c: участник acc-A ACTIVE", subject: func(w *gdWorld) *iamv1.Subject { return userSubject(w.usrM) }, granted: true,
			person: func(w *gdWorld) domain.UserID { return w.usrM }},
		{name: "d: нет членства в acc-A", subject: func(w *gdWorld) *iamv1.Subject { return userSubject(w.usrC) }},
		{name: "e: членство PENDING", subject: func(w *gdWorld) *iamv1.Subject { return userSubject(w.usrP) }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w := newGDWorld(t)
			w.requireSubject("GD-16 " + r.name)
			dU := w.dU()
			req := w.vWith(func(q *iamv1.CreateAccessBindingRequest) {
				q.RoleId, q.Subjects = string(w.rolPuller), []*iamv1.Subject{r.subject(w)}
			})
			before := w.countDelegated(dU)
			o := w.tryGrant(asSA(w.ctx, w.svaIss2), req)
			if !r.granted {
				requireDenied(t, o, "GD-16 "+r.name)
				assert.Equal(t, before, w.countDelegated(dU), "GD-16 %s: выдач с delegationId D-U прибавилось", r.name)
				return
			}
			id := requireGranted(t, o, "GD-16 "+r.name)
			w.requireDelegatedBinding(id, dU, "GD-16 "+r.name)
			if r.person != nil {
				w.pollAsk(fmtSubject("user", string(r.person(w))), "v_get", pcrRegType, pcrX, true,
					"GD-16 "+r.name+": участник получает v_get на X")
			}
		})
	}
}

// Д4 по §1 приёмки («делегирование не даёт делегату доступа к данным»):
// субъект-группа, в составе которой делегат, — тот же делегат: право роли через
// состав группы дошло бы до него самого. Учётка-делегат (acc-S) стоит в группе
// acc-A — состояние, которое прежний глагол `GroupService.AddMember` принимал, а
// нынешний не заводит (Д-3); оно сеется строкой. Затем делегат выдаёт этой
// группе роль модуля на X. Близнец — та же группа без
// делегата (GD-16 a): отличается ровно составом группы. Каждая строка — на
// свежем мире.
func TestGrantDelegation_D4_GroupHoldingTheDelegateIsRefused(t *testing.T) {
	for _, r := range []struct {
		name           string
		delegateMember bool
	}{
		{name: "a: делегат в составе группы", delegateMember: true},
		{name: "b: близнец — группа без делегата", delegateMember: false},
	} {
		t.Run(r.name, func(t *testing.T) {
			w := newGDWorld(t)
			w.requireSubject("Д4 " + r.name)
			dU := w.dU()
			if r.delegateMember {
				// Прежнее состояние — строкой посева, а не глаголом: учётка sva-iss2
				// живёт в acc-S, и `GroupService.AddMember` больше не включает в группу
				// участника не из её аккаунта (Д-3 приёмки
				// role-rights-stay-within-what-is-named.md, решение В-4.2). Посев — то,
				// что оставлял прежний глагол: строка состава и факт `member` модели
				// (форма `memberFGATuple`) — тем же коммитом журнала, что у глагола.
				_, err := w.pool.Exec(w.ctx, `
					INSERT INTO kaname.group_members (group_id, member_type, member_id)
					VALUES ($1, 'service_account', $2)`, w.grpA, w.svaIss2)
				require.NoError(t, err, "Д4 Дано: строка состава sva-iss2 → grp-A")
				gdSeedTuple(t, w.ctx, w.pool, "service_account:"+w.svaIss2, "member", "group:"+w.grpA)
			}
			var members int
			require.NoError(t, w.pool.QueryRow(w.ctx, `
				SELECT count(*) FROM kaname.group_members
				 WHERE group_id = $1 AND member_type = 'service_account' AND member_id = $2`,
				w.grpA, w.svaIss2).Scan(&members))
			want := 0
			if r.delegateMember {
				want = 1
			}
			require.Equalf(t, want, members, "Д4 контроль %s: делегат в составе grp-A", r.name)

			req := w.vWith(func(q *iamv1.CreateAccessBindingRequest) {
				q.RoleId, q.Subjects = string(w.rolPuller), []*iamv1.Subject{groupSubject(w.grpA)}
			})
			before := w.countDelegated(dU)
			o := w.tryGrant(asSA(w.ctx, w.svaIss2), req)
			if r.delegateMember {
				requireDenied(t, o, "Д4 "+r.name)
				assert.Equal(t, before, w.countDelegated(dU), "Д4 %s: выдач с delegationId D-U прибавилось", r.name)
				return
			}
			id := requireGranted(t, o, "Д4 "+r.name)
			w.requireDelegatedBinding(id, dU, "Д4 "+r.name)
		})
	}
}
