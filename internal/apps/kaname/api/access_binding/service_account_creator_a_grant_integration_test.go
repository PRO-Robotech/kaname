// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_a_grant_integration_test.go — группа A приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// выдача права создавать учётки (SAC-01…SAC-03). Мир — `newSACWorld`.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// SAC-01 — владелец выдаёт роль создателя учётке модуля.
func TestServiceAccountCreator_SAC01_OwnerGrantsTheCreatorRoleToAModuleAccount(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-01")
	require.Zero(t, w.creatorBindings(), "SAC-01 Дано: выдач роли C в acc-A нет")

	bc := w.createDoneX(asUser(w.ctx, w.usrA), w.gC(w.svaIss), "SAC-01: usr-A выдаёт G")
	got := w.getBinding(bc)
	require.Equal(t, string(w.rolC), got.GetRoleId(), "SAC-01: роль выдачи")
	require.Len(t, got.GetSubjects(), 1, "SAC-01: субъектов выдачи")
	require.Equal(t, w.svaIss, got.GetSubjects()[0].GetId(), "SAC-01: субъект выдачи")
	require.Equal(t, "iam.account", got.GetScopeType(), "SAC-01: область выдачи")
	require.Equal(t, string(w.accA), got.GetScopeId(), "SAC-01: объект области")
	require.Equal(t, iamv1.AccessBinding_ACTIVE, got.GetStatus(), "SAC-01: статус выдачи")

	w.pollRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), true,
		"SAC-01: право создавать учётки в окне")
	for _, r := range []string{"editor", "admin", "viewer", "v_get", "v_update"} {
		w.requireRelation("service_account:"+w.svaIss, r, "account:"+string(w.accA), false,
			"SAC-01: роль C не даёт "+r+" на acc-A")
	}
}

// SAC-02 — роль создателя только учётке, только на аккаунт, только целиком.
func TestServiceAccountCreator_SAC02_OnlyAServiceAccountOnlyAnAccountOnlyWhole(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-02")
	scopeText := fmt.Sprintf("role %s grants service account creation on iam.account scope only", w.rolC)
	targetText := fmt.Sprintf("role %s requires target allInScope", w.rolC)
	subjectText := fmt.Sprintf("role %s can only be granted to SUBJECT_TYPE_SERVICE_ACCOUNT", w.rolC)

	rows := []struct {
		name   string
		mutate func(r *iamv1.CreateAccessBindingRequest)
		asR    bool
		text   string
	}{
		{"a — область iam.project", func(r *iamv1.CreateAccessBindingRequest) {
			r.ScopeType, r.ScopeId = "iam.project", string(w.prjA)
		}, false, scopeText},
		{"b — область iam.cluster", func(r *iamv1.CreateAccessBindingRequest) {
			r.ScopeType, r.ScopeId = "iam.cluster", "cluster_root"
		}, true, scopeText},
		{"c — цель — названная учётка", func(r *iamv1.CreateAccessBindingRequest) {
			r.Target = resourcesTarget(&iamv1.ResourceRef{Type: "iam.serviceAccount", Id: w.svaA})
		}, false, targetText},
		{"d — субъект человек", func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
		}, false, subjectText},
		{"e — субъект группа", func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{groupSubject(w.grpA)}
		}, false, subjectText},
		{"f — субъект класс", func(r *iamv1.CreateAccessBindingRequest) {
			r.Subjects = []*iamv1.Subject{classSubject("authenticated")}
		}, false, subjectText},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			before := w.creatorBindings()
			req := w.gC(w.svaIss)
			row.mutate(req)
			caller := asUser(w.ctx, w.usrA)
			if row.asR {
				caller = asUser(w.ctx, w.usrR)
			}
			o := w.tryGrant(caller, req)
			require.Emptyf(t, o.opID, "SAC-02 %s: синхронного отказа нет, заведена операция (ошибка %v)", row.name, o.opErr)
			requireSyncRefusal(t, o.syncErr, codes.FailedPrecondition, row.text, "SAC-02 "+row.name)
			require.Equalf(t, before, w.creatorBindings(), "SAC-02 %s: выдач роли C до = после", row.name)
		})
	}
	// Близнец каждой строки — SAC-01; у строки b — та же выдача G от usr-R.
	bR := w.createDoneX(asUser(w.ctx, w.usrR), w.gC(w.svaIss), "SAC-02 b (близнец): G от usr-R на acc-A")
	require.NotEmpty(t, bR, "SAC-02 b (близнец): id выдачи")
}

// SAC-03 — без права выдавать роль не выдаётся.
func TestServiceAccountCreator_SAC03_NoGrantAuthorityNoGrant(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-03")
	requireDenied(t, w.tryGrant(asUser(w.ctx, w.usrB), w.gC(w.svaIss)), "SAC-03 a: usr-B")
	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.gC(w.svaIss)), "SAC-03 b: sva-iss сам себе")
	require.Zero(t, w.creatorBindings(), "SAC-03: выдач роли C в acc-A")
	// Близнец — SAC-01 (отличается вызывающим).
	w.createDoneX(asUser(w.ctx, w.usrA), w.gC(w.svaIss), "SAC-03 (близнец): G от usr-A")
}
