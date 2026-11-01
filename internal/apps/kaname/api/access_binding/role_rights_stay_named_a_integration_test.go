// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_a_integration_test.go — группа A приёмки
// role-rights-stay-within-what-is-named.md: право удалять даёт только удаление
// (Р1, В1; задачи PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1039). Мир — `newEscWorld`.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ESC-01 — одно право удалять на проекте не даёт права выдавать.
func TestRoleRightsStayNamed_ESC01_DeleteOnProjectGivesNoGrantAuthority(t *testing.T) {
	w := newEscWorld(t)
	x := pcrRegType + ":" + pcrX

	// Строки охраны — первыми: они читаются и там, где строки предмета красные.
	for _, row := range []struct {
		name   string
		caller domain.UserID
	}{
		{"c usr-W (rol-star)", w.usrStar},
		{"d usr-E (admin на acc-A)", w.usrE},
		{"e usr-A (владелец acc-A)", w.usrA},
	} {
		id := requireGranted(t, w.tryGrant(asUser(w.ctx, row.caller), w.vE()), "ESC-01 "+row.name)
		require.Equalf(t, "ACTIVE", w.getBinding(id).GetStatus().String(), "ESC-01 %s: выдача действует", row.name)
		if row.caller == w.usrStar {
			w.pollRelation("service_account:"+w.svaA2, "v_get", x, true, "ESC-01 c: sva-A2 получила v_get на X")
		}
		// Активная выдача уникальна по (субъект, роль, область, цель): следующая
		// строка заводит ту же выдачу, поэтому эта отзывается владельцем.
		w.revokeDone(id, "ESC-01 "+row.name+": отзыв перед следующей строкой")
	}

	for _, row := range []struct {
		name   string
		caller domain.UserID
	}{
		{"a usr-D (rol-del)", w.usrDel},
		{"b usr-U (rol-upd-del)", w.usrUpdDel},
	} {
		before := w.activeBindingsOn("project", string(w.prjA))
		w.escDenied(t, w.tryGrant(asUser(w.ctx, row.caller), w.vE()), "ESC-01 "+row.name)
		assert.Equalf(t, before, w.activeBindingsOn("project", string(w.prjA)),
			"ESC-01 %s: выдач на prj-A столько же, сколько до вызова", row.name)
	}
}

// escDenied — синхронный `PERMISSION_DENIED` `permission denied`, операции нет.
// Отказ утверждается без остановки пробы: выдача, заведённая вопреки
// ожиданию, отзывается владельцем, чтобы следующая строка шла по прежнему миру.
func (w *escWorld) escDenied(t *testing.T, o grantOutcome, why string) {
	t.Helper()
	if o.bindingID != "" {
		w.revokeDone(o.bindingID, why+": отзыв выдачи, заведённой вопреки отказу")
	}
	if !assert.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция (ошибка операции %v)", why, o.opErr) {
		return
	}
	st, ok := status.FromError(o.syncErr)
	if assert.Truef(t, ok && o.syncErr != nil, "%s: ожидался синхронный gRPC-отказ, получено %v", why, o.syncErr) {
		assert.Equalf(t, codes.PermissionDenied, st.Code(), "%s: код отказа (текст %q)", why, st.Message())
		assert.Equalf(t, "permission denied", st.Message(), "%s: текст отказа", why)
	}
}

// ESC-02 — право удалять на аккаунте не даёт ни права выдавать, ни прав в его проектах.
func TestRoleRightsStayNamed_ESC02_DeleteOnAccountGivesNothingBeyondDeletion(t *testing.T) {
	w := newEscWorld(t)
	onAccount := w.vE()
	onAccount.ScopeType, onAccount.ScopeId = "iam.account", string(w.accA)

	// a, b — выдача на аккаунт и на проект.
	for _, row := range []struct {
		name string
		req  *iamv1.CreateAccessBindingRequest
	}{
		{"a область iam.account acc-A", onAccount},
		{"b область iam.project prj-A", w.vE()},
	} {
		req := row.req
		id := requireGranted(t, w.tryGrant(asUser(w.ctx, w.usrE), req), "ESC-02 "+row.name+", usr-E")
		w.revokeDone(id, "ESC-02 "+row.name+": отзыв выдачи usr-E")
		w.escDenied(t, w.tryGrant(asUser(w.ctx, w.usrAccDel), req), "ESC-02 "+row.name+", usr-Da")
	}

	prj := "project:" + string(w.prjA)
	x := pcrRegType + ":" + pcrX
	// Парные контроли usr-E — в окне, затем ответы usr-Da.
	w.pollRelation(escUser(w.usrE), "editor", prj, true, "ESC-02 c, usr-E")
	w.pollRelation(escUser(w.usrE), "v_get", x, true, "ESC-02 d, usr-E")
	assert.False(t, w.relation(escUser(w.usrAccDel), "editor", prj), "ESC-02 c: usr-Da не держит editor на prj-A")
	assert.False(t, w.relation(escUser(w.usrAccDel), "v_get", x), "ESC-02 d: usr-Da не держит v_get на X")
	// e — право удалять аккаунт сохранено (Р4).
	assert.True(t, w.checkAction(escUser(w.usrAccDel), "iam.accounts.delete", "account", string(w.accA)),
		"ESC-02 e: usr-Da вправе удалить acc-A")
	assert.True(t, w.checkAction(escUser(w.usrE), "iam.accounts.delete", "account", string(w.accA)),
		"ESC-02 e: usr-E вправе удалить acc-A")
}

// ESC-03 — ярус проекта из одного удаления не выводится.
func TestRoleRightsStayNamed_ESC03_ProjectTierIsNotDerivedFromDeletion(t *testing.T) {
	w := newEscWorld(t)
	prj := "project:" + string(w.prjA)
	want := map[string]map[domain.UserID]bool{
		"admin":    {w.usrDel: false, w.usrUpdDel: false, w.usrStar: true},
		"editor":   {w.usrDel: false, w.usrUpdDel: true, w.usrStar: true},
		"viewer":   {w.usrDel: false, w.usrUpdDel: true, w.usrStar: true},
		"v_delete": {w.usrDel: true, w.usrUpdDel: true, w.usrStar: true},
	}
	w.escTable(t, "ESC-03", prj, want)
}

// ESC-04 — на листовом объекте право удалять не открывает изменений.
func TestRoleRightsStayNamed_ESC04_DeletionOnALeafOpensNoChange(t *testing.T) {
	w := newEscWorld(t)
	x := pcrRegType + ":" + pcrX
	// a — вопрос с действием (форма «с действием»), парные контроли — usr-U, usr-W.
	for _, u := range []domain.UserID{w.usrUpdDel, w.usrStar} {
		assert.Truef(t, w.checkAction(escUser(u), "registry.registries.update", pcrRegType, pcrX),
			"ESC-04 a: %s вправе править X", u)
	}
	assert.False(t, w.checkAction(escUser(w.usrDel), "registry.registries.update", pcrRegType, pcrX),
		"ESC-04 a: usr-D не вправе править X")
	w.escTable(t, "ESC-04", x, map[string]map[domain.UserID]bool{
		"editor": {w.usrDel: false, w.usrUpdDel: true, w.usrStar: true},
		"admin":  {w.usrDel: false, w.usrUpdDel: false, w.usrStar: true},
		"viewer": {w.usrDel: false, w.usrUpdDel: true, w.usrStar: true},
	})
}

// ESC-05 — удаление остаётся удалением (Р4: `Check(delete)`).
func TestRoleRightsStayNamed_ESC05_DeletionStaysDeletion(t *testing.T) {
	w := newEscWorld(t)
	holders := []domain.UserID{w.usrDel, w.usrUpdDel, w.usrStar, w.usrE, w.usrA}
	for _, u := range holders {
		w.pollRelation(escUser(u), "v_delete", pcrRegType+":"+pcrX, true, "ESC-05 b")
		assert.Truef(t, w.checkAction(escUser(u), "registry.registries.delete", pcrRegType, pcrX), "ESC-05 a: %s", u)
		assert.Truef(t, w.checkAction(escUser(u), "iam.projects.delete", "project", string(w.prjA)), "ESC-05 c: %s", u)
	}
	assert.False(t, w.checkAction(escUser(w.usrM), "registry.registries.delete", pcrRegType, pcrX), "ESC-05 a: usr-M")
	assert.False(t, w.relation(escUser(w.usrM), "v_delete", pcrRegType+":"+pcrX), "ESC-05 b: usr-M")
	assert.False(t, w.checkAction(escUser(w.usrM), "iam.projects.delete", "project", string(w.prjA)), "ESC-05 c: usr-M")
}

// ESC-06 — «кто может удалить» согласен с `Check(delete)`; право спрашивать о
// чужом не выводится из удаления.
func TestRoleRightsStayNamed_ESC06_WhoMayDeleteAgreesWithCheck(t *testing.T) {
	w := newEscWorld(t)
	const action = "registry.registries.delete"
	w.pollRelation(escUser(w.usrDel), "v_delete", pcrRegType+":"+pcrX, true, "ESC-06: контроль v_delete usr-D")

	// а — вызывающий модуль.
	subs, err := w.listSubjects(moduleCtx(), action)
	require.NoError(t, err, "ESC-06 а: ListSubjects от модуля")
	assert.Contains(t, subs, escUser(w.usrDel), "ESC-06 а: держатель одного удаления в ответе «кто может удалить X»")
	assert.NotContains(t, subs, escUser(w.usrM), "ESC-06 а: человек без выдач не в ответе")

	// б2 — вызывающий с `*` (парный контроль), б1 — вызывающий с одним `delete`.
	subs, err = w.listSubjects(asUser(w.ctx, w.usrStar), action)
	require.NoError(t, err, "ESC-06 б2: usr-W спрашивает о чужих на X")
	assert.Contains(t, subs, escUser(w.usrDel), "ESC-06 б2: ответ содержит usr-D")
	_, err = w.listSubjects(asUser(w.ctx, w.usrDel), action)
	requireSyncRefusal(t, err, codes.PermissionDenied, "permission denied", "ESC-06 б1: usr-D спрашивает о чужих на X")
}

// escTable — ответы `Check` с отношением на одном объекте. Сперва в окне — все
// ожидания `true` (парные контроли), затем — ожидания `false` одним вопросом.
func (w *escWorld) escTable(t *testing.T, sc, object string, want map[string]map[domain.UserID]bool) {
	t.Helper()
	for rel, row := range want {
		for u, v := range row {
			if v {
				w.pollRelation(escUser(u), rel, object, true, sc+" "+rel)
			}
		}
	}
	for rel, row := range want {
		for u, v := range row {
			if !v {
				assert.Falsef(t, w.relation(escUser(u), rel, object), "%s: Check(%s, %s, %s) обязан быть false", sc, u, rel, object)
			}
		}
	}
}
