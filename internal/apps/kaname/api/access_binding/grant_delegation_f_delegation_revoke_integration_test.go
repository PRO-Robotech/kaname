// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_f_delegation_revoke_integration_test.go — группа F приёмки
// делегированных выдач (PRO-Robotech/kaname#986): отзыв делегирования,
// GD-40…GD-45.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// reasonDelegationRevoked — `REVOCATION_REASON_DELEGATION_REVOKED` (Р4) числом:
// значения в перечислении ствола нет, и проба обязана собираться.
const reasonDelegationRevoked = iamv1.AccessBinding_RevocationReason(gdReasonRevokedNum)

// directFacts — число прямых фактов субъекта на объекте (строки
// `relation_fact`): то, что снимают строки снятия выпущенного (CE-10).
func (w *gdWorld) directFacts(subject, objType, objID string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND subject = $3`, objType, objID, subject).Scan(&n))
	return n
}

// GD-40 — отзыв делегирования отзывает всё выданное по нему.
func TestGrantDelegation_GD40_RevokingTheDelegationRevokesWhatItGranted(t *testing.T) {
	w := newGDWorld(t)
	bo := w.boOf()
	w.requireSubject("GD-40")
	d1 := w.d1()
	sa := asSA(w.ctx, w.svaIss)
	b10 := requireGranted(t, w.tryGrant(sa, w.v()), "GD-40 Дано: B10 (GD-10 a)")
	b13 := requireGranted(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{classSubject("anonymous")}
	})), "GD-40 Дано: B13 (GD-13)")
	b14 := requireGranted(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA2)}
		r.Target = resourcesTarget(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp}, &iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrYApp})
	})), "GD-40 Дано: B14 (GD-14 a)")
	// B30 — по D1, уже отозванная делегатом; субъект другой, чем у B10 (CE-19).
	b30 := requireGranted(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA3)}
	})), "GD-40 Дано: B30")
	op, err := w.revokeBinding(sa, b30)
	w.requireVerbDone(op.GetId(), err, "GD-40 Дано: делегат отзывает B30")
	b30Before := w.getBinding(b30)
	require.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_REVOKE, b30Before.GetRevocationReason(), "GD-40 Дано: причина B30")

	// Положительные контроли окна: выданное материализовано до отзыва.
	saA := fmtSubject("service_account", w.svaA)
	w.pollAsk(saA, "v_get", pcrRegType, pcrX, true, "GD-40 Дано: sva-A читает X")
	w.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "GD-40 Дано: anonymous читает X")
	w.pollAsk(fmtSubject("service_account", w.svaA2), "v_update", pcrRepoType, pcrXApp, true, "GD-40 Дано: sva-A2 пишет X/app")

	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-40")
	got, err := w.getDelegation(asUser(w.ctx, w.usrA), d1)
	require.NoError(t, err)
	assert.Equal(t, "REVOKED", got["status"], "GD-40: статус D1")
	assert.Contains(t, got, "revokedAt", "GD-40: revokedAt задан")
	assert.Equal(t, map[string]any{"type": "user", "id": string(w.usrA)}, got["revokedBy"], "GD-40: revokedBy")

	for _, id := range []string{b10, b13, b14} {
		pb := w.getBinding(id)
		assert.Equalf(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-40: статус %s", id)
		assert.Equalf(t, reasonDelegationRevoked, pb.GetRevocationReason(), "GD-40: причина %s", id)
		assert.Equalf(t, string(w.usrA), pb.GetRevokedByUserId(), "GD-40: revokedByUserId %s", id)
	}
	b30After := w.getBinding(b30)
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_REVOKE, b30After.GetRevocationReason(), "GD-40: B30 — прежняя причина")
	assert.True(t, b30Before.GetRevokedAt().AsTime().Equal(b30After.GetRevokedAt().AsTime()), "GD-40: B30 — прежний revokedAt")

	w.pollAsk(saA, "v_get", pcrRegType, pcrX, false, "GD-40: sva-A больше не читает X")
	w.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, false, "GD-40: anonymous больше не читает X")
	w.pollAsk(fmtSubject("service_account", w.svaA2), "v_update", pcrRepoType, pcrXApp, false, "GD-40: sva-A2 больше не пишет X/app")

	// Bo — близнец B10: выдана не по делегированию и действует.
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.getBinding(bo).GetStatus(), "GD-40: Bo действует")
	w.pollAsk(fmtSubject("service_account", w.svaA3), "v_get", pcrRegType, pcrX, true, "GD-40: sva-A3 читает X по Bo")
}

// GD-41 — защита от удаления отзыву делегирования не мешает.
func TestGrantDelegation_GD41_DeletionProtectionDoesNotStopDelegationRevoke(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-41")
	d1 := w.d1()
	bp := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.DeletionProtection = true
	})), "GD-41 Дано: Bp")

	_, err := w.revokeBinding(asSA(w.ctx, w.svaIss), bp)
	requireRefusal(t, err, codes.FailedPrecondition,
		fmt.Sprintf("access binding %s has deletion_protection enabled; clear it via Update before revoke", bp), "GD-41 a")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.getBinding(bp).GetStatus(), "GD-41 a: Bp действует")

	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-41 b")
	pb := w.getBinding(bp)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-41 b: Bp отозвана")
	assert.Equal(t, reasonDelegationRevoked, pb.GetRevocationReason(), "GD-41 b: причина")
}

// GD-42 — после отзыва делегат не выдаёт; близнец — GD-10 a (D1 действует).
func TestGrantDelegation_GD42_DelegateCannotGrantAfterRevoke(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-42")
	d1 := w.d1()
	requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-42 близнец (GD-10 a)")
	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-42 Дано: отзыв D1")
	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-42")
}

// GD-43 — повторный отзыв и отзыв несуществующего; близнец a — отзыв действующего D1 (Дано).
func TestGrantDelegation_GD43_RepeatedRevokeAndRevokeOfTheAbsent(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-43")
	d1 := w.d1()
	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-43 Дано и близнец a: отзыв действующего D1")

	// a — канал отказа приёмка не называет (синхронно либо `Operation.error`):
	// утверждаются код и текст, где бы отказ ни пришёл (вопрос к приёмке в
	// возврате полосы PRO-Robotech/kaname#1009).
	o := w.gdMutate(asUser(w.ctx, w.usrA), "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, d1))
	wantA := fmt.Sprintf("grant delegation %s is already revoked", d1)
	switch {
	case o.syncErr != nil:
		requireRefusal(t, o.syncErr, codes.FailedPrecondition, wantA, "GD-43 a")
	case o.opErr != nil:
		assert.Equal(t, codes.FailedPrecondition, o.opErr.Code(), "GD-43 a: код (текст %q)", o.opErr.Message())
		assert.Equal(t, wantA, o.opErr.Message(), "GD-43 a: текст")
	default:
		t.Fatalf("GD-43 a: повторный отзыв принят")
	}
	o = w.gdMutate(asUser(w.ctx, w.usrA), "Revoke", `{"grantDelegationId":"gdl00000000000000099"}`)
	requireRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", "GD-43 b")
	o = w.gdMutate(asUser(w.ctx, w.usrA), "Revoke", `{"grantDelegationId":"gdl!!"}`)
	requireRefusal(t, o.syncErr, codes.InvalidArgument, "invalid grant delegation id 'gdl!!'", "GD-43 c")
}

// GD-44 — кто вправе отозвать. Каждая строка — на свежем мире.
func TestGrantDelegation_GD44_WhoMayRevoke(t *testing.T) {
	type row struct {
		name   string
		caller func(w *gdWorld) (ctxUser string, sva string)
		ok     bool
	}
	rows := []row{
		{"a: usr-E (администратор acc-A)", func(w *gdWorld) (string, string) { return string(w.usrE), "" }, true},
		{"b: usr-B", func(w *gdWorld) (string, string) { return string(w.usrB), "" }, false},
		{"c: sva-iss (делегат)", func(w *gdWorld) (string, string) { return "", w.svaIss }, false},
		{"d: usr-C (владелец acc-B)", func(w *gdWorld) (string, string) { return string(w.usrC), "" }, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w := newGDWorld(t)
			w.requireSubject("GD-44 " + r.name)
			d1 := w.d1()
			user, sva := r.caller(w)
			ctx := asUserID(w, user)
			if sva != "" {
				ctx = asSA(w.ctx, sva)
			}
			o := w.gdMutate(ctx, "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, d1))
			got, err := w.getDelegation(asUser(w.ctx, w.usrA), d1)
			require.NoError(t, err)
			if r.ok {
				require.NoError(t, o.syncErr, "GD-44 %s", r.name)
				require.Nil(t, o.opErr, "GD-44 %s: ошибка операции", r.name)
				assert.Equal(t, map[string]any{"type": "user", "id": user}, got["revokedBy"], "GD-44 %s: revokedBy", r.name)
				return
			}
			requireRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", "GD-44 "+r.name+" (побайтово GD-43 b)")
			assert.Equal(t, "ACTIVE", got["status"], "GD-44 %s: D1 действует", r.name)
		})
	}
}

// GD-45 — учётку-делегата нельзя удалить при действующем делегировании.
func TestGrantDelegation_GD45_DelegateAccountCannotBeDeletedWhileDelegationActive(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-45")
	d1 := w.d1()
	del := func() (string, error) {
		op, err := w.sas.Delete(asUser(w.ctx, w.usrS), &iamv1.DeleteServiceAccountRequest{ServiceAccountId: w.svaIss})
		if err != nil {
			return "", err
		}
		return op.GetId(), nil
	}
	exists := func() bool {
		var n int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id = $1`, w.svaIss).Scan(&n))
		return n == 1
	}

	opID, err := del()
	require.NoError(t, err, "GD-45 a: отказ — в операции (удаление учётки асинхронно)")
	done := awaitOp(t, w.ctx, w.ops, opID)
	require.NotNil(t, done.Error, "GD-45 a: учётка-делегат удалена при действующем делегировании")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "GD-45 a: код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("service account %s holds an active grant delegation %s; revoke it first", w.svaIss, d1),
		done.Error.Message, "GD-45 a: текст")
	assert.True(t, exists(), "GD-45 a: учётка на месте")

	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-45 b: отзыв D1")
	opID, err = del()
	require.NoError(t, err, "GD-45 b")
	done = awaitOp(t, w.ctx, w.ops, opID)
	require.Nilf(t, done.Error, "GD-45 b (близнец): удаление после отзыва — ошибка %+v", done.Error)
	assert.False(t, exists(), "GD-45 b: учётки нет")
}
