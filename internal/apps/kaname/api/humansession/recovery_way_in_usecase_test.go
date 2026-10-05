// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_way_in_usecase_test.go — личность без способа входа возвращается
// восстановлением (задача PRO-Robotech/kaname#608; приёмка
// `docs/engineering/acceptance/recovery-of-access.md` Р9, Ф5-29…34, на дублёре
// хранилища).
//
// Каждое отрицание стоит рядом с близнецом, отличающимся одним фактом:
// Ф5-31 (строка пароля) и Ф5-32 (статус) — против Ф5-29; Ф5-33 (инъекция) —
// против Ф5-30; Ф5-34 (а) — против (б) строкой пароля.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// withoutWayIn — личность ACTIVE без строки пароля в форме «после переноса»:
// отметка открытого пути стоит (пара, AWI-11).
func (h *harness) withoutWayIn(t *testing.T, id, email string, verified bool) domain.User {
	t.Helper()
	u := h.person(t, id, email, "", verified)
	h.store.openPath[u.ID] = true
	return u
}

// Ф5-29 — код выдаётся и на неподтверждённый адрес ACTIVE без пароля; ответ
// тот же, что для адреса, которого нет; клетка `queued`, а не `unverified`.
func TestRecovery_F5_29_UnverifiedAddressOfAnIdentityWithoutAWayInGetsACode(t *testing.T) {
	h := newHarness(t, nil)
	a := h.withoutWayIn(t, "usr-r29", "r29@example.invalid", false)

	errA := h.recoveryRequest.Execute(context.Background(), humansession.RequestRecoveryInput{Email: "r29@example.invalid", Source: rcSource})
	errZ := h.recoveryRequest.Execute(context.Background(), humansession.RequestRecoveryInput{Email: "z29@example.invalid", Source: rcSource})
	require.Equal(t, errZ, errA, "Ф5-29: ответ для A равен ответу для адреса, которого нет")
	require.NoError(t, errA)

	codes := h.store.codesOf(a.ID)
	require.Len(t, codes, 1, "Ф5-29: код чеканится")
	require.True(t, codes[0].ExpiresAt.Equal(ucBase.Add(rcCodeTTL)), "срок — нашей настройки")
	require.Len(t, h.store.mail, 1, "Ф5-29: письмо вида восстановления в очереди")
	require.Equal(t, a.ID, h.store.mail[0].UserID)
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestQueued], "клетка queued выросла на 1")
	require.Zero(t, h.obs.recoveryRequest[humansession.RecoveryRequestUnverified], "клетка unverified не выросла")
}

// Ф5-31 — близнец Ф5-29 строкой пароля: неподтверждённый адрес с паролем кода
// не получает, как прежде.
func TestRecovery_F5_31_UnverifiedAddressWithAPasswordStillGetsNoCode(t *testing.T) {
	h := newHarness(t, nil)
	b := h.person(t, "usr-r31", "r31@example.invalid", "old-password-31", false)

	h.request(t, "r31@example.invalid")

	require.Empty(t, h.store.mail, "Ф5-31: письма нет")
	require.Empty(t, h.store.codesOf(b.ID), "Ф5-31: кода нет")
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestUnverified])
}

// Ф5-32 — близнец Ф5-29 статусом: PENDING без пароля кода не получает.
func TestRecovery_F5_32_PendingWithoutAPasswordStillGetsNoCode(t *testing.T) {
	h := newHarness(t, nil)
	c := h.person(t, "usr-r32", "r32@example.invalid", "", false)
	c.InviteStatus = domain.InviteStatusPending
	h.store.users[c.ID] = c

	h.request(t, "r32@example.invalid")

	require.Empty(t, h.store.mail, "Ф5-32: письма нет")
	require.Empty(t, h.store.codesOf(c.ID))
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestUnverified])
	require.Equal(t, domain.InviteStatusPending, h.store.users[c.ID].InviteStatus, "статус прежний")
}

// Ф5-30 — предъявление кода заводит первый пароль, подтверждает адрес и
// снимает отметку открытого пути — одним исходом; (в) негодный пароль код не
// тратит.
func TestRecovery_F5_30_PresentationSetsTheFirstPasswordAndVerifiesTheAddress(t *testing.T) {
	h := newHarness(t, nil)
	a := h.withoutWayIn(t, "usr-r30", "r30@example.invalid", false)
	h.request(t, "r30@example.invalid")
	letter := h.letterOf(t, a.ID)

	// (в) негодный пароль — отказ полем, код не тратится, ничего не записано.
	_, err := h.complete("r30@example.invalid", letter, "short")
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe, "Ф5-30 (в): отказ называет поле")
	require.Equal(t, "newPassword", fe.Field)
	require.Nil(t, h.store.codesOf(a.ID)[0].ConsumedAt, "Ф5-30 (в): код не потрачен")
	require.False(t, h.store.verified[a.ID], "Ф5-30 (в): адрес не подтверждён")
	_, has := h.store.verifiers[a.ID]
	require.False(t, has, "Ф5-30 (в): пароля нет")

	h.clock = ucBase.Add(time.Minute)
	out, err := h.complete("r30@example.invalid", letter, "brand-new-password-30")
	require.NoError(t, err, "Ф5-30: сессия выдана, а не 503")
	require.True(t, out.View.EmailVerified, "Ф5-30: emailVerified в ответе — после записи")
	require.False(t, out.Bearer.IsZero())
	require.True(t, h.store.verified[a.ID], "Ф5-30: адрес подтверждён")
	require.False(t, h.store.openPath[a.ID], "Ф5-30: отметки открытого пути нет")
	require.Equal(t, domain.InviteStatusActive, h.store.users[a.ID].InviteStatus, "статус прежний")
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionIssued])

	h.clock = h.clock.Add(time.Second)
	h.mustLogin(t, "r30@example.invalid", "brand-new-password-30")

	_, err = h.complete("r30@example.invalid", letter, "another-password-30")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "Ф5-30: второе предъявление — отказ Ф5-05")
}

// Ф5-30 (б) — близнец подтверждённостью адреса: отметка подтверждения прежняя.
func TestRecovery_F5_30b_VerifiedAddressKeepsItsMark(t *testing.T) {
	h := newHarness(t, nil)
	n := h.withoutWayIn(t, "usr-r30b", "r30b@example.invalid", true)
	h.request(t, "r30b@example.invalid")
	letter := h.letterOf(t, n.ID)

	h.clock = ucBase.Add(time.Minute)
	out, err := h.complete("r30b@example.invalid", letter, "brand-new-password-30b")
	require.NoError(t, err)
	require.True(t, out.View.EmailVerified)
	require.True(t, h.store.verified[n.ID])
	require.False(t, h.store.openPath[n.ID], "Ф5-30 (б): отметки открытого пути нет")
}

// Ф5-33 — отказ внутри завершения откатывает всё; тот же код затем проходит.
func TestRecovery_F5_33_RefusalInsideCompletionRollsEverythingBack(t *testing.T) {
	h := newHarness(t, nil)
	a := h.withoutWayIn(t, "usr-r33", "r33@example.invalid", false)
	h.request(t, "r33@example.invalid")
	letter := h.letterOf(t, a.ID)

	for _, op := range []string{"put-verifier", "mark-verified", "close-path", "commit"} {
		h.store.failOn = op
		_, err := h.complete("r33@example.invalid", letter, "brand-new-password-33")
		require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "Ф5-33: отказ на %q — недоступность", op)
		require.Empty(t, h.store.rows, "сессии нет (%s)", op)
		_, has := h.store.verifiers[a.ID]
		require.False(t, has, "пароля нет (%s)", op)
		require.False(t, h.store.verified[a.ID], "адрес не подтверждён (%s)", op)
		require.True(t, h.store.openPath[a.ID], "отметка открытого пути на месте (%s)", op)
		require.Nil(t, h.store.codesOf(a.ID)[0].ConsumedAt, "код годен (%s)", op)
	}
	h.store.failOn = ""
	_, err := h.complete("r33@example.invalid", letter, "brand-new-password-33")
	require.NoError(t, err, "Ф5-33: тот же код без инъекции проходит с исходом Ф5-30")
}

// Ф5-34 — у личности без строки «пароль» завершение строку заводит; исход тот
// же, что у личности со строкой; у заблокированной — отказ Ф5-17, учётные
// данные заведены.
func TestRecovery_F5_34_IdentityWithoutAPasswordRowCompletesLikeOneWithIt(t *testing.T) {
	h := newHarness(t, nil)
	n := h.withoutWayIn(t, "usr-r34n", "r34n@example.invalid", true)
	w := h.person(t, "usr-r34w", "r34w@example.invalid", "old-password-34w", true)
	nb := h.person(t, "usr-r34b", "r34b@example.invalid", "", true)
	nb.InviteStatus = domain.InviteStatusBlocked
	h.store.users[nb.ID] = nb
	h.store.openPath[nb.ID] = true

	letters := map[domain.UserID]string{}
	for _, u := range []domain.User{n, w, nb} {
		h.request(t, string(u.Email))
		letters[u.ID] = h.letterOf(t, u.ID)
	}
	h.clock = ucBase.Add(time.Minute)

	// (а) и (б): тот же исход Ф5-03.
	for _, u := range []domain.User{n, w} {
		_, err := h.complete(string(u.Email), letters[u.ID], "brand-new-password-34")
		require.NoError(t, err, "Ф5-34: %s — сессия выдана, а не 503", u.ID)
	}
	// (в): отказ заблокированной, не 503.
	_, err := h.complete(string(nb.Email), letters[nb.ID], "brand-new-password-34")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "Ф5-34 (в): отказ Ф5-17")

	h.clock = h.clock.Add(time.Second)
	h.mustLogin(t, string(n.Email), "brand-new-password-34")
	h.mustLogin(t, string(w.Email), "brand-new-password-34")
	for _, u := range []domain.User{n, w, nb} {
		_, err := h.complete(string(u.Email), letters[u.ID], "another-password-34")
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "Ф5-34: повторное предъявление %s — отказ Ф5-05", u.ID)
	}
	// (г): строка «пароль» у N и NB — одна (дублёр держит одну на личность).
	for _, u := range []domain.User{n, nb} {
		_, has := h.store.verifiers[u.ID]
		require.True(t, has, "Ф5-34 (г): у %s заведён пароль", u.ID)
	}
	// (д): клетки.
	require.Equal(t, 2, h.obs.recoveryCompletion[humansession.RecoveryCompletionIssued])
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionBlocked])
	require.Zero(t, h.obs.recoveryCompletion[humansession.RecoveryCompletionStoreFailed], "Ф5-34 (д): store-failed не прибавилось")
}
