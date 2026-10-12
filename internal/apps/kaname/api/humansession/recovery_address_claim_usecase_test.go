// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_address_claim_usecase_test.go — ПЕРЕХОД ЗАПИСИ К ВЛАДЕЛЬЦУ ЯЩИКА на
// слое варианта использования (задача kaname#458; приёмка
// `docs/engineering/acceptance/unverified-address-passes-to-the-mailbox-owner.md`,
// Р3, Р4, Р6, Р7). Дублёр хранилища — тот же, что у прочих проб Ф5;
// сценарии на настоящей базе и на проводе — `internal/handler/loginlanehttp/
// address_claim_integration_test.go`. Здесь — ветви исхода и их откат, которые
// дешевле судить без базы.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// seedSecondFactor — строка второго фактора и ключ доступа прежнего держателя.
func (h *harness) seedSecondFactor(t *testing.T, u domain.User) {
	t.Helper()
	material, err := domain.NewLoginVerifier("seeded-second-factor-a458")
	require.NoError(t, err)
	h.store.factors[u.ID] = map[domain.LoginMethodKind]*domain.LoginMethod{
		domain.LoginMethodTOTP: {UserID: u.ID, Kind: domain.LoginMethodTOTP, Verifier: material,
			State: domain.LoginMethodStateActive, CreatedAt: ucBase},
	}
	h.store.keys[u.ID] = true
}

// TestRecovery_A458_UnverifiedRecordWithAPasswordPassesToTheMailboxOwner — Р3:
// отметка, снятие второго фактора и ключей, причина `address-claimed` у
// снятых сессий и у отсечки, поле события, клетка `address-claimed`.
// Близнец (меняется один факт — адрес подтверждён): обычное восстановление.
func TestRecovery_A458_UnverifiedRecordWithAPasswordPassesToTheMailboxOwner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified bool
	}{{"переход: адрес не подтверждён", false}, {"близнец: адрес подтверждён", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-a458", "a458@example.invalid", "old-password-a458", tc.verified)
			h.seedSecondFactor(t, u)
			old := h.mustLogin(t, "a458@example.invalid", "old-password-a458")
			h.clock = ucBase.Add(time.Minute)
			h.request(t, "a458@example.invalid")
			letter := h.letterOf(t, u.ID)

			out, err := h.complete("a458@example.invalid", letter, "mailbox-owner-secret-pw")
			require.NoError(t, err)
			require.True(t, out.View.EmailVerified, "emailVerified: true")
			require.True(t, h.store.verified[u.ID], "отметка подтверждения стоит")

			ended := h.store.rows[old.View.Session.ID]
			require.NotNil(t, ended)
			reason, cell := domain.RevokeReasonPasswordChange, humansession.RecoveryCompletionIssued
			if !tc.verified {
				reason, cell = domain.RevokeReasonAddressClaimed, humansession.RecoveryCompletionAddressClaimed
			}
			require.Equal(t, reason, ended.reason, "причина снятия прежней сессии")
			require.Equal(t, reason, h.store.cutoffs[u.ID].reason, "причина отсечки")
			require.Equal(t, 1, h.obs.recoveryCompletion[cell], "клетка исхода")
			require.Equal(t, !tc.verified, len(h.store.factors[u.ID]) == 0, "второй фактор снят только переходом")
			require.Equal(t, tc.verified, h.store.keys[u.ID], "ключи доступа сняты только переходом")

			ev := h.store.audit[len(h.store.audit)-1]
			require.Equal(t, humansession.AuditRecoveryCompleted, ev.EventType)
			require.Equal(t, !tc.verified, ev.Payload["address_claimed"], "поле события address_claimed")
		})
	}
}

// TestRecovery_A458_InvalidInvitationRollsTheClaimBackAndKeepsTheCode — Р6: строка
// `PENDING` с паролем, приглашение негодно — отказ ErrInviteNotValid, исход
// откатан целиком: код годен, отметки нет, второй фактор на месте, прежняя
// сессия жива; клетка `invite-not-valid`. Отказ хранилища на том же операторе
// — тот же откат, но наружу «не выполнено», а не причина приглашения.
func TestRecovery_A458_InvalidInvitationRollsTheClaimBackAndKeepsTheCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(h *harness, u domain.User)
		want    error
		cell    humansession.RecoveryCompletionOutcome
	}{
		{"приглашение негодно", func(h *harness, u domain.User) { h.store.inviteGone = map[domain.UserID]bool{u.ID: true} },
			humansession.ErrInviteNotValid, humansession.RecoveryCompletionInviteNotValid},
		{"хранилище не ответило", func(h *harness, _ domain.User) { h.store.failOn = "activate-invite" },
			humansession.ErrStoreUnavailable, humansession.RecoveryCompletionStoreFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-a458p", "a458p@example.invalid", "old-password-a458p", false)
			h.seedSecondFactor(t, u)
			old := h.mustLogin(t, "a458p@example.invalid", "old-password-a458p")
			u.InviteStatus = domain.InviteStatusPending
			h.store.users[u.ID] = u
			h.clock = ucBase.Add(time.Minute)
			h.request(t, "a458p@example.invalid")
			letter := h.letterOf(t, u.ID)
			tc.arrange(h, u)

			_, err := h.complete("a458p@example.invalid", letter, "mailbox-owner-secret-pw")

			require.ErrorIs(t, err, tc.want)
			require.Equal(t, 1, h.obs.recoveryCompletion[tc.cell], "клетка исхода")
			require.False(t, h.store.verified[u.ID], "отметки нет")
			require.NotEmpty(t, h.store.factors[u.ID], "второй фактор на месте")
			require.Empty(t, h.store.rows[old.View.Session.ID].reason, "прежняя сессия жива")
			require.Equal(t, domain.InviteStatusPending, h.store.users[u.ID].InviteStatus, "строка PENDING")
			codes := h.store.codesOf(u.ID)
			require.Len(t, codes, 1)
			require.Nil(t, codes[0].ConsumedAt, "код годен")
		})
	}
}
