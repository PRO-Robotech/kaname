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

// seedFactorRow — строка генератора в состоянии state (заведён либо начат).
func (h *harness) seedFactorRow(t *testing.T, u domain.User, state domain.LoginMethodState) {
	t.Helper()
	material, err := domain.NewLoginVerifier("seeded-second-factor-a458")
	require.NoError(t, err)
	h.store.factors[u.ID] = map[domain.LoginMethodKind]*domain.LoginMethod{
		domain.LoginMethodTOTP: {UserID: u.ID, Kind: domain.LoginMethodTOTP, Verifier: material,
			State: state, CreatedAt: ucBase},
	}
}

// seedSecondFactor — заведённый второй фактор и ключ доступа на записи.
func (h *harness) seedSecondFactor(t *testing.T, u domain.User) {
	t.Helper()
	h.seedFactorRow(t, u, domain.LoginMethodStateActive)
	h.store.keys[u.ID] = true
}

// TestRecovery_A458_BranchIsDecidedByTheCredentialsOfTheRecord — Р3 п. 2, Р4:
// у неподтверждённой записи с паролем ветвь решает один факт — есть ли на ней
// удостоверения (заведённый второй фактор, ключ доступа, личный токен); у
// перехода снимается только начатое заведение. Близнец — подтверждённая запись.
func TestRecovery_A458_BranchIsDecidedByTheCredentialsOfTheRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified bool
		seed     func(h *harness, u domain.User)
		reason   string
		cell     humansession.RecoveryCompletionOutcome
		claimed  bool
		// factorLeft — строка генератора после исхода; keyLeft — ключ доступа.
		factorLeft, keyLeft bool
	}{
		{name: "переход: удостоверений нет, заведение начато", seed: func(h *harness, u domain.User) {
			h.seedFactorRow(t, u, domain.LoginMethodStatePending)
		}, reason: domain.RevokeReasonAddressClaimed, cell: humansession.RecoveryCompletionAddressClaimed, claimed: true},
		{name: "второй фактор заведён", seed: func(h *harness, u domain.User) {
			h.seedFactorRow(t, u, domain.LoginMethodStateActive)
		}, reason: domain.RevokeReasonPasswordChange, cell: humansession.RecoveryCompletionAddressVerified, factorLeft: true},
		{name: "ключ доступа", seed: func(h *harness, u domain.User) { h.store.keys[u.ID] = true },
			reason: domain.RevokeReasonPasswordChange, cell: humansession.RecoveryCompletionAddressVerified, keyLeft: true},
		{name: "личный токен", seed: func(h *harness, u domain.User) { h.store.userTokens[u.ID] = true },
			reason: domain.RevokeReasonPasswordChange, cell: humansession.RecoveryCompletionAddressVerified},
		{name: "близнец: адрес подтверждён", verified: true, seed: func(h *harness, u domain.User) { h.seedSecondFactor(t, u) },
			reason: domain.RevokeReasonPasswordChange, cell: humansession.RecoveryCompletionIssued, factorLeft: true, keyLeft: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-a458", "a458@example.invalid", "old-password-a458", tc.verified)
			tc.seed(h, u)
			old := h.mustLogin(t, "a458@example.invalid", "old-password-a458")
			h.clock = ucBase.Add(time.Minute)
			h.request(t, "a458@example.invalid")
			letter := h.letterOf(t, u.ID)

			out, err := h.complete("a458@example.invalid", letter, "mailbox-owner-secret-pw")
			require.NoError(t, err)
			require.True(t, out.View.EmailVerified, "emailVerified: true")
			require.Equal(t, "1", out.View.Session.AssuranceLevel, "сессия уровня «1»")
			require.True(t, h.store.verified[u.ID], "отметка подтверждения стоит в обеих ветвях")

			ended := h.store.rows[old.View.Session.ID]
			require.NotNil(t, ended)
			require.Equal(t, tc.reason, ended.reason, "причина снятия прежней сессии")
			require.Equal(t, tc.reason, h.store.cutoffs[u.ID].reason, "причина отсечки")
			require.Equal(t, 1, h.obs.recoveryCompletion[tc.cell], "клетка исхода")
			_, factor := h.store.factors[u.ID][domain.LoginMethodTOTP]
			require.Equal(t, tc.factorLeft, factor, "строка генератора после исхода")
			require.Equal(t, tc.keyLeft, h.store.keys[u.ID], "ключ доступа после исхода")

			ev := h.store.audit[len(h.store.audit)-1]
			require.Equal(t, humansession.AuditRecoveryCompleted, ev.EventType)
			require.Equal(t, tc.claimed, ev.Payload["address_claimed"], "поле события address_claimed")
		})
	}
}

// TestRecovery_A458_UnreadableTokenRowRollsTheOutcomeBack — чтение наличия
// личного токена не ответило: исход откатан целиком (Ф5-33) — код годен,
// отметки нет, прежняя сессия жива; наружу «не выполнено».
func TestRecovery_A458_UnreadableTokenRowRollsTheOutcomeBack(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a458t", "a458t@example.invalid", "old-password-a458t", false)
	old := h.mustLogin(t, "a458t@example.invalid", "old-password-a458t")
	h.clock = ucBase.Add(time.Minute)
	h.request(t, "a458t@example.invalid")
	letter := h.letterOf(t, u.ID)
	h.store.failOn = "user-token-held"

	_, err := h.complete("a458t@example.invalid", letter, "mailbox-owner-secret-pw")

	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionStoreFailed], "клетка store-failed")
	require.False(t, h.store.verified[u.ID], "отметки нет")
	require.Empty(t, h.store.rows[old.View.Session.ID].reason, "прежняя сессия жива")
	codes := h.store.codesOf(u.ID)
	require.Len(t, codes, 1)
	require.Nil(t, codes[0].ConsumedAt, "код годен")
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
