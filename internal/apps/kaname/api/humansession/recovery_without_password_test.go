// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_without_password_test.go — Ф5-34: у личности без строки способа
// «пароль» завершение восстановления строку ЗАВОДИТ, и исход тот же, что у
// личности со строкой (задача PRO-Robotech/kacho#2698, исход 1; приёмка Ф5
// `docs/engineering/acceptance/recovery-of-access.md`, редакция с отпечатком
// be4dfb5a…, одобренная в PRO-Robotech/kaname#612 — Р5 «Личность без строки
// „пароль“», §18; ведомость §6 строка Ф5-34).
//
// «Дано» `N` и `NB` — личность без строк способов входа: в проде такое
// состояние не производится и строится посевом (§5.6 (8)); здесь —
// `h.person` с пустым паролем: строки способа «пароль» дублёр не кладёт.
// Близнец (б) `W` — та же личность со строкой (как Ф5-03); различие пары —
// ровно одно: была ли строка до завершения.
package humansession_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestRecovery_F5_34_CompletionCreatesTheMissingPasswordRow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string // "" — строки способа «пароль» нет
	}{{"(а) N — строки нет", ""}, {"(б) W — строка есть", "old-password-34"}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-r34", "r34@example.invalid", tc.password, true)
			h.request(t, "r34@example.invalid")
			letter := h.letterOf(t, u.ID)

			h.clock = ucBase.Add(time.Minute)
			out, err := h.complete("r34@example.invalid", letter, "brand-new-password-34")
			require.NoError(t, err, "Ф5-34 %s: исход Ф5-03 — выданная сессия, не UNAVAILABLE", tc.name)
			require.Equal(t, u.ID, out.View.User.ID)
			require.False(t, out.Bearer.IsZero(), "сессия выдана")
			require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionIssued])
			require.Zero(t, h.obs.recoveryCompletion[humansession.RecoveryCompletionStoreFailed], "клетки store-failed не прибавилось")

			// Вход — ПОЗЖЕ отсечки, поставленной завершением (граница включающая).
			h.clock = ucBase.Add(2 * time.Minute)
			h.mustLogin(t, "r34@example.invalid", "brand-new-password-34")
			_, err = h.complete("r34@example.invalid", letter, "another-new-password-34")
			require.ErrorIs(t, err, humansession.ErrAccessNotRestored, "повтор — отказ Ф5-05: код применён этим завершением")
		})
	}
}

func TestRecovery_F5_34_BlockedPersonWithoutARowGetsTheBlockedRefusal(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r34b", "r34b@example.invalid", "", true)
	u.InviteStatus = domain.InviteStatusBlocked
	h.store.users[u.ID] = u
	h.request(t, "r34b@example.invalid")
	letter := h.letterOf(t, u.ID)

	h.clock = ucBase.Add(time.Minute)
	_, err := h.complete("r34b@example.invalid", letter, "brand-new-password-34b")
	require.ErrorIs(t, err, humansession.ErrAccessNotRestored, "Ф5-34 (в): отказ Ф5-17, не UNAVAILABLE")
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionBlocked])
	require.Zero(t, h.obs.recoveryCompletion[humansession.RecoveryCompletionStoreFailed])
	_, err = h.complete("r34b@example.invalid", letter, "another-new-password-34b")
	require.ErrorIs(t, err, humansession.ErrAccessNotRestored, "повтор — отказ Ф5-05: учётные данные заведены, код применён")
	require.NotNil(t, h.store.codesOf(u.ID)[0].ConsumedAt, "код применён")
	_, has := h.store.verifiers[u.ID]
	require.True(t, has, "Ф5-34 (г): строка «пароль» у NB заведена")
}
