// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// call_ended_before_check_test.go — вызов, кончившийся раньше, чем проверке
// пароля досталось место вычисления, попыткой не считается (kaname#892).
//
// Проверяющий отдаёт такой вызов ошибкой контекста, а не исходом: проверка не
// состоялась. Полоса обязана прочесть это как исчерпание ёмкости (PWV-15.3) —
// без следа неверного предъявления, — а не как исход вне словаря, который
// ушёл бы в ветвь отказа и записал попытку. Конец вызова у проверяющего
// воспроизводится контекстом, отменённым до входа: ожидание места кончается
// сразу, и выбора между свободным местом и концом вызова он случаю не отдаёт.
// Близнец — тот же неверный пароль на живом вызове — попытку записывает.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
)

func TestLogin_CallEndedBeforeTheCheckIsNotAnAttempt(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ended, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.login.Execute(ended, humansession.LoginInput{Email: "a@example.invalid", Password: "wrong", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "наружу — тот же отказ")
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeCapacity], "несостоявшаяся проверка — в клетке ёмкости")
	require.Zero(t, h.obs.login[humansession.LoginOutcomeMismatched], "несостоявшаяся проверка сосчитана неверным паролем")
	n, _ := h.store.CountFailures(context.Background(), humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Zero(t, n, "вызов, кончившийся до проверки, записан попыткой")

	// Близнец: тот же неверный пароль на живом вызове — попытка.
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "wrong", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	n, _ = h.store.CountFailures(context.Background(), humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Equal(t, 1, n, "близнец: неверный пароль на живом вызове попыткой не записан")
}

func TestChangePassword_CallEndedBeforeTheCheckIsNotAnAttempt(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	s := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	ended, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.change.Execute(ended, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "wrong",
		NewPassword: "brand new passphrase", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "наружу — тот же отказ")
	n, _ := h.store.CountFailures(context.Background(), humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Zero(t, n, "вызов, кончившийся до проверки текущего пароля, записан попыткой")

	// Близнец: тот же неверный текущий пароль на живом вызове — попытка.
	_, err = h.change.Execute(context.Background(), humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "wrong",
		NewPassword: "brand new passphrase", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	n, _ = h.store.CountFailures(context.Background(), humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Equal(t, 1, n, "близнец: неверный текущий пароль на живом вызове попыткой не записан")
}
