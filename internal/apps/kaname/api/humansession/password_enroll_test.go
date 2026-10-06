// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_enroll_test.go — сценарии уровня U приёмки A7
// (`first-password-from-a-live-session.md`, отпечаток 72825c63…; задача
// PRO-Robotech/kaname#213): FP-07 (в), FP-09, FP-10 — дублёр хранилища и
// подставные отказы, которых настоящее хранилище не производит по заказу.
package humansession_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// fpU — «Дано U»: личность без пароля и сессия ключа в h.clock.
func fpU(t *testing.T, breach humansession.BreachChecker) (*harness, *humansession.EnrollPasswordUseCase, domain.User, domain.SessionBearer) {
	t.Helper()
	h := newHarness(t, breach)
	u := h.person(t, "usr-fp", "fp-person@example.invalid", "", true)
	w, err := h.store.Writer(context.Background())
	require.NoError(t, err)
	_, bearer, err := humansession.IssueSession(context.Background(), w, humansession.IssueInput{
		User: u, Presented: []assurance.Presentation{assurance.KeyAssertion(true, false)}, At: h.clock, TTL: ucTTL,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(context.Background()))
	uc, err := humansession.NewEnrollPasswordUseCase(humansession.EnrollPasswordDeps{
		Store: h.store, Hasher: h.hasher, Rule: h.rule, Freshness: 15 * time.Minute,
		Observer: h.obs, Now: func() time.Time { return h.clock }, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	return h, uc, u, bearer
}

func fpEnrolledEvents(h *harness) int {
	n := 0
	for _, ev := range h.store.audit {
		if ev.EventType == humansession.AuditPasswordEnrolled {
			n++
		}
	}
	return n
}

// TestFP07c_BreachedPasswordIsJudgedByTheOneRule — FP-07 (в) и близнец.
func TestFP07c_BreachedPasswordIsJudgedByTheOneRule(t *testing.T) {
	h, uc, u, b := fpU(t, &fakeBreach{found: map[string]bool{"password123456": true}})
	_, err := uc.Execute(context.Background(), humansession.EnrollPasswordInput{Bearer: b, NewPassword: "password123456"})
	var fe *humansession.FieldError
	require.True(t, errors.As(err, &fe), "FP-07 (в): ошибка поля, а не %v", err)
	require.Equal(t, "newPassword", fe.Field)
	require.Equal(t, humansession.RuleBreached, fe.Rule)
	_, has := h.store.verifiers[u.ID]
	require.False(t, has, "строки нет")

	_, err = uc.Execute(context.Background(), humansession.EnrollPasswordInput{Bearer: b, NewPassword: "a clean passphrase"})
	require.NoError(t, err, "близнец: годный пароль заводится")
	_, has = h.store.verifiers[u.ID]
	require.True(t, has)
}

// TestFP09_AuditRefusalRollsTheRowBack — FP-09 и близнец.
func TestFP09_AuditRefusalRollsTheRowBack(t *testing.T) {
	h, uc, u, b := fpU(t, nil)
	h.store.failOn = "audit"
	_, err := uc.Execute(context.Background(), humansession.EnrollPasswordInput{Bearer: b, NewPassword: "a clean passphrase"})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "FP-09: отказ записи события — UNAVAILABLE")
	_, has := h.store.verifiers[u.ID]
	require.False(t, has, "FP-09: строки нет — исход откатан целиком")

	h.store.failOn = ""
	_, err = uc.Execute(context.Background(), humansession.EnrollPasswordInput{Bearer: b, NewPassword: "a clean passphrase"})
	require.NoError(t, err, "близнец без подставного отказа")
	_, has = h.store.verifiers[u.ID]
	require.True(t, has)
	require.Equal(t, 1, fpEnrolledEvents(h), "событие одно")
}

// TestFP10_ResolveRefusalIsUnavailable — FP-10.
func TestFP10_ResolveRefusalIsUnavailable(t *testing.T) {
	h, uc, u, b := fpU(t, nil)
	h.store.failOn = "resolve"
	_, err := uc.Execute(context.Background(), humansession.EnrollPasswordInput{Bearer: b, NewPassword: "a clean passphrase"})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "FP-10: UNAVAILABLE")
	_, has := h.store.verifiers[u.ID]
	require.False(t, has)
}
