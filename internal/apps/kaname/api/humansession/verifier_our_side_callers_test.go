// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// verifier_our_side_callers_test.go — негодное хранимое значение пароля растит
// клетку «наша сторона» ряда проверяющего через КАЖДОГО вызывающего полосы:
// вход, повышение уровня паролем, смену пароля (kaname#692).
//
// Правило отказов нашей стороны читает ряд проверяющего, а не исходы каждого
// глагола (deploy/password_verifier_side_ledger_test.go). Это правило звонит
// на повышение уровня и смену пароля ровно постольку, поскольку их сверка идёт
// через тот же наблюдаемый проверяющий; здесь это и держится — исходом, а не
// чтением провязки. Законный близнец — неверный пароль при читаемом значении:
// клетка «наша сторона» не растёт, растёт `mismatched`. Сверку секрета клиента
// тем же проверяющим держит соседняя проба порта церемонии
// (internal/ceremonyport/client_secrets_our_side_test.go).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// unreadableStored — хранимое значение формата вне перечня: исход проверяющего
// `format-not-in-registry`, наша сторона.
func unreadableStored(t *testing.T) domain.LoginVerifier {
	t.Helper()
	v, err := domain.NewLoginVerifier("$unknown-format$v=1$c29tZQ$Ym9keQ")
	require.NoError(t, err)
	return v
}

func TestVerifierOurSideOutcomeIsCountedThroughEveryLaneCaller(t *testing.T) {
	ctx := context.Background()
	const pw = "correct horse battery"
	ours := passwordverify.OutcomeFormatNotInRegistry
	require.True(t, ours.IsOurError(), "предпосылка: исход пробы — наша сторона")

	callers := map[string]func(t *testing.T, h *sfHarness, u domain.User, login humansession.LoginOutput) error{
		"вход": func(t *testing.T, h *sfHarness, u domain.User, _ humansession.LoginOutput) error {
			_, err := h.login.Execute(ctx, humansession.LoginInput{Email: string(u.Email), Password: pw, Source: "203.0.113.7"})
			return err
		},
		"повышение уровня паролем": func(t *testing.T, h *sfHarness, _ domain.User, login humansession.LoginOutput) error {
			_, err := h.stepUp.Execute(ctx, humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodPassword,
				Password: pw, Source: "203.0.113.7"})
			return err
		},
		"смена пароля": func(t *testing.T, h *sfHarness, _ domain.User, login humansession.LoginOutput) error {
			_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: login.Bearer,
				CurrentPassword: pw, NewPassword: "brand new passphrase", Source: "203.0.113.7"})
			return err
		},
	}
	judged := 0
	for name, call := range callers {
		t.Run(name, func(t *testing.T) {
			h := newSFHarness(t)
			u := h.person(t, "usr-vo", "vo@example.invalid", pw, true)
			login := h.freshSession(t, "vo@example.invalid", pw)

			// Законный близнец: значение читается, пароль неверный — сторона
			// вызывающего.
			h.store.verifiers[u.ID] = mustHash(t, h, "a different passphrase")
			before := h.verifyObs.count(ours)
			require.Error(t, call(t, h, u, login))
			require.Equal(t, before, h.verifyObs.count(ours), "неверный пароль — не наша сторона")
			require.NotZero(t, h.verifyObs.count(passwordverify.OutcomeMismatched), "близнец до сверки не дошёл")

			// Значение не читается: наша сторона, +1 ряду проверяющего.
			h.store.verifiers[u.ID] = unreadableStored(t)
			require.Error(t, call(t, h, u, login))
			require.Equal(t, before+1, h.verifyObs.count(ours),
				"вызывающий %q сверил негодное значение мимо наблюдаемого проверяющего — правило отказов о нём молчит", name)
			judged++
		})
	}
	t.Logf("ПЕРЕПИСЬ: вызывающих полосы %d · судимо %d", len(callers), judged)
	require.Equal(t, len(callers), judged)
}

func mustHash(t *testing.T, h *sfHarness, password string) domain.LoginVerifier {
	t.Helper()
	v, err := h.hasher.Hash(password)
	require.NoError(t, err)
	return v
}
