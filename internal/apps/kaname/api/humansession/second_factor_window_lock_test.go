// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_window_lock_test.go — ЗАМОК Ф12-46: счёт неверных предъявлений
// по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых у личности
// факторов, а не успех одного первого фактора (приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`
// редакция 11, Р7 и сценарий Ф12-46; `login-lane-issues-our-session-and-logout-
// ends-it-server-side.md` Р10 редакция 11; задача PRO-Robotech/kaname#287).
//
// # Судится НАБЛЮДАЕМОЕ, а не внутренности
//
// Ни одна проба здесь не читает счётчика и не смотрит в сессию. Наблюдаемое
// одно: СКОЛЬКО кодов полоса приняла к сверке после успеха, стоявшего между
// сериями. Пока счёт не исчерпан, неверный код получает отказ предъявления;
// исчерпанный счёт отвечает отказом по частоте ДО сверки, и эти два отказа
// различимы типом ошибки — как их различает край кодом ответа.
//
// # Пар ДВЕ, по числу мест, где успех первого фактора достижим
//
// Каждая пара отличается РОВНО ОДНИМ фактом — каким фактором предъявлен успех
// между сериями:
//
//	пара «вход»     — между сериями вход паролём (login.go) либо код в церемонии;
//	пара «церемония» — между сериями церемония паролем (step_up.go, ветвь
//	                   `password`) либо церемония кодом; полоса, сессия, длина
//	                   серий и часы у обеих ветвей ОДНИ И ТЕ ЖЕ.
//
// Вторая пара несущая: первая покрывает только `login.go`. Возврат дефекта в
// `step_up.go` оставлял весь пакет зелёным — измерено инъекцией, — и второе
// место было покрыто лишь утверждением о дереве, но не о поведении.
//
// # Отрицательные контроли, названные приёмкой
//
//	реализация, обнуляющая счёт на успехе ПЕРВОГО фактора (как до #287),
//	   принимает лишний код к сверке — ветвь «пароль» краснеет;
//	реализация, НЕ обнуляющая счёт и на успехе кода, запирает законного
//	   человека навсегда — ветвь «код» краснеет.
package humansession_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// windowLockSource — источник пробы. Предел по источнику харнесса (60) заведомо
// выше числа предъявлений сценария, поэтому ось источника здесь не срабатывает
// и наблюдаемое принадлежит оси АДРЕСА.
const windowLockSource = "203.0.113.7"

// wrongCode — код заведомо чужой ступени: ±1 ступени укладываются в окно
// сверки, +5 — нет (тот же приём, что у Ф12-06).
func wrongCode(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	return probeTOTP(t, secret, step+5)
}

// ceremonyWithWrongCode — одно неверное предъявление кода в церемонии.
func ceremonyWithWrongCode(t *testing.T, h *sfHarness, bearer domain.SessionBearer, secret totpverify.Secret) error {
	t.Helper()
	_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{
		Bearer: bearer, Method: assurance.MethodTOTP, Code: wrongCode(t, secret, h.step()), Source: windowLockSource,
	})
	return err
}

// isRateRefusal — отказ ПО ЧАСТОТЕ: код к сверке не принят.
func isRateRefusal(err error) bool {
	var tooMany *humansession.TooManyAttemptsError
	return errors.As(err, &tooMany)
}

// codesAcceptedForVerification — НАБЛЮДАЕМОЕ: сколько неверных кодов полоса
// приняла к сверке, прежде чем ответить отказом по частоте. Считает не больше
// limit, чтобы проба не висела на исправной реализации.
func codesAcceptedForVerification(t *testing.T, h *sfHarness, bearer domain.SessionBearer, secret totpverify.Secret, limit int) int {
	t.Helper()
	for accepted := 0; accepted <= limit; accepted++ {
		err := ceremonyWithWrongCode(t, h, bearer, secret)
		if isRateRefusal(err) {
			return accepted
		}
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed,
			"неверный код принимается к сверке и отвергается предъявлением, иным отказом — нет")
	}
	t.Fatalf("полоса приняла к сверке больше %d кодов — предел по адресу не наступил вовсе", limit)
	return 0
}

// TestF12_46_OnlyCodeSuccessOpensTheWindow — Ф12-46: пара на КАЖДОМ месте, где
// успех первого фактора достижим. Ветви пары отличаются ровно одним фактом —
// каким фактором предъявлен успех между сериями.
func TestF12_46_OnlyCodeSuccessOpensTheWindow(t *testing.T) {
	const password = "correct horse battery staple"

	// succeedBetween — успех между сериями; возвращает носитель для второй серии.
	type between func(t *testing.T, h *sfHarness, login humansession.LoginOutput, email string, secret totpverify.Secret) domain.SessionBearer

	viaLogin := func(t *testing.T, h *sfHarness, login humansession.LoginOutput, email string, _ totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out := h.mustLogin(t, email, password)
		require.Equal(t, "1", out.View.Session.AssuranceLevel,
			"успех первого фактора: сессия «1» — успех, но НЕ завершённый вход (Ф12-14)")
		return out.Bearer
	}
	viaCeremonyPassword := func(t *testing.T, h *sfHarness, login humansession.LoginOutput, _ string, _ totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{
			Bearer: login.Bearer, Method: assurance.MethodPassword, Password: password, Source: windowLockSource,
		})
		require.NoError(t, err, "церемония паролем — законный успех")
		require.Equal(t, "1", out.View.Session.AssuranceLevel,
			"церемония паролем у личности С фактором оставляет «1»: вход не завершён")
		return out.Bearer
	}
	viaCeremonyCode := func(t *testing.T, h *sfHarness, login humansession.LoginOutput, _ string, secret totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{
			Bearer: login.Bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step()), Source: windowLockSource,
		})
		require.NoError(t, err, "верный код ниже предела проходит — положительный контроль")
		require.Equal(t, "2", out.View.Session.AssuranceLevel,
			"код довёл вход до уровня всех заведённых факторов: вход ЗАВЕРШЁН")
		return out.Bearer
	}

	cases := []struct {
		name string
		// succeeded — ЕДИНСТВЕННЫЙ факт, которым ветви пары различаются.
		succeeded between
		// opensWindow — обнуляет ли этот успех счёт.
		opensWindow bool
	}{
		{"пара «вход»: между сериями вход ПАРОЛЁМ", viaLogin, false},
		{"пара «церемония»: между сериями церемония ПАРОЛЕМ", viaCeremonyPassword, false},
		{"пара «церемония»: между сериями церемония КОДОМ", viaCeremonyCode, true},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSFHarness(t)
			email := "kn287-" + string(rune('a'+i)) + "@example.invalid"
			_, secret, _ := h.enrolled(t, "usr-287-"+string(rune('a'+i)), email, password)
			n := sfLimits().AddressAttempts
			require.GreaterOrEqual(t, n, 2, "Дано: предел по адресу N ≥ 2, иначе серия не строится")

			// Дано, ОДНО И ТО ЖЕ у всех ветвей: сессия «1» — вход паролём при
			// заведённом факторе (Ф12-14). Именно из неё успех первого фактора
			// достижим; сессия «2» вопроса не ставит, она уже завершена.
			login := h.mustLogin(t, email, password)
			require.Equal(t, "1", login.View.Session.AssuranceLevel, "Дано: сессия «1»")

			// Первая серия, ОДНА И ТА ЖЕ у всех ветвей: N−1 неверных кодов.
			for k := 1; k < n; k++ {
				err := ceremonyWithWrongCode(t, h, login.Bearer, secret)
				require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "неверный код %d из %d", k, n-1)
				require.False(t, isRateRefusal(err), "первая серия ещё не достигла предела")
			}

			// РАЗЛИЧАЮЩИЙ ФАКТ — и ничего, кроме него.
			bearer := tc.succeeded(t, h, login, email, secret)

			// Наблюдаемое: сколько кодов принято к сверке ПОСЛЕ успеха.
			accepted := codesAcceptedForVerification(t, h, bearer, secret, n+1)
			if tc.opensWindow {
				require.Equal(t, n, accepted,
					"успех КОДА обнуляет счёт: вторая серия считается заново, иначе законный человек заперт навсегда")
			} else {
				require.Equal(t, 1, accepted,
					"успех ПЕРВОГО фактора счёт не обнуляет: после него полоса принимает к сверке ровно один "+
						"оставшийся код, а не свежее окно подбора (kaname#287)")
			}
			t.Logf("наблюдаемое: после успеха принято к сверке %d кодов при пределе N = %d", accepted, n)
		})
	}
}
