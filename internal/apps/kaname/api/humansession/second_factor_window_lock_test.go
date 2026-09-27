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
// Ни одна проба здесь не читает счётчика и не смотрит в хранилище. Наблюдаемое
// одно: СКОЛЬКО неверных предъявлений полоса приняла к сверке после успеха,
// стоявшего между сериями. Пока счёт не исчерпан, неверное предъявление
// получает отказ предъявления; исчерпанный счёт отвечает отказом по частоте ДО
// сверки, и эти два отказа различимы типом ошибки — как их различает край
// кодом ответа.
//
// Предъявляется то, что личности доступно по ОБЕ стороны успеха: у пар — код в
// церемонии (фактор заведён и до, и после); у глаголов под сессией — пароль на
// входе, потому что снятие фактора оставляет личности только пароль. Счёт у
// пароля и кода общий (Ф12 §7 инв. 3), поэтому обе формы меряют один счёт.
//
// # Пар ДВЕ — по числу полос, где успех первого фактора достижим
//
// Ветви пары отличаются РОВНО ОДНИМ фактом — каким фактором предъявлен успех
// между сериями; полоса, личность, сессия «Дано», длина серий, наблюдаемое и
// часы у обеих ветвей одни и те же:
//
//	пара «вход»      — вход (login.go) паролём БЕЗ поля `secondFactor` либо
//	                   паролём С верным кодом в этом поле;
//	пара «церемония» — церемония (step_up.go) ветвью `password` либо кодом.
//
// # Глаголы под сессией — положительная половина, пары у них нет
//
// Подтверждение заведения (sf_enroll.go), перечеканка запасных кодов
// (sf_backup_codes.go) и снятие фактора (sf_remove.go) принимают ТОЛЬКО код:
// успеха первого фактора на них не бывает, и отрицательной ветви строить не
// из чего. Каждый глагол закреплён наблюдаемым обнулением на успехе кода
// (`TestF12_46_CodeSuccessUnderSessionOpensTheWindow`).
//
// # Отрицательные контроли — названные приёмкой и измеренные инъекцией
//
//	обнуление на успехе ПЕРВОГО фактора (как до #287) — ветвь «пароль» пары
//	   принимает лишний код к сверке и краснеет;
//	НЕ обнуление на успехе кода — ветвь «код» каждой пары и каждый глагол под
//	   сессией запирают законного человека навсегда и краснеют;
//	полоса, передающая дому предъявленное БЕЗ кода, — краснеет ветвь «код» её
//	   пары либо её глагол. Исключение одно и законное: у подтверждения
//	   заведения снимок «заведено» взят до активации строки, требуемое там —
//	   «1», и решение от предъявленного кода не зависит (строка таблицы
//	   `completed_login_test.go`).
package humansession_test

import (
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

// windowLockPassword — пароль личности пробы; неверный пароль — любой иной.
const windowLockPassword = "correct horse battery staple"

// wrongCode — код заведомо чужой ступени: ±1 ступени укладываются в окно
// сверки, +5 — нет (тот же приём, что у Ф12-06).
func wrongCode(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	return probeTOTP(t, secret, step+5)
}

// ceremonyWithWrongCode — одно неверное предъявление кода в церемонии.
func ceremonyWithWrongCode(t *testing.T, h *sfHarness, bearer domain.SessionBearer, secret totpverify.Secret) error {
	t.Helper()
	_, err := h.stepUp.Execute(t.Context(), humansession.StepUpInput{
		Bearer: bearer, Method: assurance.MethodTOTP, Code: wrongCode(t, secret, h.step()), Source: windowLockSource,
	})
	return err
}

// loginWithWrongPassword — одно неверное предъявление пароля на входе.
func loginWithWrongPassword(t *testing.T, h *sfHarness, email string) error {
	t.Helper()
	_, err := h.login.Execute(t.Context(), humansession.LoginInput{
		Email: email, Password: "not the password of this person", Source: windowLockSource,
	})
	return err
}

// isRateRefusal — отказ ПО ЧАСТОТЕ: предъявление к сверке не принято.
func isRateRefusal(err error) bool {
	var tooMany *humansession.TooManyAttemptsError
	return errors.As(err, &tooMany)
}

// acceptedForVerification — НАБЛЮДАЕМОЕ: сколько неверных предъявлений полоса
// приняла к сверке, прежде чем ответить отказом по частоте. Считает не больше
// limit, чтобы проба не висела на исправной реализации.
func acceptedForVerification(t *testing.T, limit int, present func() error) int {
	t.Helper()
	for accepted := 0; accepted <= limit; accepted++ {
		err := present()
		if isRateRefusal(err) {
			return accepted
		}
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed,
			"неверное предъявление принимается к сверке и отвергается предъявлением, иным отказом — нет")
	}
	t.Fatalf("полоса приняла к сверке больше %d предъявлений — предел по адресу не наступил вовсе", limit)
	return 0
}

// TestF12_46_OnlyCodeSuccessOpensTheWindow — Ф12-46: пара на КАЖДОЙ полосе, где
// успех первого фактора достижим. Ветви пары отличаются ровно одним фактом —
// каким фактором предъявлен успех между сериями.
func TestF12_46_OnlyCodeSuccessOpensTheWindow(t *testing.T) {
	// between — успех между сериями; возвращает носитель для второй серии.
	type between func(t *testing.T, h *sfHarness, login humansession.LoginOutput, email string, secret totpverify.Secret) domain.SessionBearer

	viaLogin := func(t *testing.T, h *sfHarness, _ humansession.LoginOutput, email string, _ totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out := h.mustLogin(t, email, windowLockPassword)
		require.Equal(t, "1", out.View.Session.AssuranceLevel,
			"успех первого фактора: сессия «1» — успех, но НЕ завершённый вход (Ф12-14)")
		return out.Bearer
	}
	viaLoginWithCode := func(t *testing.T, h *sfHarness, _ humansession.LoginOutput, email string, secret totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out, err := h.login.Execute(t.Context(), humansession.LoginInput{
			Email: email, Password: windowLockPassword, Source: windowLockSource,
			SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step())},
		})
		require.NoError(t, err, "вход паролём и верным кодом ниже предела — законный успех (Ф12-11)")
		require.Equal(t, "2", out.View.Session.AssuranceLevel,
			"код на входе довёл вход до уровня всех заведённых факторов: вход ЗАВЕРШЁН")
		return out.Bearer
	}
	viaCeremonyPassword := func(t *testing.T, h *sfHarness, login humansession.LoginOutput, _ string, _ totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out, err := h.stepUp.Execute(t.Context(), humansession.StepUpInput{
			Bearer: login.Bearer, Method: assurance.MethodPassword, Password: windowLockPassword, Source: windowLockSource,
		})
		require.NoError(t, err, "церемония паролем — законный успех")
		require.Equal(t, "1", out.View.Session.AssuranceLevel,
			"церемония паролем у личности С фактором оставляет «1»: вход не завершён")
		return out.Bearer
	}
	viaCeremonyCode := func(t *testing.T, h *sfHarness, login humansession.LoginOutput, _ string, secret totpverify.Secret) domain.SessionBearer {
		t.Helper()
		out, err := h.stepUp.Execute(t.Context(), humansession.StepUpInput{
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
		{"пара «вход»: между сериями вход ПАРОЛЁМ И КОДОМ", viaLoginWithCode, true},
		{"пара «церемония»: между сериями церемония ПАРОЛЕМ", viaCeremonyPassword, false},
		{"пара «церемония»: между сериями церемония КОДОМ", viaCeremonyCode, true},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSFHarness(t)
			email := "kn287-" + string(rune('a'+i)) + "@example.invalid"
			_, secret, _ := h.enrolled(t, "usr-287-"+string(rune('a'+i)), email, windowLockPassword)
			n := sfLimits().AddressAttempts
			require.GreaterOrEqual(t, n, 2, "Дано: предел по адресу N ≥ 2, иначе серия не строится")

			// Дано, ОДНО И ТО ЖЕ у всех ветвей: сессия «1» — вход паролём при
			// заведённом факторе (Ф12-14). Именно из неё успех первого фактора
			// достижим; сессия «2» вопроса не ставит, она уже завершена.
			login := h.mustLogin(t, email, windowLockPassword)
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
			accepted := acceptedForVerification(t, n+1, func() error {
				return ceremonyWithWrongCode(t, h, bearer, secret)
			})
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

// TestF12_46_CodeSuccessUnderSessionOpensTheWindow — глаголы под сессией,
// идущие через дом единственного писателя: успех КОДА каждым из них обнуляет
// счёт по адресу НАБЛЮДАЕМО. Отличается от глагола к глаголу только сам
// глагол; личность, сессия «1», серии и наблюдаемое — одни и те же.
func TestF12_46_CodeSuccessUnderSessionOpensTheWindow(t *testing.T) {
	// verbState — то, чем глагол зовётся: сессия «1» и секрет, от которого
	// проба считает верный код.
	type verbState struct {
		bearer domain.SessionBearer
		secret totpverify.Secret
	}
	// withFactor — Дано перечеканки и снятия: фактор заведён, сессия «1».
	withFactor := func(t *testing.T, h *sfHarness, id, email string) verbState {
		t.Helper()
		_, secret, _ := h.enrolled(t, id, email, windowLockPassword)
		login := h.mustLogin(t, email, windowLockPassword)
		require.Equal(t, "1", login.View.Session.AssuranceLevel, "Дано: сессия «1» при заведённом факторе")
		return verbState{bearer: login.Bearer, secret: secret}
	}
	// pendingFactor — Дано подтверждения: заведение начато, фактора ещё нет.
	pendingFactor := func(t *testing.T, h *sfHarness, id, email string) verbState {
		t.Helper()
		h.person(t, id, email, windowLockPassword, true)
		login := h.freshSession(t, email, windowLockPassword)
		en, err := h.enroll.Execute(t.Context(), humansession.EnrollInput{Bearer: login.Bearer})
		require.NoError(t, err, "Дано: заведение начато")
		return verbState{bearer: login.Bearer, secret: en.Secret}
	}

	cases := []struct {
		name  string
		given func(t *testing.T, h *sfHarness, id, email string) verbState
		// succeed — успех глагола верным КОДОМ; возвращает уровень сессии.
		succeed func(t *testing.T, h *sfHarness, st verbState) string
	}{
		{"подтверждение заведения (sf_enroll.go)", pendingFactor, func(t *testing.T, h *sfHarness, st verbState) string {
			t.Helper()
			out, err := h.confirm.Execute(t.Context(), humansession.ConfirmInput{
				Bearer: st.bearer, Code: probeTOTP(t, st.secret, h.step()), Source: windowLockSource,
			})
			require.NoError(t, err, "верный первый код ниже предела подтверждает заведение")
			return out.View.Session.AssuranceLevel
		}},
		{"перечеканка запасных кодов (sf_backup_codes.go)", withFactor, func(t *testing.T, h *sfHarness, st verbState) string {
			t.Helper()
			out, err := h.regenerate.Execute(t.Context(), humansession.RegenerateBackupCodesInput{
				Bearer: st.bearer, Source: windowLockSource,
				Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, st.secret, h.step())},
			})
			require.NoError(t, err, "верный код ниже предела подтверждает перечеканку")
			return out.View.Session.AssuranceLevel
		}},
		{"снятие фактора (sf_remove.go)", withFactor, func(t *testing.T, h *sfHarness, st verbState) string {
			t.Helper()
			out, err := h.remove.Execute(t.Context(), humansession.RemoveSecondFactorInput{
				Bearer: st.bearer, Source: windowLockSource,
				Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, st.secret, h.step())},
			})
			require.NoError(t, err, "верный код ниже предела подтверждает снятие")
			return out.View.Session.AssuranceLevel
		}},
	}
	if len(cases) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: глаголов в таблице 0")
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSFHarness(t)
			email := "kn287-verb-" + string(rune('a'+i)) + "@example.invalid"
			st := tc.given(t, h, "usr-287-verb-"+string(rune('a'+i)), email)
			n := sfLimits().AddressAttempts
			require.GreaterOrEqual(t, n, 2, "Дано: предел по адресу N ≥ 2, иначе серия не строится")

			// Первая серия, ОДНА И ТА ЖЕ у всех глаголов: N−1 неверных паролей.
			for k := 1; k < n; k++ {
				err := loginWithWrongPassword(t, h, email)
				require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "неверный пароль %d из %d", k, n-1)
				require.False(t, isRateRefusal(err), "первая серия ещё не достигла предела")
			}

			// Глагол — и ничего, кроме него.
			level := tc.succeed(t, h, st)
			require.Equal(t, "2", level, "код довёл сессию до «2»: вход завершён до уровня заведённого")

			// Наблюдаемое: сколько неверных паролей принято к сверке ПОСЛЕ глагола.
			accepted := acceptedForVerification(t, n+1, func() error {
				return loginWithWrongPassword(t, h, email)
			})
			require.Equal(t, n, accepted,
				"успех КОДА глаголом под сессией обнуляет счёт: вторая серия считается заново, "+
					"иначе законный человек заперт навсегда (Ф12-46, второй отрицательный контроль)")
			t.Logf("наблюдаемое: после глагола принято к сверке %d неверных паролей при пределе N = %d", accepted, n)
		})
	}
}
