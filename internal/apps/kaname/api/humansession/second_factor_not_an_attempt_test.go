// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// second_factor_not_an_attempt_test.go — Ф12-32 уровня I: три исхода, которые
// попыткой НЕ считаются, в форме позиции (kaname#480 п.3; приёмка
// `second-factor-totp-and-recovery-codes.md`, Ф12-32, Ф12-43).
//
// Форма одна на три пробы: `N − 1` неверных кодов, затем исход, затем верный код
// проходит без отказа по частоте, и клетка счётчика исхода выросла ровно на
// единицу. Засчитай полоса исход попыткой, счёт по адресу дошёл бы до `N`, и
// верный код получил бы отказ по частоте (`TooManyAttemptsError`, на проводе —
// `RESOURCE_EXHAUSTED` / 429, Ф12-31 «а»): это и есть отказ, которым пробы
// краснеют, — близнец поэтому судится РАНЬШЕ счёта и клеток (`naSnapshot`). Что
// верный код ПОСЛЕ счёта `N` действительно получает отказ на каждом
// предъявлении близнеца (глагол × способ), держит проба предпосылки
// `TestF12_32_ProbeFormPremise_ACountedPresentationInPlaceOfTheOutcomeRefusesTheTwin`:
// без неё зелёный пробы исхода был бы неотличим от глагола, который счёт не читает.
//
// Исходы и глаголы — перечнем по дереву, а не по памяти:
//
//   - свежесть (Ф12-09 форма, `requireFresh`) — два глагола, которые её судят:
//     `enroll` и `confirm`; у `confirm` свежесть судится раньше частоты и
//     состояния строки;
//   - материал не открывается (Ф12-35 «в») — код по времени у четырёх глаголов
//     общей сверки (`presenter`: церемония, вход, снятие, перечеканка) и у
//     `confirm`, который открывает строку `pending` сам; набора запасных кодов
//     исход не касается — у набора нет ключа (Р6);
//   - ёмкость проверяющего исчерпана на ЗАПАСНОМ коде (ID-PW-1 PWV-15, Р6) —
//     три глагола под сессией (церемония, снятие, перечеканка). Вход в перечне
//     нет: сверка пароля занимает ту же ёмкость раньше кода, и при занятой
//     ёмкости вход отвечает исходом пароля (Ф3-30,
//     `TestLogin_F3_30_WhatIsNotAnAttempt`), до кода не доходя. Код по времени
//     ёмкости не занимает (Р6) — это утверждает отдельная ветвь.
//
// Близнец ветвей материала и ёмкости — ТО ЖЕ предъявление тем же глаголом без
// причины исхода: материал возвращён в строку, ёмкость освобождена; различие
// между исходом и близнецом одно — причина. У свежести близнец — верный код
// церемонией в той же несвежей сессии: `enroll` кода не несёт, а церемония окна
// свежести не требует — она его и освежает (Ф12-10).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// naSource — источник всех предъявлений проб: счёт по источнику судится вместе
// со счётом по адресу.
const naSource = "203.0.113.7"

// naPassword — пароль личностей проб.
const naPassword = "correct horse battery"

// naPerson — личность пробы и то, чем она предъявляет.
type naPerson struct {
	id     domain.UserID
	email  string
	bearer domain.SessionBearer
	secret totpverify.Secret
	codes  []string
}

// withFactor — личность с заведённым фактором и сессией «1» входом паролем:
// сессия, в которой код ещё не предъявлялся.
func (h *sfHarness) withFactor(t *testing.T, id, email string) *naPerson {
	t.Helper()
	enrolled, secret, codes := h.enrolled(t, id, email, naPassword)
	login := h.mustLogin(t, email, naPassword)
	require.Equal(t, "1", login.View.Session.AssuranceLevel, "предпосылка: сессия входа паролем — «1»")
	return &naPerson{id: enrolled.View.User.ID, email: email, bearer: login.Bearer, secret: secret, codes: codes}
}

// withPending — личность со строкой `pending` в свежей сессии: секрет у пробы,
// код от него `confirm` примет.
func (h *sfHarness) withPending(t *testing.T, id, email string) *naPerson {
	t.Helper()
	u := h.person(t, id, email, naPassword, true)
	login := h.freshSession(t, email, naPassword)
	en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.NoError(t, err)
	return &naPerson{id: u.ID, email: email, bearer: login.Bearer, secret: en.Secret}
}

// wrongCode — код, которого нет в окне ±Skew вокруг текущей ступени: неверный
// по построению, а не по вероятности.
func (h *sfHarness) wrongCode(t *testing.T, secret totpverify.Secret) string {
	t.Helper()
	window := map[string]bool{}
	for d := -int64(totpverify.Skew); d <= int64(totpverify.Skew); d++ {
		window[probeTOTP(t, secret, h.step()+d)] = true
	}
	for far := int64(9); far < 64; far++ {
		if c := probeTOTP(t, secret, h.step()+far); !window[c] {
			return c
		}
	}
	t.Fatal("предпосылка: не нашлось кода вне окна ступеней")
	return ""
}

// wrongCodesInSession — n неверных кодов церемонией: каждый — 401 и попытка.
func (h *sfHarness) wrongCodesInSession(t *testing.T, p *naPerson, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{
			Bearer: p.bearer, Method: assurance.MethodTOTP, Code: h.wrongCode(t, p.secret), Source: naSource,
		})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "неверный код №%d — 401", i+1)
	}
	require.Equal(t, n, h.failures(humansession.FailureByAddress, p.email), "предпосылка: сосчитано %d неверных", n)
}

// wrongCodesOnConfirm — n неверных кодов подтверждением: каждый — 401 и попытка.
func (h *sfHarness) wrongCodesOnConfirm(t *testing.T, p *naPerson, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
			Bearer: p.bearer, Code: h.wrongCode(t, p.secret), Source: naSource,
		})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "неверный код №%d — 401", i+1)
	}
	require.Equal(t, n, h.failures(humansession.FailureByAddress, p.email), "предпосылка: сосчитано %d неверных", n)
}

// naCounts — счёт по обеим осям в момент снимка.
type naCounts struct{ byAddress, bySource int }

// naCells — клетки Ф12-43, которые пробы сравнивают до и после исхода.
type naCells struct {
	present  map[string]int
	refusals map[humansession.SecondFactorRefusal]int
}

// naSnapshot — счёт и клетки в один момент. Проба снимает его ДО исхода и
// СРАЗУ ПОСЛЕ, а утверждает о нём после близнеца: засчитанный исход обязан
// ронять пробу её наблюдаемым — отказом по частоте верному коду (форма
// позиции), — а счёт и клетки идут следом, внутренней стороной того же факта.
type naSnapshot struct {
	counts naCounts
	cells  naCells
}

func (h *sfHarness) snapshot(p *naPerson) naSnapshot {
	h.obs.mu.Lock()
	defer h.obs.mu.Unlock()
	c := naCells{present: map[string]int{}, refusals: map[humansession.SecondFactorRefusal]int{}}
	for k, v := range h.obs.sfPresent {
		c.present[k] = v
	}
	for k, v := range h.obs.sfRefusals {
		c.refusals[k] = v
	}
	return naSnapshot{
		counts: naCounts{
			byAddress: h.failures(humansession.FailureByAddress, p.email),
			bySource:  h.failures(humansession.FailureBySource, naSource),
		},
		cells: c,
	}
}

// requireNotCountedAndCellsGrewByOne — исход не тронул ни одну ось счёта; ровно
// названные клетки выросли на единицу, прочие не изменились: различимость
// исхода внутрь, клеткой, и только ею.
func requireNotCountedAndCellsGrewByOne(t *testing.T, before, after naSnapshot, present []string, refusals []humansession.SecondFactorRefusal) {
	t.Helper()
	require.Equal(t, before.counts, after.counts, "исход попыткой не считается — ни по адресу, ни по источнику")
	want := naCells{present: map[string]int{}, refusals: map[humansession.SecondFactorRefusal]int{}}
	for k, v := range before.cells.present {
		want.present[k] = v
	}
	for k, v := range before.cells.refusals {
		want.refusals[k] = v
	}
	for _, k := range present {
		want.present[k]++
	}
	for _, k := range refusals {
		want.refusals[k]++
	}
	require.Equal(t, want.present, after.cells.present, "клетки предъявлений (способ × исход): выросли ровно %v", present)
	require.Equal(t, want.refusals, after.cells.refusals, "клетки отказов второго фактора: выросли ровно %v", refusals)
}

// rightCodeInSession — верный код церемонией в той же сессии; суждение — у
// вызывающего (`requireRightCodePassed`).
func (h *sfHarness) rightCodeInSession(t *testing.T, p *naPerson) (humansession.StepUpOutput, error) {
	t.Helper()
	return h.stepUp.Execute(context.Background(), humansession.StepUpInput{
		Bearer: p.bearer, Method: assurance.MethodTOTP, Code: probeTOTP(t, p.secret, h.step()), Source: naSource,
	})
}

// requireRightCodePassed — верный код проходит без отказа по частоте, сессия —
// «2», счёт по адресу обнулён.
func (h *sfHarness) requireRightCodePassed(t *testing.T, p *naPerson, out humansession.StepUpOutput, err error) {
	t.Helper()
	require.NoError(t, err, "верный код после N−1 неверных и исхода — без отказа по частоте")
	require.Equal(t, "2", out.View.Session.AssuranceLevel)
	require.Zero(t, h.failures(humansession.FailureByAddress, p.email), "код, доводящий вход до «2», обнуляет счёт")
}

// naVerb — глагол, предъявляющий код; проба судит только отказ.
type naVerb struct {
	name    string
	present func(t *testing.T, h *sfHarness, p *naPerson, f humansession.SecondFactorPresentation) error
}

var (
	naStepUp = naVerb{"step-up", func(t *testing.T, h *sfHarness, p *naPerson, f humansession.SecondFactorPresentation) error {
		_, err := h.stepUp.Execute(context.Background(), humansession.StepUpInput{Bearer: p.bearer, Method: f.Method, Code: f.Code, Source: naSource})
		return err
	}}
	naLogin = naVerb{"login", func(t *testing.T, h *sfHarness, p *naPerson, f humansession.SecondFactorPresentation) error {
		_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: p.email, Password: naPassword, Source: naSource, SecondFactor: &f})
		return err
	}}
	naRemove = naVerb{"remove", func(t *testing.T, h *sfHarness, p *naPerson, f humansession.SecondFactorPresentation) error {
		_, err := h.remove.Execute(context.Background(), humansession.RemoveSecondFactorInput{Bearer: p.bearer, Factor: f, Source: naSource})
		return err
	}}
	naRegenerate = naVerb{"regenerate", func(t *testing.T, h *sfHarness, p *naPerson, f humansession.SecondFactorPresentation) error {
		_, err := h.regenerate.Execute(context.Background(), humansession.RegenerateBackupCodesInput{Bearer: p.bearer, Factor: f, Source: naSource})
		return err
	}}
)

func totpOf(code string) humansession.SecondFactorPresentation {
	return humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: code}
}

func lookupOf(code string) humansession.SecondFactorPresentation {
	return humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: code}
}

// unreadableTOTP — в строку `totp` подставлен материал, который не открывает ни
// один ключ перечня (Ф12-35 «в»: `K1` снят из перечня); возвращает возврат
// прежнего материала — близнец исхода.
func (h *sfHarness) unreadableTOTP(t *testing.T, userID domain.UserID) (restore func()) {
	t.Helper()
	row, ok := h.store.factors[userID][domain.LoginMethodTOTP]
	require.True(t, ok, "предпосылка: строка totp есть")
	was := row.Verifier
	v, err := domain.NewLoginVerifier("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	require.NoError(t, err)
	row.Verifier = v
	return func() { row.Verifier = was }
}

// occupyCapacity — все места ёмкости проверяющего заняты блокирующей работой
// (Ф3-30 форма). Возвращает освобождение: идемпотентно, оно же — очистка пробы,
// если проба упала раньше, чем освободила места.
func occupyCapacity(t *testing.T, v *passwordverify.Verifier) (release func()) {
	t.Helper()
	slots := v.Capacity()
	require.Positive(t, slots, "предпосылка: у проверяющего есть ёмкость")
	hold := make(chan struct{})
	taken := make(chan bool, slots)
	var busy sync.WaitGroup
	for i := 0; i < slots; i++ {
		busy.Add(1)
		go func() {
			defer busy.Done()
			if !v.WithCapacity(func() { taken <- true; <-hold }) {
				taken <- false
			}
		}()
	}
	var once sync.Once
	release = func() { once.Do(func() { close(hold); busy.Wait() }) }
	t.Cleanup(release)
	for i := 0; i < slots; i++ {
		require.True(t, <-taken, "предпосылка: место ёмкости №%d занято блокирующей работой", i+1)
	}
	return release
}

// ───────────────────────────── свежесть ─────────────────────────────────

// TestF12_32_FreshnessRefusalIsNotAnAttempt — Ф12-32, исход «отказ по
// свежести» (Ф12-09 форма): сессия несвежа, `N − 1` неверных кодов церемонией в
// ней, затем отказ по свежести глаголом правки своих данных, затем верный код
// церемонией в той же сессии проходит без отказа по частоте; клетка отказа
// `session-not-fresh` выросла на единицу. Засчитай глагол отказ попыткой,
// верный код получил бы 429.
func TestF12_32_FreshnessRefusalIsNotAnAttempt(t *testing.T) {
	verbs := []struct {
		name   string
		refuse func(t *testing.T, h *sfHarness, p *naPerson) error
	}{
		{"enroll", func(t *testing.T, h *sfHarness, p *naPerson) error {
			_, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: p.bearer})
			return err
		}},
		// Верный код в теле: единственная причина отказа — свежесть; в свежей
		// сессии тот же вызов у личности с фактором дал бы «уже заведён».
		{"confirm", func(t *testing.T, h *sfHarness, p *naPerson) error {
			_, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
				Bearer: p.bearer, Code: probeTOTP(t, p.secret, h.step()), Source: naSource,
			})
			return err
		}},
	}
	for _, verb := range verbs {
		t.Run(verb.name, func(t *testing.T) {
			h := newSFHarness(t)
			p := h.withFactor(t, "usr-nf", "nf@example.invalid")
			n := sfLimits().AddressAttempts
			// Окно Р8 прошло от момента последнего предъявления; окно частоты —
			// нет: неверные коды ложатся ПОСЛЕ сдвига часов.
			h.clock = h.clock.Add(sfWindow + time.Second)
			h.wrongCodesInSession(t, p, n-1)

			before := h.snapshot(p)
			refused := verb.refuse(t, h, p)
			judged := h.snapshot(p)
			out, err := h.rightCodeInSession(t, p)

			require.ErrorIs(t, refused, humansession.ErrSessionNotFresh)
			h.requireRightCodePassed(t, p, out, err)
			requireNotCountedAndCellsGrewByOne(t, before, judged, nil, []humansession.SecondFactorRefusal{humansession.RefusalSessionNotFresh})
		})
	}
}

// ───────────────────────────── материал ─────────────────────────────────

// TestF12_32_UnreadableMaterialIsNotAnAttempt — Ф12-32, исход «материал не
// открывается» (Ф12-35 «в»): `N − 1` неверных кодов, затем верный код по времени
// при материале, который не открывает ни один ключ, — 503
// `second factor cannot be verified; ask the administrator of this installation`; счёт не вырос, клетки «материал не
// открывается» и отказа `unavailable` выросли на единицу; материал возвращён —
// тот же код тем же глаголом проходит без отказа по частоте.
func TestF12_32_UnreadableMaterialIsNotAnAttempt(t *testing.T) {
	cellPresent := []string{sfKey(assurance.MethodTOTP, humansession.PresentationMaterialUnreadable)}
	cellRefusal := []humansession.SecondFactorRefusal{humansession.RefusalUnavailable}
	for _, verb := range []naVerb{naStepUp, naLogin, naRemove, naRegenerate} {
		t.Run(verb.name, func(t *testing.T) {
			h := newSFHarness(t)
			p := h.withFactor(t, "usr-mu", "mu@example.invalid")
			n := sfLimits().AddressAttempts
			h.wrongCodesInSession(t, p, n-1)
			code := probeTOTP(t, p.secret, h.step())

			restore := h.unreadableTOTP(t, p.id)
			before := h.snapshot(p)
			refused := verb.present(t, h, p, totpOf(code))
			judged := h.snapshot(p)
			restore()
			twin := verb.present(t, h, p, totpOf(code))

			require.ErrorIs(t, refused, humansession.ErrSecondFactorUnavailable)
			require.NoError(t, twin, "близнец: тот же код, материал открывается — без отказа по частоте")
			require.Zero(t, h.failures(humansession.FailureByAddress, p.email), "код, доводящий вход до «2», обнуляет счёт")
			requireNotCountedAndCellsGrewByOne(t, before, judged, cellPresent, cellRefusal)
		})
	}
	// `confirm` открывает строку `pending` сам, мимо общей сверки.
	t.Run("confirm", func(t *testing.T) {
		h := newSFHarness(t)
		p := h.withPending(t, "usr-mp", "mp@example.invalid")
		n := sfLimits().AddressAttempts
		h.wrongCodesOnConfirm(t, p, n-1)
		code := probeTOTP(t, p.secret, h.step())

		restore := h.unreadableTOTP(t, p.id)
		before := h.snapshot(p)
		_, refused := h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: p.bearer, Code: code, Source: naSource})
		judged := h.snapshot(p)
		row, ok := h.sfRow(p.id, domain.LoginMethodTOTP)
		require.True(t, ok)
		stateAfterRefusal := row.State
		restore()
		out, twin := h.confirm.Execute(context.Background(), humansession.ConfirmInput{Bearer: p.bearer, Code: code, Source: naSource})

		require.ErrorIs(t, refused, humansession.ErrSecondFactorUnavailable)
		require.Equal(t, domain.LoginMethodStatePending, stateAfterRefusal, "после отказа заведение не подтверждено")
		require.NoError(t, twin, "близнец: тот же код, материал открывается — без отказа по частоте")
		require.Equal(t, "2", out.View.Session.AssuranceLevel)
		requireNotCountedAndCellsGrewByOne(t, before, judged, cellPresent, cellRefusal)
	})
}

// ───────────────────────────── ёмкость ──────────────────────────────────

// TestF12_32_ExhaustedCapacityOnABackupCodeIsNotAnAttempt — Ф12-32, исход
// «ёмкость проверяющего исчерпана» на предъявлении ЗАПАСНОГО кода (ID-PW-1
// PWV-15, Р6): `N − 1` неверных кодов, затем годный запасной код при занятой
// ёмкости — наружу тот же 401, что у неверного (Ф3-30 форма); счёт не вырос,
// код не потреблён, клетка `lookup_secret × capacity-exhausted` выросла на
// единицу; ёмкость освобождена — тот же код тем же глаголом проходит без отказа
// по частоте.
func TestF12_32_ExhaustedCapacityOnABackupCodeIsNotAnAttempt(t *testing.T) {
	cellPresent := []string{sfKey(assurance.MethodLookupSecret, humansession.PresentationCapacityExhausted)}
	for _, verb := range []naVerb{naStepUp, naRemove, naRegenerate} {
		t.Run(verb.name, func(t *testing.T) {
			h := newSFHarness(t)
			p := h.withFactor(t, "usr-ce", "ce@example.invalid")
			n := sfLimits().AddressAttempts
			h.wrongCodesInSession(t, p, n-1)
			set, ok := h.sfRow(p.id, domain.LoginMethodLookupSecret)
			require.True(t, ok, "предпосылка: набор заведён")

			release := occupyCapacity(t, h.verifier)
			before := h.snapshot(p)
			refused := verb.present(t, h, p, lookupOf(p.codes[0]))
			judged := h.snapshot(p)
			setAfterRefusal, ok := h.sfRow(p.id, domain.LoginMethodLookupSecret)
			require.True(t, ok)
			release()
			twin := verb.present(t, h, p, lookupOf(p.codes[0]))

			require.ErrorIs(t, refused, humansession.ErrAuthenticationFailed, "наружу — тот же 401")
			require.Equal(t, set.Verifier.Reveal(), setAfterRefusal.Verifier.Reveal(), "код не потреблён: набор прежний")
			require.NoError(t, twin, "близнец: тот же код, ёмкость свободна — без отказа по частоте")
			require.Zero(t, h.failures(humansession.FailureByAddress, p.email), "код, доводящий вход до «2», обнуляет счёт")
			requireNotCountedAndCellsGrewByOne(t, before, judged, cellPresent, nil)
		})
	}
	// Код по времени ёмкости не занимает (Р6): при той же занятой ёмкости верный
	// код по времени сверяется и проходит — отличие от ветвей выше одно: способ.
	t.Run("totp-takes-no-capacity", func(t *testing.T) {
		h := newSFHarness(t)
		p := h.withFactor(t, "usr-ct", "ct@example.invalid")
		n := sfLimits().AddressAttempts
		h.wrongCodesInSession(t, p, n-1)
		occupyCapacity(t, h.verifier)
		before := h.snapshot(p)
		out, err := h.rightCodeInSession(t, p)
		judged := h.snapshot(p)

		h.requireRightCodePassed(t, p, out, err)
		matchedCell := sfKey(assurance.MethodTOTP, humansession.PresentationMatched)
		require.Equal(t, before.cells.present[matchedCell]+1, judged.cells.present[matchedCell], "код по времени сверен при занятой ёмкости")
		require.Equal(t, before.cells.present[cellPresent[0]], judged.cells.present[cellPresent[0]], "клетка ёмкости не выросла")
	})
}

// ───────────────────────────── предпосылка формы ───────────────────────

// TestF12_32_ProbeFormPremise_ACountedPresentationInPlaceOfTheOutcomeRefusesTheTwin —
// предпосылка трёх проб выше: на КАЖДОМ предъявлении близнеца, какое они делают
// (глагол × способ), `N − 1` неверных плюс ОДНО сосчитанное предъявление на
// месте исхода дают близнецу 429 по адресу. Без этого зелёный пробы исхода не
// отличался бы от глагола, который счёт не читает, либо от предела, отличного
// от `N`.
func TestF12_32_ProbeFormPremise_ACountedPresentationInPlaceOfTheOutcomeRefusesTheTwin(t *testing.T) {
	requireRateRefusal := func(t *testing.T, err error) {
		t.Helper()
		var tma *humansession.TooManyAttemptsError
		require.ErrorAs(t, err, &tma, "N сосчитанных — близнец получает отказ по частоте")
		require.Equal(t, humansession.FailureByAddress, tma.Scope)
	}
	byTOTP := func(t *testing.T, h *sfHarness, p *naPerson) humansession.SecondFactorPresentation {
		return totpOf(probeTOTP(t, p.secret, h.step()))
	}
	byBackupCode := func(t *testing.T, h *sfHarness, p *naPerson) humansession.SecondFactorPresentation {
		return lookupOf(p.codes[0])
	}
	// Перечень — близнецы проб выше: свежесть и материал — код по времени,
	// ёмкость — запасной код.
	for _, twin := range []struct {
		verb   naVerb
		method string
		code   func(t *testing.T, h *sfHarness, p *naPerson) humansession.SecondFactorPresentation
	}{
		{naStepUp, "totp", byTOTP},
		{naStepUp, "lookup_secret", byBackupCode},
		{naLogin, "totp", byTOTP},
		{naRemove, "totp", byTOTP},
		{naRemove, "lookup_secret", byBackupCode},
		{naRegenerate, "totp", byTOTP},
		{naRegenerate, "lookup_secret", byBackupCode},
	} {
		t.Run(twin.verb.name+"/"+twin.method, func(t *testing.T) {
			h := newSFHarness(t)
			p := h.withFactor(t, "usr-pf", "pf@example.invalid")
			n := sfLimits().AddressAttempts
			h.wrongCodesInSession(t, p, n)
			requireRateRefusal(t, twin.verb.present(t, h, p, twin.code(t, h, p)))
		})
	}
	t.Run("confirm/totp", func(t *testing.T) {
		h := newSFHarness(t)
		p := h.withPending(t, "usr-pc", "pc@example.invalid")
		n := sfLimits().AddressAttempts
		h.wrongCodesOnConfirm(t, p, n)
		_, err := h.confirm.Execute(context.Background(), humansession.ConfirmInput{
			Bearer: p.bearer, Code: probeTOTP(t, p.secret, h.step()), Source: naSource,
		})
		requireRateRefusal(t, err)
	})
}
