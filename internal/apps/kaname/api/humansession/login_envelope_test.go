// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_envelope_test.go — ОГИБАЮЩАЯ ПО ПОТОЛКУ на полосе входа (Ф3-31, Ф1-48;
// ID-PW-1 Р4, PWV-03, PWV-06, PWV-15.4; решение kaname#188).
//
// Предмет проб — свойства ПОЛОСЫ, а не калибратора (тот — `passwordverify`):
//
//  1. всякий исход, наступивший после ворот частоты, уходит НЕ РАНЬШЕ потолка
//     огибающей: успех, неверный пароль, «адреса нет», «материала нет»,
//     заблокирована, негодный материал, исчерпание ёмкости, отказ хранилища.
//     Класс стоимости хранимого значения тогда невидим по времени by
//     construction — все исходы стоят одинаково;
//  2. отказ формы и отказ по частоте потолка НЕ ждут: у обоих СВОЙ ответ,
//     отличимый кодом, и о личности они не говорят ничего; задержка на них
//     сделала бы шторм попыток дороже для нас, не для постороннего;
//  3. класс значения, встреченного на чтении, ДОПУСКАЕТСЯ в огибающую до того,
//     как полоса отсчитала потолок: запись мимо нашего процесса (иным
//     процессом) приносит класс, которого перепись старта не видела, и
//     первый же вход по нему поднимает потолок — окно оракула равно одному
//     обращению, а не времени до перезапуска;
//  4. полоса без огибающей не собирается;
//  5. ёмкость проверяющего на ожидании НЕ занята (Р17; заказ kaname#220 (б)):
//     при ёмкости 1 второе обращение в окне ожидания первого получает место и
//     свой исход не раньше потолка, во время вычисления — «ёмкость исчерпана»
//     и тоже не раньше потолка; отрицательный контроль поимённо — реализация,
//     держащая место до конца ожидания, краснеет на первой половине и молчит
//     на второй.
package humansession_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// admitCall — один допуск класса, как его видел дублёр огибающей.
type admitCall struct {
	class   string
	trigger passwordverify.EnvelopeTrigger
}

// laneEnvelope — дублёр порта огибающей для проб полосы: потолок задаётся
// пробой, допуски записываются. `raiseOn` — класс, допуск которого поднимает
// потолок до `raiseTo` (так ведёт себя настоящая огибающая на классе дороже
// текущего потолка).
type laneEnvelope struct {
	mu      sync.Mutex
	floor   time.Duration
	admits  []admitCall
	raiseOn string
	raiseTo time.Duration
}

func (e *laneEnvelope) Floor() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.floor
}

func (e *laneEnvelope) Admit(_ context.Context, class domain.PasswordCostClass, trigger passwordverify.EnvelopeTrigger) (passwordverify.Admission, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.admits = append(e.admits, admitCall{class: class.Key(), trigger: trigger})
	calibrated := false
	if e.raiseOn != "" && class.Key() == e.raiseOn && e.raiseTo > e.floor {
		e.floor = e.raiseTo
		calibrated = true
	}
	return passwordverify.Admission{Calibrated: calibrated, Floor: e.floor}, nil
}

func (e *laneEnvelope) calls() []admitCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]admitCall(nil), e.admits...)
}

// timed — исполнить вход и вернуть, сколько он длился.
func timed(t *testing.T, h *harness, email, password, source string) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: email, Password: password, Source: source})
	return time.Since(start), err
}

// failingUsers — каталог людей, чьё хранилище не отвечает: отказ хранилища на
// пути ПОСЛЕ ворот частоты.
type failingUsers struct{}

func (failingUsers) UserByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, errFakePort
}

// TestLogin_F3_31_EveryOutcomeAfterTheRateGateHoldsUntilTheFloor — восемь
// исходов после ворот частоты ждут потолка; отказ формы и отказ по частоте —
// нет (положительный контроль в обе стороны: без него потолок в нуле зеленил
// бы «ждут», а потолок на всём — «не ждут»).
func TestLogin_F3_31_EveryOutcomeAfterTheRateGateHoldsUntilTheFloor(t *testing.T) {
	const floor = 40 * time.Millisecond
	h := newHarness(t, nil)
	h.envelope.floor = floor
	// Ёмкость проверяющего в один слот — чтобы полоса «ёмкость исчерпана» была
	// воспроизводима: слот держит подставная проверка.
	var err error
	h.verifier, err = passwordverify.New(1, nopVerifyObserver{})
	require.NoError(t, err)
	decoy, err := h.hasher.Hash("decoy-of-the-harness")
	require.NoError(t, err)
	require.NoError(t, h.verifier.SetDecoy(decoy))
	require.NoError(t, rebuildLoginWithLimits(h, 100, time.Hour))

	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	h.person(t, "usr-c", "c@example.invalid", "", true)
	d := h.person(t, "usr-d", "d@example.invalid", "correct horse battery", true)
	d.InviteStatus = domain.InviteStatusBlocked
	h.store.users[d.ID] = d
	e := h.person(t, "usr-e", "e@example.invalid", "", true)
	bad, err := domain.NewLoginVerifier("$pbkdf2$not-in-registry")
	require.NoError(t, err)
	h.store.verifiers[e.ID] = bad

	cases := []struct {
		name, email, password string
		outcome               humansession.LoginOutcome
		wantErr               error
	}{
		{"успех", "a@example.invalid", "correct horse battery", humansession.LoginOutcomeIssued, nil},
		{"пароль не тот", "a@example.invalid", "wrong", humansession.LoginOutcomeMismatched, humansession.ErrAuthenticationFailed},
		{"адреса нет", "nobody@example.invalid", "whatever", humansession.LoginOutcomeNoRow, humansession.ErrAuthenticationFailed},
		{"материала нет", "c@example.invalid", "whatever", humansession.LoginOutcomeMaterialNone, humansession.ErrAuthenticationFailed},
		{"заблокирована", "d@example.invalid", "correct horse battery", humansession.LoginOutcomeBlocked, humansession.ErrAuthenticationFailed},
		{"негодный материал", "e@example.invalid", "whatever", humansession.LoginOutcomeVerifierIssue, humansession.ErrAuthenticationFailed},
	}
	for i, c := range cases {
		source := "203.0.113." + string(rune('1'+i))
		elapsed, err := timed(t, h, c.email, c.password, source)
		if c.wantErr == nil {
			require.NoError(t, err, c.name)
		} else {
			require.ErrorIs(t, err, c.wantErr, c.name)
		}
		require.Equal(t, 1, h.obs.login[c.outcome], "клетка %s", c.outcome)
		require.GreaterOrEqual(t, elapsed, floor, "исход %q ушёл раньше потолка: время отказа различает причину", c.name)
	}

	// Ёмкость исчерпана: единственный слот держит подставная проверка.
	hold := make(chan struct{})
	held := make(chan struct{})
	refused := make(chan struct{})
	go func() {
		if !h.verifier.WithCapacity(func() {
			close(held)
			<-hold
		}) {
			close(refused)
		}
	}()
	select {
	case <-held:
	case <-refused:
		t.Fatal("подставная проверка не получила место — ёмкость занята кем-то ещё; проба беспредметна")
	}
	elapsed, err := timed(t, h, "a@example.invalid", "correct horse battery", "203.0.113.70")
	close(hold)
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeCapacity])
	require.GreaterOrEqual(t, elapsed, floor, "«ёмкость исчерпана» — тот же исход в то же время (PWV-15.4), а не мгновенный отказ")

	// Хранилище не ответило ПОСЛЕ ворот частоты.
	broken, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: failingUsers{}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, TTL: ucTTL, Observer: h.obs, Now: func() time.Time { return h.clock },
		Logger: slog.New(slog.DiscardHandler), Envelope: h.envelope, TOTP: h.totp, Sets: h.verifier,
		Limits: humansession.Limits{AddressAttempts: 100, AddressWindow: time.Hour, SourceAttempts: 1000, SourceWindow: time.Hour},
	})
	require.NoError(t, err)
	start := time.Now()
	_, err = broken.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "x", Source: "203.0.113.71"})
	elapsed = time.Since(start)
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.GreaterOrEqual(t, elapsed, floor, "отказ хранилища после ворот — тоже под огибающей: момент отказа не сообщает, какой запрос упал")

	// Положительный контроль: отказ формы — раньше ворот, без потолка.
	start = time.Now()
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "", Source: "203.0.113.72"})
	elapsed = time.Since(start)
	require.Error(t, err)
	require.Less(t, elapsed, floor/2, "отказ формы не ждёт потолка: о личности он не говорит ничего")

	// Положительный контроль: отказ по частоте — свой ответ, без потолка.
	require.NoError(t, rebuildLoginWithLimits(h, 1, time.Hour))
	_, err = timed(t, h, "z@example.invalid", "wrong", "203.0.113.73")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "первая попытка — отказ входа")
	start = time.Now()
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{Email: "z@example.invalid", Password: "wrong", Source: "203.0.113.73"})
	elapsed = time.Since(start)
	var tooMany *humansession.TooManyAttemptsError
	require.True(t, errors.As(err, &tooMany), "вторая — отказ по частоте")
	require.Less(t, elapsed, floor/2, "отказ по частоте не ждёт потолка: у него свой ответ, отличимый кодом")
}

// TestLogin_F3_31_TheClassReadIsAdmittedBeforeTheFloorIsTaken — класс
// прочитанного значения допускается в огибающую на каждом вычисленном исходе
// (совпал, не совпал); полосы без вычисления по хранимому значению («адреса
// нет», «материала нет», негодный материал) допуска не делают; потолок,
// поднятый допуском, действует на ЭТОТ же вход.
func TestLogin_F3_31_TheClassReadIsAdmittedBeforeTheFloorIsTaken(t *testing.T) {
	const raised = 40 * time.Millisecond
	h := newHarness(t, nil)
	a := h.person(t, "usr-a", "a@example.invalid", "", true)
	h.store.verifiers[a.ID] = bcryptVerifier(t, 4, "legacy password")
	h.person(t, "usr-b", "b@example.invalid", "declared password", true)
	h.person(t, "usr-c", "c@example.invalid", "", true)
	e := h.person(t, "usr-e", "e@example.invalid", "", true)
	bad, err := domain.NewLoginVerifier("$pbkdf2$not-in-registry")
	require.NoError(t, err)
	h.store.verifiers[e.ID] = bad

	legacy := domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: 4}}
	h.envelope.raiseOn, h.envelope.raiseTo = legacy.Key(), raised

	elapsed, err := timed(t, h, "a@example.invalid", "wrong", "203.0.113.80")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, []admitCall{{legacy.Key(), passwordverify.EnvelopeTriggerRead}}, h.envelope.calls(),
		"класс прочитанного значения допущен с поводом «чтение»")
	require.GreaterOrEqual(t, elapsed, raised, "потолок, поднятый допуском, действует на тот же вход, а не со следующего")

	declared := domain.PasswordCostClass{Format: h.hasher.Declared().Format, Params: h.hasher.Declared().Params}
	_, err = timed(t, h, "b@example.invalid", "declared password", "203.0.113.81")
	require.NoError(t, err)
	calls := h.envelope.calls()
	require.Len(t, calls, 2)
	require.Equal(t, admitCall{declared.Key(), passwordverify.EnvelopeTriggerRead}, calls[1], "совпавшее значение допускается так же, как не совпавшее")

	for _, c := range []struct{ name, email string }{
		{"адреса нет", "nobody@example.invalid"}, {"материала нет", "c@example.invalid"}, {"негодный материал", "e@example.invalid"},
	} {
		_, err = timed(t, h, c.email, "whatever", "203.0.113.82")
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, c.name)
	}
	require.Len(t, h.envelope.calls(), 2, "исходы без вычисления по хранимому значению класса не приносят")
}

// TestNewLoginUseCase_RequiresTheTimingEnvelope — полоса без огибающей не
// собирается: «выравнивать нечем» не есть решение.
func TestNewLoginUseCase_RequiresTheTimingEnvelope(t *testing.T) {
	h := newHarness(t, nil)
	_, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: func() time.Time { return h.clock },
		Logger: slog.New(slog.DiscardHandler), TOTP: h.totp, Sets: h.verifier,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "timing envelope")
}

// computedSignal — исправный проверяющий полосы, сообщающий пробе о ЗАВЕРШЕНИИ
// вычисления: сигнал уходит после возврата настоящего `Verify` (с любым его
// исходом, включая «ёмкость исчерпана»), когда место ёмкости уже отпущено. Так
// проба подаёт второе обращение ровно в окне ожидания первого — после его
// вычисления, до истечения потолка.
type computedSignal struct {
	inner    *passwordverify.Verifier
	computed chan struct{}
}

func (c *computedSignal) Verify(stored domain.LoginVerifier, presented string) passwordverify.Result {
	res := c.inner.Verify(stored, presented)
	c.computed <- struct{}{}
	return res
}

func (c *computedSignal) MeetsDeclared(stored domain.LoginVerifier, declared passwordverify.Declared) (bool, error) {
	return c.inner.MeetsDeclared(stored, declared)
}

// slotHeldThroughTheWait — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ поимённо (Ф3-31, Р17):
// реализация, держащая место ёмкости до КОНЦА ОЖИДАНИЯ, а не до конца
// вычисления. От исправной отличается одним фактом: своё единственное место
// отпускается после `hold`, ожидания в самом проверяющем. Обязана краснеть на
// первой половине пары (второе обращение в окне ожидания получает «ёмкость
// исчерпана» вместо своего исхода) и молчать на второй (во время вычисления
// «ёмкость исчерпана» законна). Вычисление — настоящим проверяющим.
type slotHeldThroughTheWait struct {
	inner    *passwordverify.Verifier
	slot     chan struct{}
	hold     time.Duration
	computed chan struct{}
}

func (d *slotHeldThroughTheWait) Verify(stored domain.LoginVerifier, presented string) passwordverify.Result {
	select {
	case d.slot <- struct{}{}:
	default:
		d.computed <- struct{}{}
		return passwordverify.Result{Outcome: passwordverify.OutcomeCapacityExhausted}
	}
	defer func() { <-d.slot }()
	res := d.inner.Verify(stored, presented)
	d.computed <- struct{}{}
	time.Sleep(d.hold) // дефект: место занято и на ожидании
	return res
}

func (d *slotHeldThroughTheWait) MeetsDeclared(stored domain.LoginVerifier, declared passwordverify.Declared) (bool, error) {
	return d.inner.MeetsDeclared(stored, declared)
}

// capacityPairOutcomes — исходы ПАРЫ обращений при ёмкости 1 против данного
// проверяющего: первое уходит в горутине; второе подаётся в ОКНЕ ОЖИДАНИЯ
// первого — после сигнала о вычислении, до его возврата (проба это проверяет,
// а не полагает). Возвращает счётчики исходов полосы по обоим обращениям и
// длительность второго.
func capacityPairOutcomes(t *testing.T, h *harness, verifier humansession.Verifier, computed <-chan struct{}, floor time.Duration) (map[humansession.LoginOutcome]int, time.Duration) {
	t.Helper()
	obs := newCountingObserver()
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: verifier,
		Hasher: h.hasher, TTL: ucTTL, Observer: obs, Now: func() time.Time { return h.clock },
		Logger: slog.New(slog.DiscardHandler), Envelope: h.envelope, TOTP: h.totp, Sets: h.verifier,
		Limits: humansession.Limits{AddressAttempts: 100, AddressWindow: time.Hour, SourceAttempts: 1000, SourceWindow: time.Hour},
	})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = login.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "wrong-first", Source: "203.0.113.90"})
	}()
	select {
	case <-computed:
	case <-time.After(floor):
		t.Fatal("первое обращение не вычислилось за потолок — окна ожидания нет, проба беспредметна")
	}
	select {
	case <-done:
		t.Fatal("первое обращение уже вернулось — второе подано бы ВНЕ окна ожидания, проба беспредметна")
	default:
	}
	start := time.Now()
	_, err = login.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "wrong-second", Source: "203.0.113.91"})
	elapsed := time.Since(start)
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "второе обращение — тот же один отказ")
	select {
	case <-done:
	case <-time.After(2 * floor):
		t.Fatal("первое обращение не вернулось и за два потолка")
	}
	select {
	case <-computed:
	case <-time.After(floor):
		t.Fatal("второе обращение не дошло до проверяющего")
	}
	return obs.login, elapsed
}

// TestLogin_F3_31_TheCapacitySlotIsFreeDuringTheWait — ёмкость проверяющего
// на ожидании не занята (Ф3-31 «Тогда», Р17; заказ kaname#220 (б)). При
// ёмкости 1 второе обращение, поданное в окне ОЖИДАНИЯ первого, получает
// место и СВОЙ исход («пароль не тот»), не раньше потолка — а не «ёмкость
// исчерпана». Положительный контроль различимости — второе, поданное во
// время ВЫЧИСЛЕНИЯ первого (единственное место держит подставная проверка),
// получает «ёмкость исчерпана» (PWV-15), и тоже не раньше потолка.
// Отрицательный контроль поимённо — `slotHeldThroughTheWait`: реализация,
// держащая место до конца ожидания, краснеет на первой половине (второе
// получает «ёмкость исчерпана») и молчит на второй.
func TestLogin_F3_31_TheCapacitySlotIsFreeDuringTheWait(t *testing.T) {
	const floor = 500 * time.Millisecond
	h := newHarness(t, nil)
	h.envelope.floor = floor
	var err error
	h.verifier, err = passwordverify.New(1, nopVerifyObserver{})
	require.NoError(t, err)
	decoy, err := h.hasher.Hash("decoy-of-the-harness")
	require.NoError(t, err)
	require.NoError(t, h.verifier.SetDecoy(decoy))
	a := h.person(t, "usr-a", "a@example.invalid", "", true)
	// Дешёвое значение: вычисление — миллисекунда, окно ожидания — почти весь
	// потолок; второе обращение заведомо попадает в окно.
	h.store.verifiers[a.ID] = bcryptVerifier(t, 4, "correct horse battery")

	// Во время ВЫЧИСЛЕНИЯ: единственное место держит подставная проверка —
	// «ёмкость исчерпана», не раньше потолка. Одна и та же процедура для
	// исправного проверяющего и для отрицательного контроля.
	duringCompute := func(verifier humansession.Verifier, slotOwner *passwordverify.Verifier, computed <-chan struct{}) (map[humansession.LoginOutcome]int, time.Duration) {
		obs := newCountingObserver()
		login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
			Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: verifier,
			Hasher: h.hasher, TTL: ucTTL, Observer: obs, Now: func() time.Time { return h.clock },
			Logger: slog.New(slog.DiscardHandler), Envelope: h.envelope, TOTP: h.totp, Sets: h.verifier,
			Limits: humansession.Limits{AddressAttempts: 100, AddressWindow: time.Hour, SourceAttempts: 1000, SourceWindow: time.Hour},
		})
		require.NoError(t, err)
		hold := make(chan struct{})
		held := make(chan struct{})
		refused := make(chan struct{})
		go func() {
			if !slotOwner.WithCapacity(func() {
				close(held)
				<-hold
			}) {
				close(refused)
			}
		}()
		select {
		case <-held:
		case <-refused:
			t.Fatal("подставная проверка не получила место — ёмкость занята кем-то ещё; проба беспредметна")
		}
		start := time.Now()
		_, err = login.Execute(context.Background(), humansession.LoginInput{Email: "a@example.invalid", Password: "wrong", Source: "203.0.113.92"})
		elapsed := time.Since(start)
		close(hold)
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
		select {
		case <-computed:
		case <-time.After(floor):
			t.Fatal("обращение не дошло до проверяющего")
		}
		return obs.login, elapsed
	}

	t.Run("correct verifier", func(t *testing.T) {
		correct := &computedSignal{inner: h.verifier, computed: make(chan struct{}, 4)}
		got, elapsed := capacityPairOutcomes(t, h, correct, correct.computed, floor)
		require.Equal(t, 2, got[humansession.LoginOutcomeMismatched], "оба обращения получили СВОЙ исход: место ёмкости на ожидании первого свободно (Р17)")
		require.Zero(t, got[humansession.LoginOutcomeCapacity], "второе обращение в окне ожидания первого не получает «ёмкость исчерпана»")
		require.GreaterOrEqual(t, elapsed, floor, "второе обращение ждёт потолка от своего отсчёта")

		got, elapsed = duringCompute(correct, h.verifier, correct.computed)
		require.Equal(t, 1, got[humansession.LoginOutcomeCapacity], "во время вычисления — «ёмкость исчерпана» (PWV-15): положительный контроль различимости")
		require.GreaterOrEqual(t, elapsed, floor, "«ёмкость исчерпана» — не раньше потолка")
	})

	t.Run("negative control: slot held through the wait", func(t *testing.T) {
		inner, err := passwordverify.New(1, nopVerifyObserver{})
		require.NoError(t, err)
		require.NoError(t, inner.SetDecoy(decoy))
		defective := &slotHeldThroughTheWait{inner: inner, slot: make(chan struct{}, 1), hold: floor, computed: make(chan struct{}, 4)}
		got, _ := capacityPairOutcomes(t, h, defective, defective.computed, floor)
		require.Equal(t, 1, got[humansession.LoginOutcomeCapacity], "первая половина КРАСНЕЕТ на реализации, держащей место до конца ожидания: второе обращение получило «ёмкость исчерпана»")
		require.Equal(t, 1, got[humansession.LoginOutcomeMismatched])

		// Вторая половина на нём же — молчит: место, занятое вычислением, и
		// здесь даёт «ёмкость исчерпана».
		got, elapsed := duringCompute(defective, inner, defective.computed)
		require.Equal(t, 1, got[humansession.LoginOutcomeCapacity], "вторая половина на отрицательном контроле молчит")
		require.GreaterOrEqual(t, elapsed, floor)
	})
}
