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
//     как полоса отсчитала потолок: запись мимо нашего процесса (перенос П3
//     иным процессом) приносит класс, которого перепись старта не видела, и
//     первый же вход по нему поднимает потолок — окно оракула равно одному
//     обращению, а не времени до перезапуска;
//  4. полоса без огибающей не собирается.
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
	go func() {
		h.verifier.WithCapacity(func() {
			close(held)
			<-hold
		})
	}()
	<-held
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
