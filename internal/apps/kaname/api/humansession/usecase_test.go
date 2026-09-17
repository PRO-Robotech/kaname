// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_test.go — пробы вариантов использования полосы через дублёр
// хранилища (фаза Ф3, `kacho#1269`): вход (Ф3-01…04, Ф3-24, Ф3-28…30, Ф3-43),
// выход (Ф3-15…18), смена пароля (Ф3-19…23), ответ краю (Ф3-09, Ф3-10),
// правило пароля (Ф3-22, Ф3-34), признак формы (Ф3-35…40). Часы — пробы.
package humansession_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

var ucBase = time.Date(2026, 9, 16, 12, 0, 0, 123456000, time.UTC)

const ucTTL = 24 * time.Hour

type harness struct {
	store    *fakeStore
	obs      *countingObserver
	clock    time.Time
	hasher   *passwordverify.Hasher
	verifier *passwordverify.Verifier
	login    *humansession.LoginUseCase
	logout   *humansession.LogoutUseCase
	change   *humansession.ChangePasswordUseCase
	resolve  *humansession.ResolveUseCase
	rule     *humansession.PasswordRule
	// envelope — дублёр огибающей по потолку (Ф3-31, kaname#188): потолок
	// задаёт проба; envelopePort — то, что получает полоса: по умолчанию
	// дублёр, измерительная проба подставляет настоящую огибающую.
	envelope     *laneEnvelope
	envelopePort humansession.TimingEnvelope
	// Восстановление доступа (Ф5).
	recoveryRequest  *humansession.RequestRecoveryUseCase
	recoveryComplete *humansession.CompleteRecoveryUseCase
}

// rcCodeTTL — срок кода в пробах: величина Ф1 §4.1, объявляемая настройкой.
const rcCodeTTL = 5 * time.Minute

type nopVerifyObserver struct{}

func (nopVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

func declared() passwordverify.Declared {
	return passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      65536,
			domain.CostParamArgon2Iterations:  3,
			domain.CostParamArgon2Parallelism: 4,
		},
	}
}

func limits() humansession.Limits {
	return humansession.Limits{AddressAttempts: 3, AddressWindow: 10 * time.Minute, SourceAttempts: 5, SourceWindow: 10 * time.Minute}
}

func newHarness(t *testing.T, breach humansession.BreachChecker) *harness {
	t.Helper()
	h := &harness{store: newFakeStore(), obs: newCountingObserver(), clock: ucBase, envelope: &laneEnvelope{}}
	h.envelopePort = h.envelope
	var err error
	h.hasher, err = passwordverify.NewHasher(declared())
	require.NoError(t, err)
	h.verifier, err = passwordverify.New(4, nopVerifyObserver{})
	require.NoError(t, err)
	// Выравнивание полосы «материала нет» — как в композиционном корне.
	decoy, err := h.hasher.Hash("decoy-of-the-harness")
	require.NoError(t, err)
	require.NoError(t, h.verifier.SetDecoy(decoy))
	now := func() time.Time { return h.clock }
	logger := slog.New(slog.DiscardHandler)
	h.rule, err = humansession.NewPasswordRule(8, breach, h.obs, logger)
	require.NoError(t, err)
	h.login, err = humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: now, Logger: logger,
		Envelope: h.envelopePort,
	})
	require.NoError(t, err)
	h.logout, err = humansession.NewLogoutUseCase(h.store, h.obs, now, logger)
	require.NoError(t, err)
	h.change, err = humansession.NewChangePasswordUseCase(humansession.ChangePasswordDeps{
		Store: h.store, Methods: fakeMethods{h.store}, Verifier: h.verifier, Hasher: h.hasher, Rule: h.rule,
		Limits: limits(), Observer: h.obs, Now: now, Logger: logger,
	})
	require.NoError(t, err)
	h.resolve, err = humansession.NewResolveUseCase(h.store, h.obs, now)
	require.NoError(t, err)
	h.recoveryRequest, err = humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: h.store, CodeTTL: rcCodeTTL, Dispatcher: humansession.SyncDispatcher{}, Observer: h.obs, Now: now, Logger: logger,
	})
	require.NoError(t, err)
	h.recoveryComplete, err = humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		Store: h.store, Hasher: h.hasher, Rule: h.rule, Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: now, Logger: logger,
	})
	require.NoError(t, err)
	return h
}

func (h *harness) person(t *testing.T, id, email, password string, verified bool) domain.User {
	t.Helper()
	u := domain.User{ID: domain.UserID(id), AccountID: "acc-1", ExternalID: domain.ExternalSubject("own:" + id), Email: domain.Email(email),
		DisplayName: domain.DisplayName("Person " + id), InviteStatus: domain.InviteStatusActive}
	h.store.users[u.ID] = u
	h.store.verified[u.ID] = verified
	if password != "" {
		v, err := h.hasher.Hash(password)
		require.NoError(t, err)
		h.store.verifiers[u.ID] = v
	}
	return u
}

func (h *harness) mustLogin(t *testing.T, email, password string) humansession.LoginOutput {
	t.Helper()
	out, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: email, Password: password, Source: "203.0.113.7"})
	require.NoError(t, err)
	return out
}

// TestLogin_F3_01_IssuesASessionWithLevelOneAndRemembersFirstAuthentication —
// вход выдаёт сессию: уровень «1» по правилу, срок = выдача + 24 ч, адрес в
// любом регистре, событие выдачи, память первой аутентификации.
func TestLogin_F3_01_IssuesASessionWithLevelOneAndRemembersFirstAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "Ann@Example.invalid", "correct horse battery", true)

	out := h.mustLogin(t, "ann@example.INVALID", "correct horse battery")
	require.Equal(t, u.ID, out.View.User.ID)
	require.Equal(t, "1", out.View.Session.AssuranceLevel, "Ф11: пароль → «1» по правилу")
	require.Equal(t, []string{"password"}, out.View.Session.PresentedMethods)
	require.True(t, out.View.Session.ExpiresAt.Equal(ucBase.Add(ucTTL)), "срок — момент выдачи плюс 24 ч")
	require.True(t, out.View.Session.AuthenticatedAt.Equal(ucBase))
	require.True(t, out.View.EmailVerified)
	require.False(t, out.View.Session.PasswordChangeRequired)
	require.False(t, out.Bearer.IsZero())
	require.Len(t, h.store.audit, 1)
	require.Equal(t, humansession.AuditSessionIssued, h.store.audit[0].EventType)
	require.NotContains(t, h.store.audit[0].Payload, "email", "без адреса в событии")
	first, ok := h.store.first[u.ID]
	require.True(t, ok)
	require.True(t, first.Equal(ucBase), "Р5: память первой аутентификации")
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeIssued])
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteNotNeeded], "значение уже объявленного формата не переписывается")

	view, found, err := h.resolve.Execute(context.Background(), out.Bearer)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, out.View.Session.ID, view.Session.ID)
}

// TestLogin_F3_02_OneRefusalForEveryCause — неверный пароль, адреса нет,
// материала нет, заблокирована, негодный материал — один и тот же отказ;
// различимость — только клетками; каждый отказ считается попыткой; положительный
// контроль — верный пароль после неверного проходит.
func TestLogin_F3_02_OneRefusalForEveryCause(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	h.person(t, "usr-c", "c@example.invalid", "", true)
	d := h.person(t, "usr-d", "d@example.invalid", "correct horse battery", true)
	d.InviteStatus = domain.InviteStatusBlocked
	h.store.users[d.ID] = d
	e := h.person(t, "usr-e", "e@example.invalid", "", true)
	v, err := domain.NewLoginVerifier("$pbkdf2$not-in-registry")
	require.NoError(t, err)
	h.store.verifiers[e.ID] = v

	cases := []struct {
		email, password string
		outcome         humansession.LoginOutcome
	}{
		{"a@example.invalid", "wrong", humansession.LoginOutcomeMismatched},
		{"b@example.invalid", "whatever", humansession.LoginOutcomeNoRow},
		{"c@example.invalid", "whatever", humansession.LoginOutcomeMaterialNone},
		{"d@example.invalid", "correct horse battery", humansession.LoginOutcomeBlocked},
		{"e@example.invalid", "whatever", humansession.LoginOutcomeVerifierIssue},
	}
	for i, c := range cases {
		// Источники разные: ось источника считает своё (Ф1-08), а предмет пробы — ось адреса.
		source := "203.0.113." + string(rune('1'+i))
		_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: c.email, Password: c.password, Source: source})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, c.email)
		require.Equal(t, humansession.TextAuthenticationFailed, err.Error(), "один текст на все причины")
		require.Equal(t, 1, h.obs.login[c.outcome], "клетка %s", c.outcome)
	}
	require.Len(t, h.store.failures, 2*len(cases), "каждый отказ — попытка по адресу и по источнику")
	require.Zero(t, len(h.store.audit), "отказ ничего не выдал")

	out := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	require.False(t, out.Bearer.IsZero(), "F4d-16: верный пароль после неверного проходит")
}

// TestLogin_F3_03_UnverifiedAddressStillSignsIn — адрес не подтверждён: вход
// состоится, ответ это называет.
func TestLogin_F3_03_UnverifiedAddressStillSignsIn(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", false)
	out := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	require.False(t, out.View.EmailVerified, "Ф1-06: emailVerified=false")
}

// TestLogin_F3_04_MigratedBcryptIsRewrittenAfterMatch — перенесённое значение
// прежнего формата входит прежним паролем и переписывается после «совпал»;
// неверный пароль не переписывает; 72 байта и нулевой байт — не переписываются
// и сосчитаны по причине (PWV-08, PWV-19).
func TestLogin_F3_04_MigratedBcryptIsRewrittenAfterMatch(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-m", "m@example.invalid", "", true)
	// bcrypt, стоимость 4 — читаемый, ниже потолка; синтетика пробы.
	bcryptOf := func(pw string) domain.LoginVerifier {
		v, err := domain.NewLoginVerifier(bcryptHash(t, pw))
		require.NoError(t, err)
		return v
	}
	h.store.verifiers[u.ID] = bcryptOf("old password 1")

	_, err := h.login.Execute(context.Background(), humansession.LoginInput{Email: "m@example.invalid", Password: "not it"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.True(t, strings.HasPrefix(h.store.verifiers[u.ID].Reveal(), "$2a$"), "PWV-08.7: неверный пароль не переписал")

	out := h.mustLogin(t, "m@example.invalid", "old password 1")
	require.False(t, out.View.Session.PasswordChangeRequired, "PWV-01.2: требования смены нет")
	require.True(t, strings.HasPrefix(h.store.verifiers[u.ID].Reveal(), "$argon2id$"), "PWV-08.2: значение несёт объявленный формат")
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteDone])
	h.mustLogin(t, "m@example.invalid", "old password 1")
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteNotNeeded], "PWV-08.3: повторный вход тем же паролем проходит и не переписывает")

	long := strings.Repeat("x", 72)
	h.store.verifiers[u.ID] = bcryptOf(long)
	h.mustLogin(t, "m@example.invalid", long)
	require.True(t, strings.HasPrefix(h.store.verifiers[u.ID].Reveal(), "$2a$"), "PWV-19: 72 байта — не переписывается")
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteSkippedLong72])

	withNul := "pass\x00word-rest"
	h.store.verifiers[u.ID] = bcryptOf(withNul)
	h.mustLogin(t, "m@example.invalid", withNul)
	require.True(t, strings.HasPrefix(h.store.verifiers[u.ID].Reveal(), "$2a$"), "PWV-19: нулевой байт — не переписывается")
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteSkippedNulByte])

	// Отказ записи замещения: вход состоялся, значение прежнее, клетка выросла.
	h.store.verifiers[u.ID] = bcryptOf("old password 1")
	h.store.failOn = "replace"
	out = h.mustLogin(t, "m@example.invalid", "old password 1")
	require.False(t, out.Bearer.IsZero(), "PWV-09.1: вход состоялся при отказе замещения")
	require.True(t, strings.HasPrefix(h.store.verifiers[u.ID].Reveal(), "$2a$"))
	require.Equal(t, 1, h.obs.rewrit[humansession.RewriteWriteFailed])
	h.store.failOn = ""
	h.mustLogin(t, "m@example.invalid", "old password 1")
	require.Equal(t, 2, h.obs.rewrit[humansession.RewriteDone], "PWV-09.4: следующий вход повторяет")
}

// TestLogin_F3_28_SourceAxisSilenceIsCounted — вопрос без адреса источника не
// молчит: клетка «источник неизвестен» растёт, ось адреса при этом судится;
// с адресом клетка не растёт.
func TestLogin_F3_28_SourceAxisSilenceIsCounted(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	_, err := h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "wrong", Source: "203.0.113.9"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Zero(t, h.obs.sourceUnknown, "с адресом источника клетка не растёт")
	_, err = h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "wrong"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.obs.sourceUnknown, "без адреса — ровно один вопрос сосчитан")
}

// TestLogin_F3_28_RateLimitByAddressAndSource — N неверных по адресу → отказ по
// частоте на N+1-й, побайтово равный для адреса, которого нет; регистр не
// удваивает окно; после окна проходит; успешный вход обнуляет счёт; по источнику
// — свой счёт.
func TestLogin_F3_28_RateLimitByAddressAndSource(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	fail := func(email, source string) error {
		_, err := h.login.Execute(ctx, humansession.LoginInput{Email: email, Password: "wrong", Source: source})
		return err
	}
	for i := 0; i < 3; i++ {
		spelled := []string{"a@example.invalid", "A@Example.invalid", "a@EXAMPLE.invalid"}[i]
		require.ErrorIs(t, fail(spelled, "203.0.113.7"), humansession.ErrAuthenticationFailed)
	}
	err := fail("a@example.invalid", "203.0.113.7")
	var tma *humansession.TooManyAttemptsError
	require.ErrorAs(t, err, &tma, "Ф1-07: N+1-я — отказ по частоте (регистр не удвоил окно)")
	require.Equal(t, humansession.FailureByAddress, tma.Scope)
	require.Equal(t, 10*time.Minute, tma.RetryAfter, "до конца окна: первый след в t0")
	require.Equal(t, humansession.TextTooManyAttempts, err.Error())

	for i := 0; i < 3; i++ {
		require.ErrorIs(t, fail("nobody@example.invalid", "198.51.100.1"), humansession.ErrAuthenticationFailed)
	}
	err2 := fail("nobody@example.invalid", "198.51.100.1")
	require.ErrorAs(t, err2, &tma)
	require.Equal(t, err.Error(), err2.Error(), "отказ для адреса, которого нет, равен отказу для адреса, который есть")
	require.Equal(t, 2, h.obs.rate[humansession.FailureByAddress])

	// После окна — верный пароль проходит и обнуляет счёт по адресу.
	h.clock = ucBase.Add(10*time.Minute + time.Second)
	out := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	require.False(t, out.Bearer.IsZero())
	n, _ := h.store.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Zero(t, n, "успешный вход обнуляет счёт по адресу")

	// По источнику: 5 разных адресов с одного источника → шестая любая — отказ.
	h.clock = ucBase.Add(time.Hour)
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, fail("u"+string(rune('0'+i))+"@example.invalid", "192.0.2.9"), humansession.ErrAuthenticationFailed)
	}
	err = fail("zz@example.invalid", "192.0.2.9")
	require.ErrorAs(t, err, &tma)
	require.Equal(t, humansession.FailureBySource, tma.Scope, "Ф1-08: по источнику")
	require.ErrorIs(t, fail("zz@example.invalid", "192.0.2.10"), humansession.ErrAuthenticationFailed, "второй источник не задет")
}

// TestLogin_F3_30_WhatIsNotAnAttempt — отказ по частоте и исчерпание ёмкости
// попыткой не считаются; ниже предела верный пароль проходит без отказа.
func TestLogin_F3_30_WhatIsNotAnAttempt(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, err := h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "wrong"})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	}
	// Исчерпание ёмкости: занять все 4 места блокирующим проверяющим.
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	var busy sync.WaitGroup
	for i := 0; i < 4; i++ {
		busy.Add(1)
		go func() {
			defer busy.Done()
			h.verifier.WithCapacity(func() { started <- struct{}{}; <-release })
		}()
	}
	for i := 0; i < 4; i++ {
		<-started
	}
	_, err := h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "correct horse battery"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "наружу — тот же 401")
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeCapacity])
	close(release)
	busy.Wait()
	n, _ := h.store.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Equal(t, 2, n, "PWV-15.3: исчерпание ёмкости попыткой не считается")
	out := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	require.False(t, out.Bearer.IsZero(), "N−1 неверных плюс не-попытки — верный проходит")
}

// TestLogout_F3_15_16_EndsOwnSessionWritesCutoffBeforeFirstAuthentication —
// выход гасит свою запись, вторая жива; отсечка = первая аутентификация − 1 µs
// с причиной logout и актором-человеком; событие; второй выход ничего не пишет.
func TestLogout_F3_15_16_EndsOwnSessionWritesCutoffBeforeFirstAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	s1 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	h.clock = ucBase.Add(time.Minute)
	s2 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	ctx := context.Background()
	auditBefore := len(h.store.audit)

	h.clock = ucBase.Add(time.Hour)
	ended, err := h.logout.Execute(ctx, s2.Bearer)
	require.NoError(t, err)
	require.True(t, ended)
	_, found, _ := h.resolve.Execute(ctx, s2.Bearer)
	require.False(t, found, "Ф1-14: сохранённая копия после выхода — «сессии нет»")
	_, found, _ = h.resolve.Execute(ctx, s1.Bearer)
	require.True(t, found, "Ф1-64: ранняя годна после выхода из поздней")
	cut := h.store.cutoffs[u.ID]
	require.True(t, cut.at.Equal(ucBase.Add(-time.Microsecond)), "Ф3-16: t₁ − 1 µs, не t₂ и не момент выхода: %s", cut.at)
	require.Equal(t, domain.RevokeReasonLogout, cut.reason)
	require.Equal(t, u.ID, cut.actor)
	require.Len(t, h.store.audit, auditBefore+1)
	require.Equal(t, humansession.AuditSessionLoggedOut, h.store.audit[auditBefore].EventType)

	ended, err = h.logout.Execute(ctx, s2.Bearer)
	require.NoError(t, err)
	require.False(t, ended, "Ф1-18: второй выход ничего не пишет")
	require.Len(t, h.store.audit, auditBefore+1)
	require.Equal(t, 2, h.obs.noSess[humansession.NoSessionEnded], "клетка «снята»: резолв копии и второй выход")

	ended, err = h.logout.Execute(ctx, domain.PresentedSessionBearer("nobody-knows-this"))
	require.NoError(t, err)
	require.False(t, ended, "Ф3-18: неизвестный носитель — тот же исход, записей нет")
	ended, err = h.logout.Execute(ctx, domain.SessionBearer{})
	require.NoError(t, err)
	require.False(t, ended, "Ф3-18: без носителя")
}

// TestLogout_F3_16_ThreeRecordsAreOneOutcome — подставной отказ любой из трёх
// записей не оставляет ни одной (Ф1 §4.2); хранилище недоступно — ErrStoreUnavailable.
func TestLogout_F3_16_ThreeRecordsAreOneOutcome(t *testing.T) {
	for _, op := range []string{"end", "cutoff", "audit", "commit", "writer"} {
		t.Run(op, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
			s := h.mustLogin(t, "a@example.invalid", "correct horse battery")
			h.store.failOn = op
			_, err := h.logout.Execute(context.Background(), s.Bearer)
			require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
			h.store.failOn = ""
			_, found, _ := h.resolve.Execute(context.Background(), s.Bearer)
			require.True(t, found, "запись не снята при отказе %s", op)
			_, hasCutoff := h.store.cutoffs[u.ID]
			require.False(t, hasCutoff, "отсечки нет при отказе %s", op)
			require.Equal(t, 1, h.obs.logout)
		})
	}
}

// TestLogout_F3_16_CutoffKeepsAStandingAdminRecord — замок Ф1-63: стоящая
// отсечка администратора t꜀ > t₁, сессии позже неё, выход из одной — момент,
// причина и актор прежние.
func TestLogout_F3_16_CutoffKeepsAStandingAdminRecord(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	h.mustLogin(t, "a@example.invalid", "correct horse battery") // t₁
	tc := ucBase.Add(time.Hour)
	h.store.cutoffs[u.ID] = fakeCutoff{at: tc, reason: "admin-force-logout", actor: "usr-admin"}
	h.clock = tc.Add(time.Minute)
	s3 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	h.clock = tc.Add(2 * time.Minute)
	s4 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	_, err := h.logout.Execute(context.Background(), s3.Bearer)
	require.NoError(t, err)
	_, found, _ := h.resolve.Execute(context.Background(), s4.Bearer)
	require.True(t, found, "S4 годна")
	cut := h.store.cutoffs[u.ID]
	require.True(t, cut.at.Equal(tc))
	require.Equal(t, "admin-force-logout", cut.reason, "Ф1-63: отброшенный момент причины не переносит")
	require.Equal(t, domain.UserID("usr-admin"), cut.actor)
}

// TestChangePassword_F3_19_21_FourRecordsOneOutcome — смена из S2 при S1<S2<S3:
// прочие сняты, S2 жива с прежним моментом, носитель перевыпущен, прежний пароль
// негоден, отсечка та же, что у выхода, с причиной password-change, событие.
func TestChangePassword_F3_19_21_FourRecordsOneOutcome(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	s1 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	h.clock = ucBase.Add(time.Minute)
	s2 := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	h.clock = ucBase.Add(2 * time.Minute)
	s3 := h.mustLogin(t, "a@example.invalid", "correct horse battery")

	h.clock = ucBase.Add(time.Hour)
	out, err := h.change.Execute(ctx, humansession.ChangePasswordInput{
		Bearer: s2.Bearer, CurrentPassword: "correct horse battery", NewPassword: "brand new passphrase", Source: "203.0.113.7",
	})
	require.NoError(t, err)
	require.False(t, out.Bearer.IsZero())
	require.NotEqual(t, s2.Bearer.CookieValue(), out.Bearer.CookieValue(), "носитель перевыпущен")
	require.True(t, out.View.Session.AuthenticatedAt.Equal(ucBase.Add(time.Minute)), "момент аутентификации прежний")
	require.True(t, out.View.Session.LastPresentedAt.Equal(h.clock), "момент последнего предъявления сдвинут")
	require.Equal(t, "1", out.View.Session.AssuranceLevel, "уровень пересчитан правилом")

	_, found, _ := h.resolve.Execute(ctx, s2.Bearer)
	require.False(t, found, "прежний носитель S2 — «сессии нет»")
	_, found, _ = h.resolve.Execute(ctx, out.Bearer)
	require.True(t, found, "новый носитель — та же сессия")
	_, found, _ = h.resolve.Execute(ctx, s1.Bearer)
	require.False(t, found, "Ф1-65: S1 снята")
	_, found, _ = h.resolve.Execute(ctx, s3.Bearer)
	require.False(t, found, "Ф1-65: S3 снята")

	cut := h.store.cutoffs[u.ID]
	require.True(t, cut.at.Equal(ucBase.Add(-time.Microsecond)), "Ф1-66: та же отсечка, что писал бы выход")
	require.Equal(t, domain.RevokeReasonPasswordChange, cut.reason)
	require.Equal(t, u.ID, cut.actor)
	require.Equal(t, humansession.AuditPasswordChanged, h.store.audit[len(h.store.audit)-1].EventType)

	_, err = h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "correct horse battery"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "F4d-19: прежний пароль негоден")
	h.mustLogin(t, "a@example.invalid", "brand new passphrase")
}

// TestChangePassword_F3_20_TwoRefusalsAndTheAttemptCount — без подтверждения —
// поле; неверное — тот же отказ, что на входе, и оно считается попыткой; без
// носителя — тот же отказ и не считается; материал не изменён.
func TestChangePassword_F3_20_TwoRefusalsAndTheAttemptCount(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	s := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	before := h.store.verifiers[u.ID].Reveal()

	_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, NewPassword: "brand new passphrase"})
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "currentPassword", fe.Field, "(а) поле названо")

	_, err = h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "wrong", NewPassword: "brand new passphrase", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "(б) тот же текст, что на входе")
	require.Equal(t, humansession.TextAuthenticationFailed, err.Error())
	n, _ := h.store.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Equal(t, 1, n, "(б) считается попыткой")

	_, err = h.change.Execute(ctx, humansession.ChangePasswordInput{CurrentPassword: "correct horse battery", NewPassword: "brand new passphrase"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "(в) без носителя")
	n, _ = h.store.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", time.Time{})
	require.Equal(t, 1, n, "(в) не считается")
	require.Equal(t, before, h.store.verifiers[u.ID].Reveal(), "материал не изменён")
	_, found, _ := h.resolve.Execute(ctx, s.Bearer)
	require.True(t, found, "носитель не перевыпущен")

	// N−1 неверных входов плюс одно неподошедшее подтверждение → отказ по частоте.
	for i := 0; i < 1; i++ {
		_, err = h.login.Execute(ctx, humansession.LoginInput{Email: "a@example.invalid", Password: "wrong", Source: "203.0.113.7"})
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	}
	_, err = h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "wrong", NewPassword: "brand new passphrase", Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	_, err = h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "correct horse battery", NewPassword: "brand new passphrase", Source: "203.0.113.7"})
	var tma *humansession.TooManyAttemptsError
	require.ErrorAs(t, err, &tma, "смена — не обход счётчика входа (F4d-19)")
}

// TestChangePassword_F3_22_NewPasswordIsJudgedByTheOneRule — короче длины,
// схож с адресом, в базе утечек — отказ называет поле и правило; годный принят.
func TestChangePassword_F3_22_NewPasswordIsJudgedByTheOneRule(t *testing.T) {
	breach := &fakeBreach{found: map[string]bool{"password123456": true}}
	h := newHarness(t, breach)
	u := h.person(t, "usr-a", "annabelle@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	s := h.mustLogin(t, "annabelle@example.invalid", "correct horse battery")
	before := h.store.verifiers[u.ID].Reveal()

	for _, c := range []struct{ pw, rule string }{
		{"short1", humansession.RuleTooShort},
		{"xxannabellexx", humansession.RuleResemblesEmail},
		{"password123456", humansession.RuleBreached},
	} {
		_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "correct horse battery", NewPassword: c.pw})
		var fe *humansession.FieldError
		require.ErrorAs(t, err, &fe, c.pw)
		require.Equal(t, "newPassword", fe.Field)
		require.Equal(t, c.rule, fe.Rule)
		require.NotContains(t, err.Error(), "1", "число утечек не раскрывается")
	}
	require.Equal(t, before, h.store.verifiers[u.ID].Reveal(), "материал не изменён")
	require.Equal(t, 1, h.obs.breach[humansession.BreachCheckFound])

	_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "correct horse battery", NewPassword: "a clean passphrase"})
	require.NoError(t, err, "Ф1-38: годный принят")
	require.Equal(t, 1, h.obs.breach[humansession.BreachCheckClean])
}

// TestPasswordRule_F3_34_UnavailableAuthorityPassesLoudlyMisconfiguredRefuses —
// авторитет недоступен — принят, клетка выросла; настроен не туда — отказ.
func TestPasswordRule_F3_34_UnavailableAuthorityPassesLoudlyMisconfiguredRefuses(t *testing.T) {
	breach := &fakeBreach{err: humansession.ErrBreachAuthorityUnavailable}
	h := newHarness(t, breach)
	h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	s := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	out, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: s.Bearer, CurrentPassword: "correct horse battery", NewPassword: "a clean passphrase"})
	require.NoError(t, err, "Ф1-35: проход громко")
	require.Equal(t, 1, h.obs.breach[humansession.BreachCheckUnavailable])

	breach.err = humansession.ErrBreachAuthorityMisconfigured
	_, err = h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: out.Bearer, CurrentPassword: "a clean passphrase", NewPassword: "another clean passphrase"})
	require.ErrorIs(t, err, humansession.ErrBreachAuthorityMisconfigured, "настроен не туда — отказ, не проход")
	require.Equal(t, 1, h.obs.breach[humansession.BreachCheckMisconfigured])
}

// TestChangePassword_F3_20_FiveRecordsAreOneOutcome — подставной отказ ЛЮБОЙ из
// записей смены пароля (замещение материала, снятие прочих сессий, отсечка,
// ротация носителя, снятие требования, аудит, фиксация) не оставляет ни одной:
// материал прежний, прочие сессии живы, отсечки нет, носитель прежний, требование
// стоит; наружу — ErrStoreUnavailable (Р6, Ф3-20 «д»).
func TestChangePassword_F3_20_FiveRecordsAreOneOutcome(t *testing.T) {
	for _, op := range []string{"replace", "end-others", "cutoff", "rotate", "clear-requirement", "audit", "commit", "writer"} {
		t.Run(op, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
			ctx := context.Background()
			other := h.mustLogin(t, "a@example.invalid", "correct horse battery") // прочая сессия
			rb, _ := domain.NewSessionBearer()
			r := domain.HumanSession{ID: "hss-r", UserID: u.ID, AuthenticatedAt: ucBase, LastPresentedAt: ucBase,
				ExpiresAt: ucBase.Add(ucTTL), AssuranceLevel: "1", PresentedMethods: []string{"recovery_code"}, PasswordChangeRequired: true}
			h.store.rows[r.ID] = &fakeRow{s: r, digest: rb.Digest()}
			before := h.store.verifiers[u.ID].Reveal()

			h.store.failOn = op
			_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: rb, CurrentPassword: "correct horse battery", NewPassword: "a clean passphrase"})
			require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "отказ %s", op)
			h.store.failOn = ""

			require.Equal(t, before, h.store.verifiers[u.ID].Reveal(), "материал не замещён при отказе %s", op)
			_, found, _ := h.resolve.Execute(ctx, other.Bearer)
			require.True(t, found, "прочая сессия жива при отказе %s", op)
			_, hasCutoff := h.store.cutoffs[u.ID]
			require.False(t, hasCutoff, "отсечки нет при отказе %s", op)
			view, found, _ := h.resolve.Execute(ctx, rb)
			require.True(t, found, "носитель не ротирован при отказе %s", op)
			require.True(t, view.Session.PasswordChangeRequired, "требование стоит при отказе %s", op)
			for _, ev := range h.store.audit {
				require.NotEqual(t, humansession.AuditPasswordChanged, ev.EventType, "события смены нет при отказе %s", op)
			}
		})
	}
}

// TestChangePassword_F3_23_ClearsTheRequirementAndKeepsOthersUntouched —
// сессия восстановления с требованием: смена снимает поле; вход паролем с тем
// же носителем в заголовке выдаёт новую сессию БЕЗ требования, запись R не тронута.
func TestChangePassword_F3_23_ClearsTheRequirementAndKeepsOthersUntouched(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	// Посев записи с требованием (Ф5-03 сквозным путём — Ф5).
	rb, _ := domain.NewSessionBearer()
	r := domain.HumanSession{ID: "hss-r", UserID: u.ID, AuthenticatedAt: ucBase, LastPresentedAt: ucBase,
		ExpiresAt: ucBase.Add(ucTTL), AssuranceLevel: "1", PresentedMethods: []string{"recovery_code"}, PasswordChangeRequired: true}
	h.store.rows[r.ID] = &fakeRow{s: r, digest: rb.Digest()}

	view, found, err := h.resolve.Execute(ctx, rb)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, view.Session.PasswordChangeRequired, "«кто я» видит требование")

	l := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	require.False(t, l.View.Session.PasswordChangeRequired, "вход даёт новую сессию без требования")
	view, _, _ = h.resolve.Execute(ctx, rb)
	require.True(t, view.Session.PasswordChangeRequired, "запись R не тронута входом")

	out, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: rb, CurrentPassword: "correct horse battery", NewPassword: "a clean passphrase"})
	require.NoError(t, err)
	require.False(t, out.View.Session.PasswordChangeRequired, "Ф5-24: поле снято")
	view, found, _ = h.resolve.Execute(ctx, out.Bearer)
	require.True(t, found)
	require.False(t, view.Session.PasswordChangeRequired)
}

// TestResolve_F3_10_OneAnswerForFourReasons — неизвестный, снятый, истёкший,
// заблокированный — found=false; причины — только в клетках.
func TestResolve_F3_10_OneAnswerForFourReasons(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	ended := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	_, err := h.logout.Execute(ctx, ended.Bearer)
	require.NoError(t, err)
	expired := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	h.clock = ucBase.Add(ucTTL + time.Second)
	live := h.mustLogin(t, "a@example.invalid", "correct horse battery")

	_, found, _ := h.resolve.Execute(ctx, domain.PresentedSessionBearer("unknown"))
	require.False(t, found)
	_, found, _ = h.resolve.Execute(ctx, ended.Bearer)
	require.False(t, found)
	_, found, _ = h.resolve.Execute(ctx, expired.Bearer)
	require.False(t, found)
	u.InviteStatus = domain.InviteStatusBlocked
	h.store.users[u.ID] = u
	_, found, _ = h.resolve.Execute(ctx, live.Bearer)
	require.False(t, found, "Ф3-10 N4")
	u.InviteStatus = domain.InviteStatusActive
	h.store.users[u.ID] = u
	view, found, _ := h.resolve.Execute(ctx, live.Bearer)
	require.True(t, found, "положительный контроль")
	require.Equal(t, u.ID, view.User.ID)
	for _, r := range humansession.NoSessionReasons() {
		require.Equal(t, 1, h.obs.noSess[r], "клетка %s", r)
	}
	h.store.failOn = "resolve"
	_, _, err = h.resolve.Execute(ctx, live.Bearer)
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
}

// TestFormToken_F3_35_40_ContextAndKind — признак привязан к контексту и виду:
// свой проходит, чужой контекст и чужой вид дают один отказ, отсутствие —
// поле; из признака не читается контекст.
func TestFormToken_F3_35_40_ContextAndKind(t *testing.T) {
	k1, err := humansession.NewFormContext()
	require.NoError(t, err)
	k2, err := humansession.NewFormContext()
	require.NoError(t, err)
	require.NotEqual(t, k1, k2)
	tok := humansession.FormToken(k1, domain.FormPassword)
	require.NoError(t, humansession.JudgeFormToken(k1, domain.FormPassword, tok), "Ф1-42: годный проходит")
	require.ErrorIs(t, humansession.JudgeFormToken(k2, domain.FormPassword, tok), humansession.ErrFormTokenRejected, "Ф1-41: чужой контекст")
	require.ErrorIs(t, humansession.JudgeFormToken(k1, domain.FormLogout, tok), humansession.ErrFormTokenRejected, "Ф1-40: чужой вид")
	require.ErrorIs(t, humansession.JudgeFormToken("", domain.FormPassword, tok), humansession.ErrFormTokenRejected, "контекста нет")
	var fe *humansession.FieldError
	require.ErrorAs(t, humansession.JudgeFormToken(k1, domain.FormPassword, ""), &fe, "Ф1-39: без признака")
	require.Equal(t, "csrfToken", fe.Field)
	require.NotContains(t, tok, k1[:8], "контекст из признака не читается")
	require.Equal(t, humansession.JudgeFormToken(k2, domain.FormPassword, tok).Error(),
		humansession.JudgeFormToken(k1, domain.FormLogout, tok).Error(), "один текст на чужой контекст и чужой вид")
	// Вид вне перечня: значение, которого перечень не несёт by construction.
	// Прежде здесь стояло «register» — с Ф4 это законный вид (форма
	// регистрации), и отрицание на нём перестало бы отрицать.
	_, err = domain.ParseFormKind("no-such-form")
	require.Error(t, err, "вид вне перечня")
}

// fakeBreach — дублёр авторитета утечек.
type fakeBreach struct {
	found map[string]bool
	err   error
}

func (b *fakeBreach) Check(_ context.Context, password string) (humansession.BreachVerdict, error) {
	if b.err != nil {
		return humansession.BreachNotFound, b.err
	}
	if b.found[password] {
		return humansession.BreachFound, nil
	}
	return humansession.BreachNotFound, nil
}

var _ = errors.Is
