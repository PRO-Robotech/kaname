// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// cutoff_clock_test.go — писатели полосы входа ставят моменты, сравниваемые с
// отсечкой отзыва-всех, ОБЩИМ источником, а не часами процесса своей реплики
// (задача kaname#589).
//
// Писатели: вход паролем и вход ключом (момент аутентификации сессии),
// завершение восстановления (отсечка и момент сессии). Часы процесса реплики
// (`Now`) и общий источник (`CutoffClock`) разведены на 37 минут: момент,
// попавший в запись, называет, чьими часами он поставлен.
//
// Каждый случай — пара: проводка корня (общий источник) — момент общего
// источника; инъекция «часы реплики» (тому же писателю подан источник,
// отвечающий часами процесса) — момент реплики. Инъекция обязана дать другой
// момент, иначе проба не различает источник и её зелёное ничего не говорит.
//
// Отказ источника — закрытый: глагол отвечает своим фиксированным отказом «не
// выполнено», ничего не пишет, а журнал называет шаг и класс, но не адрес и не
// текст причины.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// sharedAhead — на сколько общий источник впереди часов процесса реплики.
const sharedAhead = 37 * time.Minute

// clockWiring — как писатель получает источник моментов.
type clockWiring struct {
	name string
	// source строит источник по часам процесса реплики.
	source func(replica func() time.Time) revocationpolicy.Clock
	// shared — ожидается момент общего источника (иначе — момент реплики).
	shared bool
}

func clockWirings() []clockWiring {
	return []clockWiring{
		{name: "проводка корня: общий источник", shared: true, source: func(replica func() time.Time) revocationpolicy.Clock {
			return momentclock.Func(func() time.Time { return replica().Add(sharedAhead) })
		}},
		{name: "инъекция: часы реплики", shared: false, source: func(replica func() time.Time) revocationpolicy.Clock {
			return momentclock.Func(replica)
		}},
	}
}

// wantMoment — какой момент обязан лечь в запись при этой проводке.
func (w clockWiring) wantMoment(replica time.Time) time.Time {
	if w.shared {
		return replica.Add(sharedAhead)
	}
	return replica
}

func TestCutoffClock_PasswordLoginStampsTheSessionFromTheSharedSource(t *testing.T) {
	for _, w := range clockWirings() {
		t.Run(w.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-clk1", "clk1@example.invalid", "correct horse battery", true)
			replica := func() time.Time { return h.clock }
			login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
				Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
				Hasher: h.hasher, Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: replica,
				Logger: slog.New(slog.DiscardHandler), Envelope: h.envelopePort, TOTP: h.totp, Sets: h.verifier,
				CutoffClock: w.source(replica),
			})
			require.NoError(t, err)
			out, err := login.Execute(context.Background(), humansession.LoginInput{
				Email: "clk1@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
			})
			require.NoError(t, err)
			want := w.wantMoment(h.clock)
			require.Truef(t, out.View.Session.AuthenticatedAt.Equal(want),
				"момент сессии %s, ожидался %s", out.View.Session.AuthenticatedAt, want)
			require.True(t, out.View.Session.ExpiresAt.Equal(want.Add(ucTTL)), "срок — от того же момента")
			require.True(t, h.store.first[u.ID].Equal(want), "память первой аутентификации — тот же момент")
		})
	}
}

func TestCutoffClock_RecoveryStampsCutoffAndSessionFromTheSharedSource(t *testing.T) {
	for _, w := range clockWirings() {
		t.Run(w.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-clk2", "clk2@example.invalid", "old-password-2", true)
			h.request(t, "clk2@example.invalid")
			letter := h.letterOf(t, u.ID)
			h.clock = ucBase.Add(time.Minute)
			replica := func() time.Time { return h.clock }
			complete, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
				Store: h.store, Hasher: h.hasher, Rule: h.rule, Limits: limits(), TTL: ucTTL,
				Observer: h.obs, Now: replica, Logger: slog.New(slog.DiscardHandler),
				CutoffClock: w.source(replica),
			})
			require.NoError(t, err)
			out, err := complete.Execute(context.Background(), humansession.CompleteRecoveryInput{
				Email: "clk2@example.invalid", Code: letter, NewPassword: "brand-new-password-2", Source: "203.0.113.7",
			})
			require.NoError(t, err)
			want := w.wantMoment(h.clock)
			require.Truef(t, h.store.cutoffs[u.ID].at.Equal(want), "отсечка %s, ожидалась %s", h.store.cutoffs[u.ID].at, want)
			require.Truef(t, out.View.Session.AuthenticatedAt.Equal(want.Add(time.Microsecond)),
				"момент сессии %s, ожидался %s + 1 мкс", out.View.Session.AuthenticatedAt, want)
		})
	}
}

// akStore — дублёр хранилища входа ключом: одно испытание, один ключ, один
// человек. Не снисходительнее настоящего: испытание однократно и привязано к
// контексту, счётчик сдвигается только с прежнего значения.
type akStore struct {
	challenge []byte
	form      string
	key       domain.AccessKey
	user      domain.User
}

func (s *akStore) IssueChallenge(_ context.Context, c domain.AccessKeyLoginChallenge, _ time.Duration) error {
	s.challenge, s.form = append([]byte(nil), c.Challenge...), c.FormContext
	return nil
}

func (s *akStore) ConsumeChallenge(_ context.Context, challenge []byte, form string) (bool, error) {
	if s.challenge == nil || form != s.form || !bytes.Equal(challenge, s.challenge) {
		return false, nil
	}
	s.challenge = nil
	return true, nil
}

func (s *akStore) KeyByCredentialID(_ context.Context, id []byte) (domain.AccessKey, bool, error) {
	if !bytes.Equal(id, s.key.CredentialID) {
		return domain.AccessKey{}, false, nil
	}
	return s.key, true, nil
}

func (s *akStore) AdvanceSignCount(_ context.Context, _ domain.AccessKeyID, expected, reported uint32, _ time.Time) (bool, error) {
	if s.key.SignCount != expected {
		return false, nil
	}
	s.key.SignCount = reported
	return true, nil
}

func (s *akStore) UserOf(context.Context, domain.UserID) (domain.User, error) { return s.user, nil }

const (
	clkRPID   = "console.example.invalid"
	clkOrigin = "https://console.example.invalid"
)

func TestCutoffClock_AccessKeyLoginStampsTheSessionFromTheSharedSource(t *testing.T) {
	for _, w := range clockWirings() {
		t.Run(w.name, func(t *testing.T) {
			h := newHarness(t, nil)
			u := h.person(t, "usr-clk3", "clk3@example.invalid", "", true)
			auth := webauthntest.New(t, webauthntest.AlgES256)
			handle := bytes.Repeat([]byte{3}, 64)
			keys := &akStore{user: u, key: domain.AccessKey{
				ID: "ak-clk3", UserID: u.ID, CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t),
				Algorithm: auth.Algorithm(), UserHandle: handle,
			}}
			replica := func() time.Time { return h.clock }
			deps := humansession.AccessKeyLoginDeps{
				Store: h.store, Keys: keys, Methods: fakeMethods{h.store},
				Binding: webauthnverify.Binding{RPID: clkRPID, Origins: []string{clkOrigin},
					Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
				ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
				Limits: limits(), TTL: ucTTL, Observer: humansession.NopObserver{}, Now: replica,
				Logger: slog.New(slog.DiscardHandler), CutoffClock: w.source(replica),
			}
			begin, err := humansession.NewBeginAccessKeyLoginUseCase(deps)
			require.NoError(t, err)
			login, err := humansession.NewAccessKeyLoginUseCase(deps)
			require.NoError(t, err)
			form, err := humansession.NewFormContext()
			require.NoError(t, err)
			ctx := context.Background()
			ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: "203.0.113.7"})
			require.NoError(t, err)
			as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: clkOrigin, RPID: clkRPID})
			out, err := login.Execute(ctx, humansession.AccessKeyLoginInput{
				FormContext: form, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
				AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: handle, Source: "203.0.113.7",
			})
			require.NoError(t, err)
			want := w.wantMoment(h.clock)
			require.Truef(t, out.View.Session.AuthenticatedAt.Equal(want),
				"момент сессии %s, ожидался %s", out.View.Session.AuthenticatedAt, want)
		})
	}
}

// TestCutoffClock_EveryWriterRefusesToBuildWithoutTheSource — полоса без
// источника не собирается: часы процесса реплики — тот второй источник,
// который снят, и умолчания к ним нет.
func TestCutoffClock_EveryWriterRefusesToBuildWithoutTheSource(t *testing.T) {
	h := newHarness(t, nil)
	logger := slog.New(slog.DiscardHandler)
	_, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: limits(), TTL: ucTTL, Logger: logger, Envelope: h.envelopePort, TOTP: h.totp, Sets: h.verifier,
	})
	require.ErrorContains(t, err, "shared clock required")
	_, err = humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		Store: h.store, Hasher: h.hasher, Rule: h.rule, Limits: limits(), TTL: ucTTL, Logger: logger,
	})
	require.ErrorContains(t, err, "shared clock required")
	_, err = humansession.NewAccessKeyLoginUseCase(humansession.AccessKeyLoginDeps{
		Store: h.store, Keys: &akStore{}, Methods: fakeMethods{h.store},
		Binding: webauthnverify.Binding{RPID: clkRPID, Origins: []string{clkOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
		Limits: limits(), TTL: ucTTL, Logger: logger,
	})
	require.ErrorContains(t, err, "shared clock required")
}

// TestCutoffClock_UnansweredSourceIsAClosedRefusal — источник не ответил:
// вход отвечает фиксированным «не выполнено», сессии нет, попытка не
// записана как успех; журнал называет шаг и класс, не адрес и не текст причины.
func TestCutoffClock_UnansweredSourceIsAClosedRefusal(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-clk4", "clk4@example.invalid", "correct horse battery", true)
	var logBuf bytes.Buffer
	cause := errors.New("dial tcp 10.0.0.9:5432: connect: connection refused (user=kaname)")
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: func() time.Time { return h.clock },
		Logger: slog.New(slog.NewTextHandler(&logBuf, nil)), Envelope: h.envelopePort, TOTP: h.totp, Sets: h.verifier,
		CutoffClock: momentclock.Failing{Err: cause},
	})
	require.NoError(t, err)
	_, err = login.Execute(context.Background(), humansession.LoginInput{
		Email: "clk4@example.invalid", Password: "correct horse battery", Source: "203.0.113.7",
	})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.Equal(t, "store unavailable", err.Error(), "текст отказа фиксирован и не несёт причины")
	require.Empty(t, h.store.rows, "сессия не выдана")
	_, remembered := h.store.first[u.ID]
	require.False(t, remembered, "память первой аутентификации не записана")
	logged := logBuf.String()
	require.Contains(t, logged, "step=shared-moment", "журнал называет шаг")
	require.Contains(t, logged, "class=store", "журнал называет класс")
	require.NotContains(t, logged, "clk4@example.invalid", "в журнале нет адреса")
	require.NotContains(t, logged, "10.0.0.9", "в журнале нет текста причины")
	require.NotContains(t, logged, "user=kaname", "в журнале нет текста причины")
}
