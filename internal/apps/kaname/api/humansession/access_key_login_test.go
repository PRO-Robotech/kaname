// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// access_key_login_test.go — полоса входа ключом НЕ ЗАВИСИТ от пароля (Ф13
// Р6, инв. 8; задача PRO-Robotech/kaname#787): решение об обнулении счёта по
// адресу полоса принимает, не читая строки способа «пароль», и исход обнуления
// одинаков у личности с паролем и без него.
//
// Счёт ведёт дублёр порта способов входа: он считает чтения по виду строки и
// отвечает тем же, что `fakeMethods`. Дублёр не подменяет решения — он лишь
// видит, о чём полоса спросила.

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// countingMethods — порт способов входа, считающий чтения строки по виду.
type countingMethods struct {
	fakeMethods
	mu    sync.Mutex
	reads map[domain.LoginMethodKind]int
}

func (m *countingMethods) Get(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	m.mu.Lock()
	m.reads[kind]++
	m.mu.Unlock()
	return m.fakeMethods.Get(ctx, userID, kind)
}

func (m *countingMethods) readsOf(kind domain.LoginMethodKind) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads[kind]
}

// keyLoginOutcome — что видно после входа ключом: обнулён ли счёт по адресу и
// сколько раз полоса читала строку пароля.
type keyLoginOutcome struct {
	addressFailuresLeft int
	passwordReads       int
}

// loginWithKeyCountingReads — вход ключом у личности с заведённым ключом и
// неверными предъявлениями по адресу; withPassword — заведён ли у неё пароль.
func loginWithKeyCountingReads(t *testing.T, withPassword bool) keyLoginOutcome {
	t.Helper()
	h := newHarness(t, nil)
	password := ""
	if withPassword {
		password = "correct horse battery"
	}
	u := h.person(t, "usr-akpw", "akpw@example.invalid", password, true)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	handle := bytes.Repeat([]byte{7}, 64)
	keys := &akStore{user: u, key: domain.AccessKey{
		ID: "ak-akpw", UserID: u.ID, CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t),
		Algorithm: auth.Algorithm(), UserHandle: handle,
	}}
	addr := humansession.AddressKey(string(u.Email))
	h.store.mu.Lock()
	h.store.accessKeyRows[keys.key.ID] = u.ID
	h.store.keys[u.ID] = true
	// Неверные предъявления по адресу — до входа и внутри окна счёта.
	for i := 0; i < 2; i++ {
		h.store.failures = append(h.store.failures, fakeFailure{
			scope: humansession.FailureByAddress, key: addr, at: h.clock.Add(-time.Duration(i+1) * time.Minute),
		})
	}
	h.store.mu.Unlock()

	methods := &countingMethods{fakeMethods: fakeMethods{h.store}, reads: map[domain.LoginMethodKind]int{}}
	now := func() time.Time { return h.clock }
	deps := humansession.AccessKeyLoginDeps{
		Store: h.store, Keys: keys, Methods: methods,
		Binding: webauthnverify.Binding{RPID: clkRPID, Origins: []string{clkOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
		Limits: limits(), TTL: ucTTL, Observer: h.obs, Now: now,
		Logger: slog.New(slog.DiscardHandler), CutoffClock: momentclock.Func(now),
	}
	begin, err := humansession.NewBeginAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	login, err := humansession.NewAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	form, err := humansession.NewFormContext()
	require.NoError(t, err)
	ctx := context.Background()
	ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: "203.0.113.11"})
	require.NoError(t, err)
	as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: clkOrigin, RPID: clkRPID})
	out, err := login.Execute(ctx, humansession.AccessKeyLoginInput{
		FormContext: form, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: handle, Source: "203.0.113.11",
	})
	require.NoError(t, err, "вход ключом обязан выдать сессию — иначе об обнулении судить не по чему")
	require.Equal(t, u.ID, out.View.User.ID)

	left, err := h.store.CountFailures(ctx, humansession.FailureByAddress, addr, h.clock.Add(-time.Hour))
	require.NoError(t, err)
	return keyLoginOutcome{addressFailuresLeft: left, passwordReads: methods.readsOf(domain.LoginMethodPassword)}
}

// TestAccessKeyLogin_ResetDecisionDoesNotReadThePassword — Ф13 Р6 и Р9: вход
// ключом обнуляет счёт по адресу у личности С паролем и БЕЗ него одинаково, а
// строку пароля при этом решении не читает ни разу.
func TestAccessKeyLogin_ResetDecisionDoesNotReadThePassword(t *testing.T) {
	withPassword := loginWithKeyCountingReads(t, true)
	withoutPassword := loginWithKeyCountingReads(t, false)

	require.Zero(t, withPassword.addressFailuresLeft,
		"Р9: вход ключом у личности с паролем обязан обнулить счёт по адресу")
	require.Equal(t, withPassword.addressFailuresLeft, withoutPassword.addressFailuresLeft,
		"Р6: исход обнуления зависит от того, заведён ли пароль")
	require.Zero(t, withPassword.passwordReads,
		"Р6: полоса входа ключом прочитала строку пароля (личность с паролем)")
	require.Zero(t, withoutPassword.passwordReads,
		"Р6: полоса входа ключом прочитала строку пароля (личность без пароля)")
}
