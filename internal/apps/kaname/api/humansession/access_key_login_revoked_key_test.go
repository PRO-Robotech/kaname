// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// access_key_login_revoked_key_test.go — выдача входа ключом судит
// существование ключа САМА, после захвата личности (kaname#669, Р8, Р15).
// Строка ключа прочитана входом раньше и своим чтением; здесь её снимают
// между чтением и выдачей — дублёр хранилища держит строки ключей так же, как
// адаптер: транзакция выдачи берёт строку под замком и при её отсутствии
// отвечает NOT_FOUND. Межтранзакционное чередование на настоящей базе —
// `internal/handler/loginlanehttp/access_key_revoke_during_login_integration_test.go`.

import (
	"bytes"
	"context"
	"log/slog"
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

// loginWithKeyRow — вход ключом над дублёрами; seeded — лежит ли строка ключа
// в хранилище транзакции выдачи (снята ли она после чтения входом).
func loginWithKeyRow(t *testing.T, seeded bool) (*harness, domain.User, error) {
	t.Helper()
	h := newHarness(t, nil)
	u := h.person(t, "usr-akrv", "akrv@example.invalid", "", true)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	handle := bytes.Repeat([]byte{5}, 64)
	keys := &akStore{user: u, key: domain.AccessKey{
		ID: "ak-akrv", UserID: u.ID, CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t),
		Algorithm: auth.Algorithm(), UserHandle: handle,
	}}
	if seeded {
		h.store.accessKeyRows[keys.key.ID] = u.ID
	}
	now := func() time.Time { return h.clock }
	deps := humansession.AccessKeyLoginDeps{
		Store: h.store, Keys: keys, Methods: fakeMethods{h.store},
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
	ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: "203.0.113.9"})
	require.NoError(t, err)
	as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: clkOrigin, RPID: clkRPID})
	_, err = login.Execute(ctx, humansession.AccessKeyLoginInput{
		FormContext: form, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: handle, Source: "203.0.113.9",
	})
	return h, u, err
}

// liveRowsOf — живые записи сессии личности в дублёре.
func liveRowsOf(h *harness, user domain.UserID) int {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	n := 0
	for _, r := range h.store.rows {
		if r.s.UserID == user && r.ended == nil {
			n++
		}
	}
	return n
}

func TestAccessKeyLogin_KeyGoneBeforeIssueIsTheUnifiedRefusal(t *testing.T) {
	h, u, err := loginWithKeyRow(t, false)
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed,
		"Р8/Р15: ключ снят после чтения входом — выдача отказывает единым отказом")
	require.Zero(t, liveRowsOf(h, u.ID), "Р8: снятый ключ записи сессии не выдаёт")
}

// Близнец: тот же вход, строка ключа лежит — запись выдана.
func TestAccessKeyLogin_KeyStillThereAtIssueIssuesTheSession(t *testing.T) {
	h, u, err := loginWithKeyRow(t, true)
	require.NoError(t, err)
	require.Equal(t, 1, liveRowsOf(h, u.ID))
}
