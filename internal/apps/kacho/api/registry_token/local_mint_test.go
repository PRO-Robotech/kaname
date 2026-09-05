// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// local_mint_test.go — приземление подписанта на НАСТОЯЩИЙ путь выдачи
// (приёмка F1 §9.1 п. 5).
//
// Подписант без производственного вызывающего есть тот же класс, что снятое
// хранилище без читателя: он выглядит исправным, потому что его пробы зелены.
// Поэтому фаза обязана перевести один контур целиком — тот, обе стороны
// которого наши.
package registry_token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
)

// recordingExchanger — прежний путь выдачи. Пробе он нужен ровно затем, чтобы
// утверждать, что его БОЛЬШЕ НЕ ЗОВУТ: «мы теперь чеканим сами» без этого
// утверждения зелено и на реализации, которая по-прежнему ходит к соседу.
type recordingExchanger struct{ calls int }

func (e *recordingExchanger) Exchange(context.Context, registrytokenuc.ExchangeInput) (registrytokenuc.ExchangeOutput, error) {
	e.calls++
	return registrytokenuc.ExchangeOutput{AccessToken: "from-the-previous-issuer", ExpiresIn: 300}, nil
}

// stubMinter — наш подписант с точки зрения контура выдачи.
type stubMinter struct {
	in  registrytokenuc.MintInput
	err error
}

func (m *stubMinter) MintToken(_ context.Context, in registrytokenuc.MintInput) (registrytokenuc.MintOutput, error) {
	if m.err != nil {
		return registrytokenuc.MintOutput{}, m.err
	}
	m.in = in
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://iam.kacho.local", "sub": in.Subject, "aud": in.Audience,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	raw, _ := tok.SignedString([]byte("proof-only"))
	return registrytokenuc.MintOutput{AccessToken: raw, ExpiresIn: 300}, nil
}

type nopSigner struct{}

func (nopSigner) Sign(registrytokenuc.AssertionInput) (string, error) { return "assertion", nil }

func newUseCase(t *testing.T, minter registrytokenuc.LocalMinter, ex registrytokenuc.TokenExchanger) (*registrytokenuc.IssueRegistryTokenUseCase, string) {
	t.Helper()
	secret, authority := newBasicCredential(t)
	uc := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		AssertionAudience: "https://provider/oauth2/token",
		AllowedAudiences:  []string{"registry.kacho.local"},
		DefaultService:    "registry.kacho.local",
		Anonymous: registrytokenuc.AnonymousIdentity{
			ClientID: "anon-client", KeyID: "anon-kid", PrivateKeyPEM: "anon-pem",
		},
	}, nopSigner{}, ex).WithBasicCredentialResolver(authority)
	if minter != nil {
		uc = uc.WithLocalMinter(minter)
	}
	return uc, secret
}

// TestExecute_MintsWithOurSignerAndStopsCallingThePreviousIssuer — приземление.
func TestExecute_MintsWithOurSignerAndStopsCallingThePreviousIssuer(t *testing.T) {
	ex := &recordingExchanger{}
	minter := &stubMinter{}
	uc, secret := newUseCase(t, minter, ex)

	in := dockerLogin(secret)
	in.Service = "registry.kacho.local"
	out, err := uc.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)
	require.Equal(t, 0, ex.calls, "прежний издатель не должен звучать на переведённом контуре")

	// Субъект токена — ТОТ ЖЕ, что приёмная сторона резолвила до перевода:
	// иначе смена чеканки тихо сменила бы принципала, и запросы отвергались бы
	// уже правами, а не подписью.
	require.Equal(t, dockerSubject, minter.in.Subject)
	require.Equal(t, "registry.kacho.local", minter.in.Audience)

	// Положительный контроль обратной стороны переехал на АНОНИМНЫЙ поток, и
	// это не послабление, а следствие #1143: полоса предъявленного
	// удостоверения к прежнему издателю не ходит НИ ПРИ КАКОЙ настройке —
	// подписывать утверждение нечем, ключевого материала у принимаемого вида
	// не существует. Без этой половины «не зовём» зелено и на контуре, который
	// не зовёт никого.
	legacy, _ := newUseCase(t, nil, ex)
	out, err = legacy.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	require.NoError(t, err)
	require.Equal(t, 1, ex.calls)
	require.Equal(t, "from-the-previous-issuer", out.Token)
}

// TestExecuteAnonymous_MintsWithOurSigner — анонимный путь переводится тем же
// решением: два издателя на ОДНОМ контуре означали бы, что приёмная сторона
// обязана держать обе записи ради одного и того же реестра.
func TestExecuteAnonymous_MintsWithOurSigner(t *testing.T) {
	ex := &recordingExchanger{}
	minter := &stubMinter{}
	uc, _ := newUseCase(t, minter, ex)

	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)
	require.Equal(t, 0, ex.calls)

	// Субъект анонимного токена — тот же идентификатор, который приёмная
	// сторона резолвит в подстановочного принципала.
	require.Equal(t, "anon-client", minter.in.Subject)
	// И запрошенный объём — только чтение: анонимный токен НИКОГДА не просит
	// глагола записи.
	require.Equal(t, registrytokenuc.AnonymousReadScope, minter.in.Scope)
}

// TestExecute_MinterFailureIsFailClosed — отказ нашего подписанта НЕ
// возвращает контур к прежнему издателю: молчаливый откат означал бы, что
// перевод контура снимается сам собой при первой же неисправности.
func TestExecute_MinterFailureIsFailClosed(t *testing.T) {
	ex := &recordingExchanger{}
	uc, secret := newUseCase(t, &stubMinter{err: errors.New("no signing key")}, ex)

	_, err := uc.Execute(context.Background(), dockerLogin(secret))
	require.Error(t, err)
	require.ErrorIs(t, err, registrytokenuc.ErrIssuerUnavailable,
		"неисправность своей чеканки — недоступность издателя, а не негодные учётные данные")
	require.Equal(t, 0, ex.calls, "откат к прежнему издателю при отказе своего — молчаливое снятие перевода")
}
