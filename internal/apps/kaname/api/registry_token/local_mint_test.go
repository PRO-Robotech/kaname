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

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
)

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
		"iss": "https://kaname.kacho.local", "sub": in.Subject, "aud": in.Audience,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	raw, _ := tok.SignedString([]byte("proof-only"))
	return registrytokenuc.MintOutput{AccessToken: raw, ExpiresIn: 300}, nil
}

// mustLane — полоса на НАШЕЙ чеканке: подписант — обязательный вход
// построителя (kaname#494), и проба, которой нужна собранная полоса, его подаёт.
func mustLane(t *testing.T, cfg registrytokenuc.Config, m registrytokenuc.LocalMinter) *registrytokenuc.IssueRegistryTokenUseCase {
	t.Helper()
	uc, err := registrytokenuc.NewIssueRegistryTokenUseCase(cfg, m)
	require.NoError(t, err, "построитель полосы отказал на исправном входе")
	return uc
}

func newUseCase(t *testing.T, minter registrytokenuc.LocalMinter) (*registrytokenuc.IssueRegistryTokenUseCase, string) {
	t.Helper()
	secret, authority := newBasicCredential(t)
	uc := mustLane(t, registrytokenuc.Config{
		AllowedAudiences: []string{"registry.kacho.local"},
		DefaultService:   "registry.kacho.local",
		Anonymous:        registrytokenuc.AnonymousIdentity{ClientID: "anon-client"},
	}, minter).WithBasicCredentialResolver(authority)
	return uc, secret
}

// TestExecute_MintsWithOurSigner — приземление: вход базовым секретом получает
// токен НАШЕГО подписанта за ту служебную учётку, за которую говорит секрет.
//
// Прежде проба утверждала ещё и обратное — «прежний издатель на переведённом
// контуре не звучит», — с положительным контролем на анонимном потоке без
// подписанта, который шёл к прежнему издателю. Той половины больше нет не
// послаблением, а построением (kaname#494): без подписанта полоса не строится
// (TestUseCaseWithoutOurMinterIssuesNothing), и звучать прежнему издателю
// негде.
func TestExecute_MintsWithOurSigner(t *testing.T) {
	minter := &stubMinter{}
	uc, secret := newUseCase(t, minter)

	in := dockerLogin(secret)
	in.Service = "registry.kacho.local"
	out, err := uc.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)

	// Субъект токена — служебная учётка, за которую говорит секрет: иначе
	// запросы отвергались бы уже правами, а не подписью.
	require.Equal(t, dockerSubject, minter.in.Subject)
	require.Equal(t, "registry.kacho.local", minter.in.Audience)
}

// TestExecuteAnonymous_MintsWithOurSigner — анонимный путь чеканит тот же
// подписант: два издателя на ОДНОМ контуре означали бы, что приёмная сторона
// обязана держать обе записи ради одного и того же реестра.
func TestExecuteAnonymous_MintsWithOurSigner(t *testing.T) {
	minter := &stubMinter{}
	uc, _ := newUseCase(t, minter)

	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)

	// Субъект анонимного токена — тот же идентификатор, который приёмная
	// сторона резолвит в подстановочного принципала.
	require.Equal(t, "anon-client", minter.in.Subject)
	// И запрошенный объём — только чтение: анонимный токен НИКОГДА не просит
	// глагола записи.
	require.Equal(t, registrytokenuc.AnonymousReadScope, minter.in.Scope)
}

// TestExecute_MinterFailureIsFailClosed — отказ нашего подписанта — отказ
// выдачи недоступностью издателя: запасного издателя у полосы нет, и токена на
// этом пути не бывает.
func TestExecute_MinterFailureIsFailClosed(t *testing.T) {
	uc, secret := newUseCase(t, &stubMinter{err: errors.New("no signing key")})

	out, err := uc.Execute(context.Background(), dockerLogin(secret))
	require.Error(t, err)
	require.ErrorIs(t, err, registrytokenuc.ErrIssuerUnavailable,
		"неисправность своей чеканки — недоступность издателя, а не негодные учётные данные")
	require.Empty(t, out.Token, "токен на отказе своей чеканки")
}
