// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_usertoken_test.go — состав утверждений персонального токена
// (UserOAuthClient) и граница полос, которые его выпускают.
//
// Персональный токен выпускает ОДНА полоса — наш токен-эндпоинт, по
// идентификатору строки реестра ([TokenEnrichmentService.ClaimsForAssertionClient]).
// Обратный вызов прежнего поставщика резолвил его по имени клиента у
// поставщика; поставщик персональных токенов не регистрирует, и ветвь снята
// вместе со столбцом этого имени (kaname#362). Пробы ниже держат обе стороны:
//
//   - наш путь даёт ПОЛНЫЙ состав принципала-человека, включая привязку
//     DPoP/mTLS и аккаунт владельца, и значением `kaname_external_id` ставит
//     идентификатор строки — единственное имя клиента;
//   - отказ чтения владельца не превращается в состав без владельца;
//   - обратный вызов, получивший субъектом идентификатор персонального токена,
//     его не резолвит: ни один принципал за этим субъектом не стоит.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// stubUserPort — the interactive-user lookup port. It fails the test when it is
// consulted on a path that must not reach the interactive branch.
type stubUserPort struct{ t *testing.T }

func (s stubUserPort) FindByExternalID(_ context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	if s.t != nil {
		s.t.Fatalf("interactive-user path must not be reached on a user-token subject")
	}
	return nil, nil
}

// stubUserTokenPort — programmable owner read of a personal token.
type stubUserTokenPort struct {
	user    domain.User
	userErr error
}

func (s stubUserTokenPort) GetUser(_ context.Context, _ domain.UserID) (domain.User, error) {
	return s.user, s.userErr
}

// stubOwnUserToken — чтение строки реестра по нашему идентификатору.
type stubOwnUserToken struct {
	uoc domain.UserOAuthClient
}

func (s stubOwnUserToken) GetUserToken(_ context.Context, _ domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return s.uoc, nil
}

func (s stubOwnUserToken) GetSAKey(_ context.Context, _ domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

func newUserTokenEnricher(users TokenEnrichmentUserPort, ut TokenEnrichmentUserTokenPort, uoc domain.UserOAuthClient, now time.Time) *TokenEnrichmentService {
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "kacho.cloud"},
		users,
	).WithUserTokenPort(ut).WithOwnClientPort(stubOwnUserToken{uoc: uoc})
	svc.now = func() time.Time { return now }
	return svc
}

func userTokenClient(id, owner string) domain.AssertionClient {
	return domain.AssertionClient{ID: id, Kind: domain.AssertionClientUser, OwnerID: owner, OwnerActive: true}
}

// TestClaimsForAssertionClient_UserToken_HappyPath — строка персонального токена
// даёт полный состав принципала-человека.
func TestClaimsForAssertionClient_UserToken_HappyPath(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	uoc := domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-123"), UserID: domain.UserID("usr-abc"),
		CredentialKind: domain.CredentialKindKeypair}
	ut := stubUserTokenPort{
		user: domain.User{ID: domain.UserID("usr-abc"), AccountID: domain.AccountID("acc-xyz"),
			// A personal token is its owner's authority: the owner's state is
			// load-bearing, so the fixture states it rather than leaving it unset.
			InviteStatus: domain.InviteStatusActive},
	}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, uoc, fixed)

	claims, principal, err := svc.ClaimsForAssertionClient(context.Background(),
		userTokenClient("uoc-123", "usr-abc"), TokenHookContext{
			CnfJkt:     "jkt-thumb",
			CnfX5tS256: "x5t-thumb",
			ACR:        "3",
		})
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"kaname_external_id":       "uoc-123",
		"kaname_principal_type":    "user",
		"kaname_principal_id":      "usr-abc",
		"kaname_user_id":           "usr-abc",
		"kaname_user_token_id":     "uoc-123",
		"kaname_device_compliance": "unknown",
		"kaname_jkt":               "jkt-thumb",
		"kaname_x5t_s256":          "x5t-thumb",
		"kaname_acr":               "3",
		"kaname_audience":          "kacho.cloud",
		"kaname_issued_at":         fixed.Unix(),
		"kaname_account_id":        "acc-xyz",
		"kaname_active_account":    "acc-xyz",
	}, claims)
	assert.Equal(t, PrincipalUser, principal.Kind)
	assert.Equal(t, "usr-abc", principal.UserID)
}

// TestClaimsForAssertionClient_UserToken_OwnerReadError_Propagates — отказ
// чтения владельца отказывает выпуску, а не даёт состав без владельца.
func TestClaimsForAssertionClient_UserToken_OwnerReadError_Propagates(t *testing.T) {
	uoc := domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-9"), UserID: domain.UserID("usr-9"),
		CredentialKind: domain.CredentialKindKeypair}
	svc := newUserTokenEnricher(stubUserPort{t: t}, stubUserTokenPort{userErr: stderrors.New("boom")}, uoc, time.Unix(1, 0))

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), userTokenClient("uoc-9", "usr-9"), TokenHookContext{})
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "owner of user-token client")
}

// TestEnrichClaims_UserTokenIDIsNotResolvedByTheProviderLane — обратный вызов
// прежнего поставщика, получивший субъектом идентификатор персонального токена,
// не находит за ним принципала: ветви, резолвившей персональный токен по имени
// клиента у поставщика, больше нет, и поставщик таких клиентов не регистрирует.
//
// Близнец — тот же вход нашим путём: строка разрешается и даёт принципала.
func TestEnrichClaims_UserTokenIDIsNotResolvedByTheProviderLane(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	uoc := domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-123"), UserID: domain.UserID("usr-abc"),
		CredentialKind: domain.CredentialKindKeypair}
	ut := stubUserTokenPort{user: domain.User{ID: domain.UserID("usr-abc"), AccountID: domain.AccountID("acc-xyz"),
		InviteStatus: domain.InviteStatusActive}}
	// Порт интерактивного пути пуст и НЕ роняет пробу: обратный вызов законно
	// доходит до него и не находит никого.
	svc := newUserTokenEnricher(stubUserPort{}, ut, uoc, now)

	claims, principal, err := svc.EnrichClaims(context.Background(), "uoc-123", TokenHookContext{})
	require.Error(t, err, "обратный вызов не вправе резолвить персональный токен")
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "got %v", err)
	assert.Nil(t, claims)
	assert.Equal(t, PrincipalUnresolved, principal.Kind)

	twin, twinPrincipal, twinErr := svc.ClaimsForAssertionClient(context.Background(),
		userTokenClient("uoc-123", "usr-abc"), TokenHookContext{})
	require.NoError(t, twinErr, "близнец: наш путь обязан резолвить ту же строку")
	assert.Equal(t, "user", twin["kaname_principal_type"])
	assert.Equal(t, PrincipalUser, twinPrincipal.Kind)
}

// TestClaimsForAssertionClient_UserToken_BlockedOwner_Refused — персональный
// токен — полномочие владельца и не переживает его права входить: строка,
// чей владелец заблокирован, состава не получает. Прежде это держала проба
// обратного вызова; полоса персонального токена там снята (kaname#362), и
// свойство держится здесь, на единственной полосе, которая его предъявляет.
//
// Близнец — тот же владелец активным: состав выдан (HappyPath выше).
func TestClaimsForAssertionClient_UserToken_BlockedOwner_Refused(t *testing.T) {
	uoc := domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-blk"), UserID: domain.UserID("usr-blk"),
		CredentialKind: domain.CredentialKindKeypair}
	ut := stubUserTokenPort{user: domain.User{ID: domain.UserID("usr-blk"), AccountID: domain.AccountID("acc-blk"),
		InviteStatus: domain.InviteStatusBlocked}}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, uoc, time.Unix(1, 0))

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), userTokenClient("uoc-blk", "usr-blk"), TokenHookContext{})
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, ErrSubjectNotActive), "got %v", err)
	assert.Nil(t, claims, "заблокированному владельцу состав не выдаётся")
}
