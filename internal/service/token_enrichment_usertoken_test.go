// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// token_enrichment_usertoken_test.go — coverage for the personal-access-token
// (UserOAuthClient) claim-minting branch of TokenEnrichmentService.
//
// 5th-audit TEST-medium: userTokenClaims + the user-token lookup branch of
// EnrichClaims (wired in prod via cmd/kacho-iam/hooks_mux.go .WithUserTokenPort)
// had ZERO test coverage — no test anywhere wired a UserTokenPort into the
// enrichment service. This is the security-relevant path that stamps
// kacho_principal_id / kacho_account_id / the DPoP-binding kacho_jkt / x5t_s256
// confirmation claims onto a token minted from a personal access token. A
// silent regression here (wrong principal/account, or a dropped cnf binding)
// would ship green. These tests lock the exact claim map and the error-
// propagation contract.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// stubUserPort — the interactive-user lookup port. The user-token branch returns
// BEFORE the interactive path is reached, so this must never be consulted on the
// paths under test; it fails the test if it is.
type stubUserPort struct{ t *testing.T }

func (s stubUserPort) FindActiveByExternalID(_ context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	if s.t != nil {
		s.t.Fatalf("interactive-user path must not be reached on a user-token subject")
	}
	return nil, nil
}

// stubUserTokenPort — programmable UserOAuthClient + User lookup.
type stubUserTokenPort struct {
	uoc     domain.UserOAuthClient
	uocErr  error
	user    domain.User
	userErr error
}

func (s stubUserTokenPort) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.UserOAuthClient, error) {
	return s.uoc, s.uocErr
}

func (s stubUserTokenPort) GetUser(_ context.Context, _ domain.UserID) (domain.User, error) {
	return s.user, s.userErr
}

func newUserTokenEnricher(users TokenEnrichmentUserPort, ut TokenEnrichmentUserTokenPort, now time.Time) *TokenEnrichmentService {
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"},
		users,
	).WithUserTokenPort(ut)
	svc.now = func() time.Time { return now }
	return svc
}

// TestEnrichClaims_UserToken_HappyPath — a subject resolving to a UserOAuthClient
// mints the full user-principal claim set, including the DPoP/mTLS cnf bindings
// and the owning account.
func TestEnrichClaims_UserToken_HappyPath(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	ut := stubUserTokenPort{
		uoc:  domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-123"), UserID: domain.UserID("usr-abc")},
		user: domain.User{ID: domain.UserID("usr-abc"), AccountID: domain.AccountID("acc-xyz")},
	}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, fixed)

	claims, err := svc.EnrichClaims(context.Background(), "client-abc", TokenHookContext{
		CnfJkt:     "jkt-thumb",
		CnfX5tS256: "x5t-thumb",
		ACR:        "3",
	})
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"kacho_external_id":       "client-abc",
		"kacho_hydra_client_id":   "client-abc",
		"kacho_principal_type":    "user",
		"kacho_principal_id":      "usr-abc",
		"kacho_user_id":           "usr-abc",
		"kacho_user_token_id":     "uoc-123",
		"kacho_device_compliance": "unknown",
		"kacho_jkt":               "jkt-thumb",
		"kacho_x5t_s256":          "x5t-thumb",
		"kacho_acr":               "3",
		"kacho_audience":          "kacho.cloud",
		"kacho_issuer":            "https://hydra.kacho.local",
		"kacho_issued_at":         fixed.Unix(),
		"kacho_account_id":        "acc-xyz",
		"kacho_active_account":    "acc-xyz",
	}, claims)
}

// TestEnrichClaims_UserToken_UserGone_OmitsAccount — when the User row is gone
// (GetUser → NotFound, mapping outlived the user) the principal claims are still
// minted but account_id / active_account are omitted (not blanked to a wrong
// value). NotFound must NOT propagate as an error.
func TestEnrichClaims_UserToken_UserGone_OmitsAccount(t *testing.T) {
	fixed := time.Unix(1_700_000_500, 0).UTC()
	ut := stubUserTokenPort{
		uoc:     domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-777"), UserID: domain.UserID("usr-gone")},
		userErr: iamerr.Wrapf(iamerr.ErrNotFound, "user usr-gone not found"),
	}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, fixed)

	claims, err := svc.EnrichClaims(context.Background(), "client-gone", TokenHookContext{})
	require.NoError(t, err)
	assert.Equal(t, "usr-gone", claims["kacho_principal_id"])
	assert.Equal(t, "uoc-777", claims["kacho_user_token_id"])
	assert.NotContains(t, claims, "kacho_account_id", "account omitted when the User row is gone")
	assert.NotContains(t, claims, "kacho_active_account")
}

// TestEnrichClaims_UserToken_LookupError_Propagates — a non-NotFound error from
// the UserOAuthClient lookup fails the hook (fail-closed) rather than silently
// falling through to minimal/interactive claims.
func TestEnrichClaims_UserToken_LookupError_Propagates(t *testing.T) {
	ut := stubUserTokenPort{uocErr: stderrors.New("db unavailable")}
	// users port must NOT be reached; pass a non-fatal stub (t=nil) so a bug that
	// DID fall through would surface as a wrong (non-error) result, caught below.
	svc := newUserTokenEnricher(stubUserPort{}, ut, time.Unix(1, 0))

	claims, err := svc.EnrichClaims(context.Background(), "client-err", TokenHookContext{})
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "lookup user-token oauth client")
}

// TestEnrichClaims_UserToken_GetUserError_Propagates — a non-NotFound error from
// GetUser also fails the hook.
func TestEnrichClaims_UserToken_GetUserError_Propagates(t *testing.T) {
	ut := stubUserTokenPort{
		uoc:     domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-9"), UserID: domain.UserID("usr-9")},
		userErr: stderrors.New("boom"),
	}
	svc := newUserTokenEnricher(stubUserPort{}, ut, time.Unix(1, 0))

	claims, err := svc.EnrichClaims(context.Background(), "client-9", TokenHookContext{})
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "get user")
}
