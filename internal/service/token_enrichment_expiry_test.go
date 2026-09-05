// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_expiry_test.go — the credential behind a minted token must
// still be within its lifetime.
//
// `service_account_oauth_clients.expires_at` (and its user-token twin
// `user_oauth_clients.expires_at`) is stamped at issue time, but the provider
// path — client → Hydra /oauth2/token (private_key_jwt client_assertion) →
// this enricher via the token hook — never read it. Hydra authenticates the
// assertion against the registered JWK, which does not expire, so a key past
// its stated expiry kept minting tokens indefinitely. Докерная полоса отвергала
// просроченный ключ своим проверяющим; тот снят вместе с приёмом ключевого
// материала в поле пароля (задача #1143), и путь провайдера остался
// ЕДИНСТВЕННЫМ, где срок ключа вообще проверяется. Эти пробы его и держат.
//
// Boundary and nil semantics are asserted explicitly because both are
// load-bearing:
//   - expires_at == now is EXPIRED (deny at the instant): `!ExpiresAt.After(now)`,
//     дословно тот предикат, которым отвергала снятая ныне докерная проверка;
//   - expires_at IS NULL is NON-EXPIRING, not invalid — the bootstrap-admin
//     mint (#58) inserts its mapping with a NULL expiry, as does every row
//     predating the TTL knobs. Reading NULL as invalid would revoke the
//     cluster-admin credential and every legacy key at once.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

const (
	expiryClientID = "kacho-sak-expiry"
	expirySvaID    = "sva01abcdefghjkmnp"
	expirySocID    = "soc_01abcdefghjkmnp"
	expiryAccID    = "acc01abcdefghjkmnp"
)

// expiryFedSAPort — SA port whose FEDERATED lookup resolves (the non-federated
// lookup misses), so the jwt-bearer branch of EnrichClaims is exercised.
type expiryFedSAPort struct {
	soc domain.ServiceAccountOAuthClient
	sa  domain.ServiceAccount
}

func (p expiryFedSAPort) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

func (p expiryFedSAPort) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return p.sa, nil
}

func (p expiryFedSAPort) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return p.soc, nil
}

// newExpirySAEnricher builds an enricher whose SA mapping carries expiresAt and
// whose clock is pinned to now. The interactive-user port must never be reached.
func newExpirySAEnricher(t *testing.T, expiresAt *time.Time, now time.Time) *TokenEnrichmentService {
	t.Helper()
	sa := stubSAPort{
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             domain.SAOAuthClientID(expirySocID),
			SvaID:          domain.ServiceAccountID(expirySvaID),
			OAuthClientID:  domain.OAuthClientID(expiryClientID),
			ExpiresAt:      expiresAt,
		},
		sa: domain.ServiceAccount{
			ID:        domain.ServiceAccountID(expirySvaID),
			AccountID: domain.AccountID(expiryAccID),
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: "https://hydra.kacho.cloud"},
		stubUserPort{t: t},
	).WithSAPort(sa)
	svc.now = func() time.Time { return now }
	return svc
}

// TestEnrichClaims_SAKey_Expired_Denied — a key whose stated expiry has passed
// must not enrich; the caller (token hook) turns the sentinel into a denial.
func TestEnrichClaims_SAKey_Expired_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	expired := now.Add(-time.Second)
	svc := newExpirySAEnricher(t, &expired, now)

	claims, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{ACR: "0"})

	require.Error(t, err, "an expired SA key must not mint a token")
	assert.True(t, stderrors.Is(err, ErrCredentialExpired),
		"denial must be the credential-expired sentinel so the hook answers 403, not 500: got %v", err)
	assert.Nil(t, claims, "no claims may be produced for an expired credential")
}

// TestEnrichClaims_SAKey_ExpiringExactlyNow_Denied — the boundary instant.
// expires_at == now is treated as EXPIRED, matching the docker path's
// `!ExpiresAt.After(now)` exactly; a split here would let a key work on one
// path and fail on the other at the same wall-clock instant.
func TestEnrichClaims_SAKey_ExpiringExactlyNow_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	atInstant := now
	svc := newExpirySAEnricher(t, &atInstant, now)

	claims, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{ACR: "0"})

	require.Error(t, err, "expires_at == now must be treated as expired (deny at the instant)")
	assert.True(t, stderrors.Is(err, ErrCredentialExpired), "got %v", err)
	assert.Nil(t, claims)
}

// TestEnrichClaims_SAKey_ExpiredInAnotherZone_Denied — the stored timestamptz
// may come back from pgx in any location. Expiry compares INSTANTS, so the same
// moment expressed in a non-UTC zone must produce the same verdict; a
// wall-clock (field-wise) comparison would let a key survive its expiry by the
// zone offset.
func TestEnrichClaims_SAKey_ExpiredInAnotherZone_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	// One second ago, rendered in UTC+14 — same instant, different wall clock.
	expired := now.Add(-time.Second).In(time.FixedZone("UTC+14", 14*3600))
	svc := newExpirySAEnricher(t, &expired, now)

	claims, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{ACR: "0"})

	require.Error(t, err, "expiry must compare instants, not wall-clock fields")
	assert.True(t, stderrors.Is(err, ErrCredentialExpired), "got %v", err)
	assert.Nil(t, claims)
}

// TestEnrichClaims_SAKey_NotYetExpired_Mints — one nanosecond of life left is
// still life: the gate must not round a live key into a dead one.
func TestEnrichClaims_SAKey_NotYetExpired_Mints(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	live := now.Add(time.Nanosecond)
	svc := newExpirySAEnricher(t, &live, now)

	claims, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{ACR: "0"})

	require.NoError(t, err)
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
	assert.Equal(t, expirySvaID, claims["kacho_principal_id"])
}

// TestEnrichClaims_SAKey_NoExpiry_Mints — NULL expires_at means non-expiring,
// NOT invalid. The bootstrap-admin mapping is inserted with a NULL expiry, so
// reading NULL as invalid would take the cluster-admin credential down.
func TestEnrichClaims_SAKey_NoExpiry_Mints(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	svc := newExpirySAEnricher(t, nil, now)

	claims, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{ACR: "0"})

	require.NoError(t, err, "a NULL expiry is non-expiring — the bootstrap-admin row shape")
	assert.Equal(t, expirySvaID, claims["kacho_principal_id"])
}

// TestEnrichClaims_FederatedSAKey_Expired_Denied — the federation-in branch
// resolves a DIFFERENT row (by external issuer+subject) and must apply the same
// gate; the trust-grant lifetime tracks the key's expiry at issue time, but the
// row is what this path holds.
func TestEnrichClaims_FederatedSAKey_Expired_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	expired := now.Add(-time.Hour)
	port := expiryFedSAPort{
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             domain.SAOAuthClientID(expirySocID),
			SvaID:          domain.ServiceAccountID(expirySvaID),
			OAuthClientID:  domain.OAuthClientID(expiryClientID),
			ExpiresAt:      &expired,
		},
		sa: domain.ServiceAccount{
			ID:        domain.ServiceAccountID(expirySvaID),
			AccountID: domain.AccountID(expiryAccID),
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: "https://hydra.kacho.cloud"},
		stubUserPort{t: t},
	).WithSAPort(port)
	svc.now = func() time.Time { return now }

	claims, _, err := svc.EnrichClaims(context.Background(), "external-subject", TokenHookContext{
		GrantType:      "urn:ietf:params:oauth:grant-type:jwt-bearer",
		ExternalIssuer: "https://idp.example.com",
		OAuthClientID:  expiryClientID,
	})

	require.Error(t, err, "an expired federated SA key must not mint a token")
	assert.True(t, stderrors.Is(err, ErrCredentialExpired), "got %v", err)
	assert.Nil(t, claims)
}

// TestEnrichClaims_UserToken_Expired_Denied — the personal-access-token twin
// carries the same column and reaches the same hook; leaving it ungated would
// keep an expired user token minting while the SA key next to it is refused.
func TestEnrichClaims_UserToken_Expired_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	expired := now.Add(-time.Minute)
	ut := stubUserTokenPort{
		uoc: domain.UserOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             domain.UserOAuthClientID("uoc-123"),
			UserID:         domain.UserID("usr-abc"),
			ExpiresAt:      &expired,
		},
		user: domain.User{ID: domain.UserID("usr-abc"), AccountID: domain.AccountID("acc-xyz"),
			// A personal token is its owner's authority: the owner's state is
			// load-bearing, so the fixture states it rather than leaving it unset.
			InviteStatus: domain.InviteStatusActive},
	}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, now)

	claims, _, err := svc.EnrichClaims(context.Background(), "client-abc", TokenHookContext{})

	require.Error(t, err, "an expired user token must not mint a token")
	assert.True(t, stderrors.Is(err, ErrCredentialExpired), "got %v", err)
	assert.Nil(t, claims)
}

// TestEnrichClaims_UserToken_NoExpiry_Mints — user tokens are issued without a
// default TTL, so NULL is the common shape; it stays non-expiring.
func TestEnrichClaims_UserToken_NoExpiry_Mints(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ut := stubUserTokenPort{
		uoc: domain.UserOAuthClient{ID: domain.UserOAuthClientID("uoc-123"), UserID: domain.UserID("usr-abc")},
		user: domain.User{ID: domain.UserID("usr-abc"), AccountID: domain.AccountID("acc-xyz"),
			// A personal token is its owner's authority: the owner's state is
			// load-bearing, so the fixture states it rather than leaving it unset.
			InviteStatus: domain.InviteStatusActive},
	}
	svc := newUserTokenEnricher(stubUserPort{t: t}, ut, now)

	claims, _, err := svc.EnrichClaims(context.Background(), "client-abc", TokenHookContext{})

	require.NoError(t, err)
	assert.Equal(t, "user", claims["kacho_principal_type"])
}

// TestEnrichClaims_ExpiredSAKey_DoesNotFallThroughToUserPath — the denial must
// be terminal. Falling through would hand an expired SA client_id to the
// interactive-user lookup and, on a miss, to the hook's MinimalClaims fallback
// — i.e. a token would still be minted.
func TestEnrichClaims_ExpiredSAKey_DoesNotFallThroughToUserPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	expired := now.Add(-time.Second)
	// stubUserPort{t: t} fails the test if the interactive path is reached.
	svc := newExpirySAEnricher(t, &expired, now)

	_, _, err := svc.EnrichClaims(context.Background(), expiryClientID, TokenHookContext{})

	require.Error(t, err)
	assert.False(t, stderrors.Is(err, iamerr.ErrNotFound),
		"an expired credential must not degrade into not-found (the hook mints minimal claims on not-found)")
}
