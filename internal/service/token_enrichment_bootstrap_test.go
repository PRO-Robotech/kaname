// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_bootstrap_test.go — IBT-T5 (#58): the bootstrap-admin SA's
// client_credentials token enriches to service-account principal claims exactly
// like any SA-key token. This locks the claim contract the gateway relies on:
// kaname_principal_type=service_account + kaname_principal_id=<bootstrap sva>, so
// the gateway resolves the FGA subject `service_account:<sva>` (which holds the
// seeded system_admin@cluster grant) and stamps the acr-exempt principal.

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

// Deterministic bootstrap identity (byte-identical to migration 0058 /
// bootstrap_token.DeriveIdentity()).
const (
	bootstrapSvaID  = "svab91854890de887e6d"
	bootstrapSocID  = "soc_db27d17291ff453b6"
	systemAccountID = "acc1a18042d81fb438d6"
)

// stubSAPort — programmable owning-ServiceAccount read.
type stubSAPort struct {
	sa    domain.ServiceAccount
	saErr error
}

func (s stubSAPort) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return s.sa, s.saErr
}

// stubOwnClients — programmable read of a registry row by OUR id.
type stubOwnClients struct {
	soc    domain.ServiceAccountOAuthClient
	socErr error
}

func (s stubOwnClients) GetUserToken(_ context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user token %s", id)
}

func (s stubOwnClients) GetSAKey(_ context.Context, _ domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return s.soc, s.socErr
}

// The bootstrap mint goes through the own lane (ClaimsForAssertionClient). The
// provider's token-hook branch that resolved the same row by client id is gone
// with the hooks (kaname#363).
func TestEnrichClaims_BootstrapSA_ServiceAccountClaims(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	own := stubOwnClients{soc: domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             domain.SAOAuthClientID(bootstrapSocID),
		SvaID:          domain.ServiceAccountID(bootstrapSvaID),
	}}
	sa := stubSAPort{sa: domain.ServiceAccount{
		ID:        domain.ServiceAccountID(bootstrapSvaID),
		AccountID: domain.AccountID(systemAccountID),
		// This account may authenticate; the refusal under test is a different one.
		Enabled: true,
	}}
	svc := NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "api.kacho.cloud"}).
		WithSAPort(sa).WithOwnClientPort(own)
	svc.now = func() time.Time { return fixed }

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), domain.AssertionClient{
		ID: bootstrapSocID, Kind: domain.AssertionClientServiceAccount, OwnerID: bootstrapSvaID,
	}, TokenHookContext{ACR: "0"})
	require.NoError(t, err)

	assert.Equal(t, "service_account", claims["kaname_principal_type"],
		"bootstrap SA token must carry a service-account principal type (acr-exempt at the gateway)")
	assert.Equal(t, bootstrapSvaID, claims["kaname_principal_id"],
		"principal id must be the bootstrap SA so the gateway resolves service_account:<sva>")
	assert.Equal(t, bootstrapSocID, claims["kaname_sa_key_id"])
	assert.Equal(t, systemAccountID, claims["kaname_account_id"])
	assert.Equal(t, "api.kacho.cloud", claims["kaname_audience"])
	// The enricher passes through the stated ACR; the gateway step-up
	// SA-exemption (O-1) is what lets this satisfy acr>=2 RPCs.
	assert.Equal(t, "0", claims["kaname_acr"])
}

// A missing key row is refused, not read as the bootstrap SA (guards against the
// enricher silently treating an unknown client id as a known one).
func TestEnrichClaims_UnknownClient_NotBootstrapSA(t *testing.T) {
	own := stubOwnClients{socErr: iamerr.ErrNotFound}
	svc := NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "api.kacho.cloud"}).
		WithSAPort(stubSAPort{}).WithOwnClientPort(own)
	_, _, err := svc.ClaimsForAssertionClient(context.Background(), domain.AssertionClient{
		ID: "some-other-client", Kind: domain.AssertionClientServiceAccount,
	}, TokenHookContext{})
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound), "unknown client resolves to no SA key row")
}
