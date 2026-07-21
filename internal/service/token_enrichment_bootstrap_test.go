// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// token_enrichment_bootstrap_test.go — IBT-T5 (#58): the bootstrap-admin SA's
// client_credentials token enriches to service-account principal claims exactly
// like any SA-key token. This locks the claim contract the gateway relies on:
// kacho_principal_type=service_account + kacho_principal_id=<bootstrap sva>, so
// the gateway resolves the FGA subject `service_account:<sva>` (which holds the
// seeded system_admin@cluster grant) and stamps the acr-exempt principal.

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

// Deterministic bootstrap identity (byte-identical to migration 0058 /
// bootstrap_token.DeriveIdentity()).
const (
	bootstrapClientID = "kacho-bootstrap-admin"
	bootstrapSvaID    = "svab91854890de887e6d"
	bootstrapSocID    = "soc_db27d17291ff453b6"
	systemAccountID   = "acc1a18042d81fb438d6"
)

// stubSAPort — programmable ServiceAccount + OAuth-client-mapping lookup.
type stubSAPort struct {
	soc    domain.ServiceAccountOAuthClient
	socErr error
	sa     domain.ServiceAccount
	saErr  error
}

func (s stubSAPort) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return s.soc, s.socErr
}

func (s stubSAPort) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return s.sa, s.saErr
}

func (s stubSAPort) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

// bootstrapUserPort — the interactive-user path must NOT be reached for the
// bootstrap SA subject (the SA branch resolves first).
type bootstrapUserPort struct{ t *testing.T }

func (p bootstrapUserPort) FindActiveByExternalID(_ context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	p.t.Fatalf("interactive-user path must not be reached for the bootstrap SA client_credentials subject")
	return nil, nil
}

func TestEnrichClaims_BootstrapSA_ServiceAccountClaims(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()
	sa := stubSAPort{
		soc: domain.ServiceAccountOAuthClient{
			ID:            domain.SAOAuthClientID(bootstrapSocID),
			SvaID:         domain.ServiceAccountID(bootstrapSvaID),
			OAuthClientID: domain.OAuthClientID(bootstrapClientID),
		},
		sa: domain.ServiceAccount{
			ID:        domain.ServiceAccountID(bootstrapSvaID),
			AccountID: domain.AccountID(systemAccountID),
		},
	}
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: "https://hydra.kacho.cloud"},
		bootstrapUserPort{t: t},
	).WithSAPort(sa)
	svc.now = func() time.Time { return fixed }

	// For client_credentials, Hydra's `subject` == the client_id.
	claims, err := svc.EnrichClaims(context.Background(), bootstrapClientID, TokenHookContext{ACR: "0"})
	require.NoError(t, err)

	assert.Equal(t, "service_account", claims["kacho_principal_type"],
		"bootstrap SA token must carry a service-account principal type (acr-exempt at the gateway)")
	assert.Equal(t, bootstrapSvaID, claims["kacho_principal_id"],
		"principal id must be the bootstrap SA so the gateway resolves service_account:<sva>")
	assert.Equal(t, bootstrapSocID, claims["kacho_sa_key_id"])
	assert.Equal(t, systemAccountID, claims["kacho_account_id"])
	assert.Equal(t, "api.kacho.cloud", claims["kacho_audience"])
	// The enricher passes through the (client_credentials ≈ "0") session ACR; the
	// gateway step-up SA-exemption (O-1) is what lets this satisfy acr>=2 RPCs.
	assert.Equal(t, "0", claims["kacho_acr"])
}

// A missing SA mapping falls through to the interactive-user path (guards against
// the enricher silently treating an unknown client_id as the bootstrap SA).
func TestEnrichClaims_UnknownClient_NotBootstrapSA(t *testing.T) {
	sa := stubSAPort{socErr: iamerr.ErrNotFound}
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: "https://hydra.kacho.cloud"},
		fallthroughUserPort{},
	).WithSAPort(sa)
	_, err := svc.EnrichClaims(context.Background(), "some-other-client", TokenHookContext{})
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound), "unknown client resolves to neither SA nor user")
}

type fallthroughUserPort struct{}

func (fallthroughUserPort) FindActiveByExternalID(_ context.Context, _ domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
