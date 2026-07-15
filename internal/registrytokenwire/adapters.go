// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytokenwire — composition-root adapters binding the registry
// `/iam/token` shim use-case to iam infrastructure:
//
//   - SAClientLookupAdapter — resolves the SA-key registered for a Hydra
//     client_id (reverse lookup), so the shim can build the client_assertion.
//   - HydraExchangeAdapter — brokers the client_credentials + private_key_jwt
//     exchange with Hydra's public token endpoint, mapping issuer-unavailability
//     to the use-case's fail-closed sentinel.
//
// These are thin adapters over already-tested primitives (the SA repo + the Hydra
// token client); they carry no policy.
package registrytokenwire

import (
	"context"
	"errors"
	"fmt"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// saClientByIDReader — reverse lookup of an SA-OAuth-client by Hydra client_id
// (satisfied by the SA repo's GetByOAuthClientID).
type saClientByIDReader interface {
	GetByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error)
}

// ── SA-key lookup by client_id ──────────────────────────────────────────────

// SAClientLookupAdapter — resolves the registered SA-key for a Hydra client_id.
type SAClientLookupAdapter struct {
	repo saClientByIDReader
}

// NewSAClientLookup — builder.
func NewSAClientLookup(repo saClientByIDReader) *SAClientLookupAdapter {
	return &SAClientLookupAdapter{repo: repo}
}

var _ registrytokenuc.SAClientLookup = (*SAClientLookupAdapter)(nil)

// KeyByClientID returns the registered key material for a Hydra client_id.
func (a *SAClientLookupAdapter) KeyByClientID(ctx context.Context, clientID string) (registrytokenuc.RegisteredKey, error) {
	row, err := a.repo.GetByOAuthClientID(ctx, domain.OAuthClientID(clientID))
	if err != nil {
		return registrytokenuc.RegisteredKey{}, fmt.Errorf("registrytokenwire: lookup client %s: %w", clientID, err)
	}
	return registrytokenuc.RegisteredKey{
		ClientID:     string(row.OAuthClientID),
		KeyID:        string(row.ID),
		Subject:      string(row.SvaID),
		PublicKeyPEM: row.PublicKeyPEM,
		KeyAlgorithm: row.KeyAlgorithm,
		ExpiresAt:    row.ExpiresAt,
	}, nil
}

// ── Hydra token exchange ────────────────────────────────────────────────────

// hydraClientCredentials — the Hydra public token endpoint (satisfied by
// clients.HydraTokenClient).
type hydraClientCredentials interface {
	ClientCredentials(ctx context.Context, req clients.ClientCredentialsRequest) (clients.TokenResponse, error)
}

// HydraExchangeAdapter — the TokenExchanger backed by Hydra's public token
// endpoint. Issuer unavailability is surfaced as the use-case's fail-closed
// sentinel; a Hydra rejection is returned as-is (the use-case collapses it to a
// 401 challenge).
type HydraExchangeAdapter struct {
	client hydraClientCredentials
}

// NewHydraExchange — builder.
func NewHydraExchange(c hydraClientCredentials) *HydraExchangeAdapter {
	return &HydraExchangeAdapter{client: c}
}

var _ registrytokenuc.TokenExchanger = (*HydraExchangeAdapter)(nil)

// Exchange brokers the client_credentials + private_key_jwt exchange.
func (a *HydraExchangeAdapter) Exchange(ctx context.Context, in registrytokenuc.ExchangeInput) (registrytokenuc.ExchangeOutput, error) {
	out, err := a.client.ClientCredentials(ctx, clients.ClientCredentialsRequest{
		ClientAssertion: in.ClientAssertion,
		Audience:        in.Audience,
		Scope:           in.Scope,
	})
	if err != nil {
		if errors.Is(err, clients.ErrHydraUnavailable) {
			return registrytokenuc.ExchangeOutput{}, registrytokenuc.ErrIssuerUnavailable
		}
		// Hydra rejection (invalid_client / invalid_grant) — collapsed to 401
		// upstream; no raw Hydra detail is propagated.
		return registrytokenuc.ExchangeOutput{}, registrytokenuc.ErrInvalidCredentials
	}
	return registrytokenuc.ExchangeOutput{AccessToken: out.AccessToken, ExpiresIn: out.ExpiresIn}, nil
}
