// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// iface.go — narrow port interfaces for the bootstrap-token use-case.
//
// Clean Architecture: the use-case depends on these; concrete adapters live in
// internal/repo/kacho/pg (BootstrapStore), internal/clients (OAuthClientAdmin)
// and internal/registrytokenwire (TokenExchanger), wired in cmd/kacho-iam. No
// pgx / grpc imports here (only the shared clients + domain DTOs, mirroring sa_keys).
package bootstrap_token

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// BootstrapStore — the singleton provisioning port for the bootstrap OAuth-client
// mapping (a service_account_oauth_clients row). LockAndGet serialises concurrent
// first-callers via a transaction-scoped advisory lock (released on commit/
// rollback) so the external Hydra client is created at most once (IBT-03);
// UNIQUE(sva_id) on the mapping is the DB backstop.
type BootstrapStore interface {
	// LockAndGet takes the bootstrap provisioning advisory lock within tx, then
	// returns the existing mapping (found=false when not yet provisioned).
	LockAndGet(ctx context.Context, tx service.Tx) (c domain.ServiceAccountOAuthClient, found bool, err error)
	// InsertMapping persists the mapping row within tx (public key only; the
	// private half is env-held, never stored).
	InsertMapping(ctx context.Context, tx service.Tx, c domain.ServiceAccountOAuthClient) error
}

// OAuthClientAdmin — the Hydra Admin subset needed to provision the bootstrap
// OAuth client (client_credentials + private_key_jwt). Satisfied by
// *clients.HydraAdminClient (the same adapter sa_keys uses).
type OAuthClientAdmin interface {
	CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error)
}

// ExchangeInput — the Hydra client_credentials exchange request. The bootstrap
// mint requests no scope (the token carries identity only; per-RPC authz is the
// gateway FGA Check), so there is no scope field.
type ExchangeInput struct {
	ClientAssertion string // the signed ES256 client_assertion (private_key_jwt).
	Audience        string // requested token `aud` — the gateway audience (API_DOMAIN).
}

// ExchangeOutput — Hydra's minted access-token relayed to the caller.
type ExchangeOutput struct {
	AccessToken string
	ExpiresIn   int
}

// ErrIssuerUnavailable — Hydra (the token issuer, a hard mint-path dependency)
// is unreachable / misbehaving. The use-case maps it to UNAVAILABLE (fail-closed;
// no token, raw Hydra body never leaks — no auth-oracle).
var ErrIssuerUnavailable = errors.New("bootstrap token: issuer unavailable")

// TokenExchanger — brokers the Hydra client_credentials + private_key_jwt
// exchange. Implementations return ErrIssuerUnavailable when the issuer is
// unreachable/misbehaving; any other failure is a fail-closed mint error.
// Satisfied by an adapter over *clients.HydraTokenClient.
type TokenExchanger interface {
	Exchange(ctx context.Context, in ExchangeInput) (ExchangeOutput, error)
}
