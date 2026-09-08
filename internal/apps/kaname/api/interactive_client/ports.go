// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package interactiveclient — use-cases of InternalInteractiveClientService
// (IAM-INT-1): the lifecycle of the OAuth2 client through which a HUMAN
// completes an interactive sign-in ceremony.
//
// Clean Architecture: this package defines the narrow ports below and depends on
// nothing but domain + the corelib operation envelope. Concrete adapters (pgx,
// the identity provider's admin API) live in internal/repo and internal/clients
// and are wired in cmd/kaname/wiring.go.
package interactiveclient

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// clientRepo — persistence port.
//
// Delete reports whether a row was actually removed. The distinction is not
// bookkeeping: the RPC is idempotent, so "already gone" and "just removed" look
// the same to the caller, and this is the one place that must still tell them
// apart — only a real removal owes a provider-side deregistration.
type clientRepo interface {
	Get(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, error)
	// List returns one page and the cursor for the next. The codec lives in the
	// adapter (it encodes a row's sort key), so the page and its cursor are
	// produced by the same code — a caller cannot re-derive a cursor from a page
	// it has already truncated.
	List(ctx context.Context, limit int, pageToken, nameFilter string) ([]domain.InteractiveClient, string, error)
	Insert(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error)
	Update(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error)
	Delete(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error)
}

// providerClients — the identity provider's client-registration port.
//
// WHY IT IS A PORT AND NOT A DIRECT CALL. iam is the single facade to the
// provider (core rule #16); expressing the dependency here keeps the use-case
// testable without a live provider and keeps the provider's HTTP shape out of
// the business layer. The adapter is *clients.HydraAdminClient.
type providerClients interface {
	Register(ctx context.Context, in ProviderClientSpec) (ProviderClient, error)
	Deregister(ctx context.Context, providerClientID string) error
}

// ProviderClientSpec — what iam asks the provider to register. The caller of the
// RPC supplies only the first two fields' worth of intent; everything else is
// iam's decision (Р2 — the audience is stamped, never accepted).
type ProviderClientSpec struct {
	Name                   string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	Audiences              []string
	// GrantTypes — decided by the use-case, forwarded verbatim. The adapter does
	// not choose: this resource exists to register exactly one shape, and a
	// default living in the adapter is how the other three registration paths
	// ended up all meaning `client_credentials`.
	GrantTypes []string
}

// ProviderClient — what the provider gives back.
type ProviderClient struct {
	ClientID                string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Audiences               []string
}
