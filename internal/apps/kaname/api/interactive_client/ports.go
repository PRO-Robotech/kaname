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
	// Insert records the row AND, in the same statement, the verification value
	// of the client's secret with the moment it was set (kaname#405, Р5). The
	// zero material means "no secret" (a client with method `none`). There is no
	// second writer of the material: a separate write after the insert would
	// open a window in which a client with a secret method exists and nothing
	// can be presented for it.
	Insert(ctx context.Context, c domain.InteractiveClient, material domain.LoginVerifier) (domain.InteractiveClient, error)
	Update(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error)
	Delete(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error)
}

// ProviderClients — порт заведения и снятия клиента интерактивного входа.
//
// WHY IT IS A PORT AND NOT A DIRECT CALL. iam is the single facade to the
// provider (core rule #16); expressing the dependency here keeps the use-case
// testable without a live provider and keeps the provider's HTTP shape out of
// the business layer.
//
// ИМЕНОВАН НАРУЖУ, и это не косметика: исполнителей у порта ДВА, и выбирает их
// посадка — под `external` зеркало чужого реестра
// (`*clients.InteractiveClientProvider`), под `own` наш собственный реестр
// (`*pg.OwnInteractiveClientProvider`). Выбор делает композиционный корень, а
// выбор, который нельзя назвать типом, пришлось бы выражать ветвью внутри
// use-case — то есть переносить решение о посадке в бизнес-слой (kaname#313).
type ProviderClients interface {
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
//
// The triple «method ⟺ material ⟺ secret» must agree: a secret method
// (`client_secret_basic`, `client_secret_post`) comes with BOTH a secret and its
// verification value, `none` with neither. The use-case refuses any other
// combination before the row is written (`secretMaterialAgrees`): the schema
// holds only one direction of it on purpose (a client of an external provider
// has no material in our row).
type ProviderClient struct {
	ClientID                string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Audiences               []string
	// Secret — the secret, minted by the registry, shown once in the answer of
	// the call. A carrier and not a string: see client_secret.go.
	Secret ClientSecret
	// SecretVerifier — the verification value of Secret; it is what the row
	// keeps. Zero — no secret.
	SecretVerifier domain.LoginVerifier
}
