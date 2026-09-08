// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// hydra_interactive_clients.go — adapter satisfying the interactive-client
// use-case's provider port, on top of the existing HydraAdminClient.
//
// WHY A THIN NAMED ADAPTER AND NOT THE ADMIN CLIENT DIRECTLY. The use-case must
// not depend on the provider's HTTP shape (Clean Architecture), and the
// translation has one substantive job: it forwards the grant types the use-case
// DECIDED instead of letting the admin client's default apply. That default is
// `client_credentials`, and it is exactly how the three pre-existing
// registration paths all came to mean "machine" — the shape was chosen by an
// adapter default rather than by a caller.

import (
	"context"
	"errors"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
)

// InteractiveClientProvider adapts HydraAdminClient to the use-case port.
type InteractiveClientProvider struct {
	admin *HydraAdminClient
}

// NewInteractiveClientProvider — constructor. A nil admin client is refused at
// call time rather than dereferenced: an unwired provider must fail closed, not
// panic the listener.
func NewInteractiveClientProvider(admin *HydraAdminClient) *InteractiveClientProvider {
	return &InteractiveClientProvider{admin: admin}
}

// Register — creates the authorization-code client at the provider.
//
// `response_types` is set to `code` explicitly. Leaving the admin client's
// default (`token`) would register a client the provider refuses to run a code
// ceremony for — the registration would succeed and the ceremony would fail
// later, at the point furthest from the cause.
func (p *InteractiveClientProvider) Register(
	ctx context.Context, in interactiveclient.ProviderClientSpec,
) (interactiveclient.ProviderClient, error) {
	if p == nil || p.admin == nil {
		return interactiveclient.ProviderClient{}, errors.New("identity provider client is not configured")
	}
	out, err := p.admin.CreateOAuthClient(ctx, CreateOAuthClientRequest{
		ClientName:             in.Name,
		GrantTypes:             in.GrantTypes,
		ResponseTypes:          []string{"code"},
		RedirectURIs:           in.RedirectURIs,
		PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
		Audience:               in.Audiences,
		// A public client with proof of possession: no secret is minted, so
		// there is no secret to return, store, or leak. Inv. 6 of the acceptance
		// is satisfied by construction rather than by remembering to redact.
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		return interactiveclient.ProviderClient{}, err
	}
	return interactiveclient.ProviderClient{
		ClientID:                out.ClientID,
		GrantTypes:              out.GrantTypes,
		TokenEndpointAuthMethod: out.TokenEndpointAuthMethod,
		Audiences:               out.Audience,
	}, nil
}

// Deregister — removes the client at the provider. Used both on Delete and as
// the compensation when the row insert fails after a successful registration.
func (p *InteractiveClientProvider) Deregister(ctx context.Context, providerClientID string) error {
	if p == nil || p.admin == nil {
		return errors.New("identity provider client is not configured")
	}
	return p.admin.DeleteOAuthClient(ctx, providerClientID)
}
