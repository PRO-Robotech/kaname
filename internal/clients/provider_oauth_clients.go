// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_oauth_clients.go — the wire types of an OAuth2 client registration at
// the external provider, for the lanes that still register there (the
// interactive client and the drain that compensates it). Service-account keys
// and personal tokens register nothing here (kaname#362, #1121).
//
// The calls themselves are methods of the admin client, next to its type
// (CreateOAuthClient, DeleteOAuthClient). This file holds what they carry: the
// client record the provider answers with, the registration request, the key
// set published with a private_key_jwt client, and the refusal a non-2xx answer
// becomes.
//
// Endpoints the records travel on:
//
//	POST   /admin/clients              — create OAuth2 client (returns
//	                                     {client_id, client_secret, ...}).
//	DELETE /admin/clients/{client_id}  — delete OAuth2 client.
//
// The plaintext `client_secret` is returned EXACTLY ONCE by Create and is never
// persisted (security rule: secrets are never stored).
package clients

import "fmt"

// JWK — JSON Web Key (RFC 7517), the subset relevant to a client registration
// at the provider. Only EC keys are required (ES256); RS256 / OKP
// fields are reserved but not populated by kaname.
type JWK struct {
	Kty string `json:"kty"`           // "EC"
	Crv string `json:"crv,omitempty"` // "P-256"
	X   string `json:"x,omitempty"`   // base64url ECDSA X
	Y   string `json:"y,omitempty"`   // base64url ECDSA Y
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"` // "ES256"
	Use string `json:"use,omitempty"` // "sig"
}

// JWKS — JWK Set wrapper.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ProviderOAuthClient — minimal OAuth2-client record of the provider's admin API.
type ProviderOAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"` // present only on Create (legacy client_secret_basic)
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Audience                []string `json:"audience,omitempty"`
	Owner                   string   `json:"owner,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	// TokenEndpointAuthSigningAlg — JOSE-alg, которым поставщик обязан проверять
	// client_assertion (private_key_jwt); без него поставщик дефолтит на RS256 и
	// отвергает ES256-assertion (invalid_client).
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`
	// JWKS — embedded JSON Web Key Set; populated when
	// `token_endpoint_auth_method == "private_key_jwt"`.
	JWKS *JWKS `json:"jwks,omitempty"`
	// AccessTokenLifespan — per-client access-token lifetime (Go duration string,
	// e.g. "15m0s"). Empty → the provider's global default. Set for the bootstrap
	// client so its minted tokens are deliberately short-lived (#58, IBT-09).
	AccessTokenLifespan string `json:"access_token_lifespan,omitempty"`
	// DPoPBoundAccessTokens — RFC 9449 §5.2 client-registration metadata. True →
	// tokens minted for this client are sender-constrained: they carry a `cnf.jkt`
	// and are usable only by the holder of the matching key.
	//
	// Sender-constraining is per-client metadata, not a global switch (the global
	// `oauth2.dpop` config block does not exist in the pinned provider version),
	// so it MUST be requested here at registration. Omitted when false — an
	// existing client registration is untouched.
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens,omitempty"`
	// TLSClientCertificateBoundAccessTokens — RFC 8705 §3.4 counterpart: binds
	// minted tokens to the client's TLS certificate (`cnf.x5t#S256`). Reserved
	// for mTLS-authenticating clients; kaname SA keys use DPoP.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	// RedirectURIs — where the provider may deliver an authorization code.
	// Meaningful ONLY for the interactive-login client (IAM-INT-1): the
	// machine grants this file otherwise registers (client_credentials,
	// jwt-bearer) never redirect anywhere. Omitted when empty, so no existing
	// registration changes shape.
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// PostLogoutRedirectURIs — RP-initiated-logout counterpart of the above.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
}

// CreateOAuthClientRequest — input for the admin client's CreateOAuthClient.
type CreateOAuthClientRequest struct {
	// ClientID is optional — if empty, the provider auto-generates.
	ClientID string
	// ClientName is a human-readable identifier (e.g. "kaname-sak-XYZ").
	ClientName string
	// Owner is the kaname ServiceAccount id (used by the provider's `owner`
	// filter for List by SA).
	Owner string
	// Scope — space-separated set granted to this client.
	Scope string
	// Audience — `aud` claim placed in minted tokens.
	Audience []string
	// AuthMethod — "client_secret_basic" / "client_secret_post" /
	// "private_key_jwt" (the default).
	AuthMethod string
	// GrantTypes — OAuth2 grants the client may exercise. Defaults to
	// `["client_credentials"]` when nil/empty.
	GrantTypes []string
	// TokenEndpointAuthMethod — explicit override of AuthMethod for clients
	// migrated to private_key_jwt. When non-empty, takes precedence over
	// AuthMethod. Set to "private_key_jwt" for SA keys.
	TokenEndpointAuthMethod string
	// TokenEndpointAuthSigningAlg — JOSE-alg client_assertion ("ES256" для SA-ключей).
	TokenEndpointAuthSigningAlg string
	// JWKS — embedded public-key set published with the client (private_key_jwt:
	// kaname mints the keypair and registers the
	// public JWK here). The provider stores it, validates `client_assertion`
	// signatures against it, and never sees the private half.
	JWKS *JWKS
	// AccessTokenLifespan — per-client access-token lifetime (Go duration string).
	// Empty → the provider's global default.
	AccessTokenLifespan string
	// DPoPBoundAccessTokens — request sender-constrained (RFC 9449) tokens for
	// this client. See the field of the same name on ProviderOAuthClient.
	DPoPBoundAccessTokens bool
	// TLSClientCertificateBoundAccessTokens — RFC 8705 mTLS-bound tokens.
	TLSClientCertificateBoundAccessTokens bool
	// RedirectURIs / PostLogoutRedirectURIs — interactive-login client only.
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// ResponseTypes — overrides the default ["token"]. The authorization-code
	// ceremony needs ["code"]; leaving the default would register a client the
	// provider refuses to run a code flow for.
	ResponseTypes []string
}

// ProviderAPIError — the provider's admin API returned non-2xx.
type ProviderAPIError struct {
	StatusCode int
	Body       string
}

func (e *ProviderAPIError) Error() string {
	return fmt.Sprintf("provider admin api: status %d: %s", e.StatusCode, e.Body)
}

func providerAPIError(status int, body []byte) error {
	return &ProviderAPIError{StatusCode: status, Body: string(body)}
}
