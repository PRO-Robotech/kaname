// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hydra_oauth_clients.go — Hydra Admin API for OAuth2 client CRUD,
// supporting Class A static service-account keys.
//
// Endpoints used:
//
//	POST   /admin/clients              — create OAuth2 client (returns
//	                                     {client_id, client_secret, ...}).
//	GET    /admin/clients/{client_id}  — get OAuth2 client (no secret).
//	DELETE /admin/clients/{client_id}  — delete OAuth2 client.
//
// The plaintext `client_secret` is returned EXACTLY ONCE by Create — we
// propagate it back through Operation.response.IssueSAKeyResponse and never
// persist it (security rule: secrets are never stored; only `hydra_client_id`
// is kept in `service_account_oauth_clients`).
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// JWK — JSON Web Key (RFC 7517), the subset relevant to Hydra client
// registration. Only EC keys are required (ES256); RS256 / OKP
// fields are reserved but not populated by kacho-iam.
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

// HydraOAuthClient — minimal Hydra Admin OAuth2-client representation.
type HydraOAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"` // present only on Create (legacy client_secret_basic)
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Audience                []string `json:"audience,omitempty"`
	Owner                   string   `json:"owner,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	// TokenEndpointAuthSigningAlg — JOSE-alg, которым Hydra обязан проверять
	// client_assertion (private_key_jwt). Для SA-ключей — "ES256"; без него Hydra
	// дефолтит на RS256 и отвергает ES256-assertion (invalid_client).
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`
	// JWKS — embedded JSON Web Key Set; populated when
	// `token_endpoint_auth_method == "private_key_jwt"`.
	JWKS *JWKS `json:"jwks,omitempty"`
	// AccessTokenLifespan — per-client access-token lifetime (Go duration string,
	// e.g. "15m0s"). Empty → Hydra's global default. Set for the bootstrap client
	// so its minted tokens are deliberately short-lived (#58, IBT-09).
	AccessTokenLifespan string `json:"access_token_lifespan,omitempty"`
}

// CreateOAuthClientRequest — input for HydraAdminClient.CreateOAuthClient.
type CreateOAuthClientRequest struct {
	// ClientID is optional — if empty, Hydra auto-generates.
	ClientID string
	// ClientName is a human-readable identifier (e.g. "kacho-sak-XYZ").
	ClientName string
	// Owner is the kacho-iam ServiceAccount id (used by Hydra's `owner`
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
	// kacho-iam mints the keypair and registers the
	// public JWK here). Hydra stores it, validates `client_assertion`
	// signatures against it, and never sees the private half.
	JWKS *JWKS
	// AccessTokenLifespan — per-client access-token lifetime (Go duration string).
	// Empty → Hydra's global default.
	AccessTokenLifespan string
}

// CreateOAuthClient registers a new client_credentials OAuth2 client with
// Hydra.
//
// When `req.TokenEndpointAuthMethod == "private_key_jwt"` the
// caller supplies `req.JWKS` with the public half of the keypair; Hydra
// validates `client_assertion` (RFC 7521/7523) signatures against it and
// returns NO `client_secret`. Otherwise (legacy `client_secret_basic`)
// Hydra mints + returns the plaintext `client_secret` exactly once.
func (c *HydraAdminClient) CreateOAuthClient(ctx context.Context, req CreateOAuthClientRequest) (HydraOAuthClient, error) {
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = defaultStr(req.AuthMethod, "client_secret_basic")
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"client_credentials"}
	}
	payload := HydraOAuthClient{
		ClientID:                    req.ClientID,
		ClientName:                  req.ClientName,
		GrantTypes:                  grants,
		ResponseTypes:               []string{"token"},
		Scope:                       req.Scope,
		Audience:                    req.Audience,
		Owner:                       req.Owner,
		TokenEndpointAuthMethod:     authMethod,
		TokenEndpointAuthSigningAlg: req.TokenEndpointAuthSigningAlg,
		JWKS:                        req.JWKS,
		AccessTokenLifespan:         req.AccessTokenLifespan,
	}
	// #nosec G117 -- client_secret is a legitimate field of the Hydra OAuth2 client-registration payload, not a leaked credential.
	body, err := json.Marshal(payload)
	if err != nil {
		return HydraOAuthClient{}, fmt.Errorf("marshal create-client: %w", err)
	}
	url := c.BaseURL + "/admin/clients"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return HydraOAuthClient{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return HydraOAuthClient{}, fmt.Errorf("hydra create-client: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode/100 != 2 {
		return HydraOAuthClient{}, hydraAPIError(resp.StatusCode, respBody)
	}
	var out HydraOAuthClient
	if err := json.Unmarshal(respBody, &out); err != nil {
		return HydraOAuthClient{}, fmt.Errorf("unmarshal hydra response: %w", err)
	}
	if out.ClientID == "" {
		return HydraOAuthClient{}, errors.New("hydra returned empty client_id")
	}
	return out, nil
}

// DeleteOAuthClient revokes an OAuth2 client. Returns nil on success or if
// Hydra returns 404 (idempotent).
func (c *HydraAdminClient) DeleteOAuthClient(ctx context.Context, clientID string) error {
	url := c.BaseURL + "/admin/clients/" + clientID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("hydra delete-client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return hydraAPIError(resp.StatusCode, body)
	}
	return nil
}

// GetOAuthClient fetches an OAuth2 client (without secret).
func (c *HydraAdminClient) GetOAuthClient(ctx context.Context, clientID string) (HydraOAuthClient, error) {
	url := c.BaseURL + "/admin/clients/" + clientID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HydraOAuthClient{}, err
	}
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return HydraOAuthClient{}, fmt.Errorf("hydra get-client: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNotFound {
		return HydraOAuthClient{}, ErrHydraClientNotFound
	}
	if resp.StatusCode/100 != 2 {
		return HydraOAuthClient{}, hydraAPIError(resp.StatusCode, body)
	}
	var out HydraOAuthClient
	if err := json.Unmarshal(body, &out); err != nil {
		return HydraOAuthClient{}, fmt.Errorf("unmarshal hydra response: %w", err)
	}
	return out, nil
}

// HydraAPIError — Hydra Admin returned non-2xx.
type HydraAPIError struct {
	StatusCode int
	Body       string
}

func (e *HydraAPIError) Error() string {
	return fmt.Sprintf("hydra admin api: status %d: %s", e.StatusCode, e.Body)
}

// ErrHydraClientNotFound — Hydra Admin 404 for GET / DELETE.
var ErrHydraClientNotFound = errors.New("hydra: oauth client not found")

func hydraAPIError(status int, body []byte) error {
	return &HydraAPIError{StatusCode: status, Body: string(body)}
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
