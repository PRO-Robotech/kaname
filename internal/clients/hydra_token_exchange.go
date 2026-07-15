// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hydra_token_exchange.go — client for the Ory Hydra PUBLIC OAuth2 token
// endpoint (`POST /oauth2/token`). Used by the Docker Registry v2 `/iam/token`
// shim: the shim signs an ES256 client_assertion from the presented SA-key and
// brokers a `client_credentials` + `private_key_jwt` exchange, returning Hydra's
// access_token to the docker client. kacho-iam no longer mints registry tokens
// itself — Hydra is the issuer/signer. (The data-plane verifies that token against
// Hydra's JWKS, which iam mirrors on a separate cluster-internal jwks-proxy
// listener — internal/handler/jwksproxyhttp — never re-signing anything.)
//
// Failure classification (fail-closed, no-leak):
//   - network failure / timeout / 5xx / malformed 2xx  → ErrHydraUnavailable
//     (the issuer is a hard dependency of the mint path; the shim returns 503).
//   - 4xx OAuth2 error (invalid_client / invalid_grant) → ErrHydraRejected
//     (bad/expired/revoked credential; the shim returns a 401 challenge).
//
// The raw Hydra body is never embedded in the returned sentinel (no auth oracle).
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrHydraUnavailable — the Hydra token endpoint is unreachable or misbehaving
// (network / timeout / 5xx / malformed response). Fail-closed: no token.
var ErrHydraUnavailable = errors.New("hydra token endpoint unavailable")

// ErrHydraRejected — Hydra rejected the exchange (4xx OAuth2 error). The
// credential is invalid / expired / revoked; the client re-authenticates.
var ErrHydraRejected = errors.New("hydra rejected the token exchange")

// HydraTokenClient — HTTP client for the Hydra public `/oauth2/token` endpoint.
type HydraTokenClient struct {
	// TokenURL — the FULL token endpoint URL the shim POSTs to (cluster-internal
	// in production, e.g. http://kacho-umbrella-hydra-public.<ns>.svc:4444/oauth2/token).
	TokenURL   string
	HTTPClient *http.Client
}

// NewHydraTokenClient — constructor (default timeout 10s).
func NewHydraTokenClient(tokenURL string) *HydraTokenClient {
	return &HydraTokenClient{
		TokenURL:   tokenURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// ClientCredentialsRequest — inputs for the private_key_jwt exchange.
type ClientCredentialsRequest struct {
	// ClientAssertion — the signed ES256 JWS (RFC 7523) proving possession of the
	// SA-key private half; identifies the Hydra client (iss=sub=client_id).
	ClientAssertion string
	// Audience — requested `aud` for the minted token (the registry service).
	// Empty → not sent (Hydra falls back to the client's configured audience).
	Audience string
	// Scope — requested scope. Empty → not sent.
	Scope string
}

// TokenResponse — the subset of the Hydra token response the shim relays.
type TokenResponse struct {
	AccessToken string
	ExpiresIn   int
}

// ClientCredentials brokers a `grant_type=client_credentials` exchange with a
// `private_key_jwt` client_assertion and returns Hydra's access_token.
func (c *HydraTokenClient) ClientCredentials(ctx context.Context, req ClientCredentialsRequest) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", req.ClientAssertion)
	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}
	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: build token request: %v", ErrHydraUnavailable, err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		// Network failure / timeout / connection refused — issuer down.
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrHydraUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch resp.StatusCode / 100 {
	case 2:
		var parsed struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
			// A 2xx that is not a well-formed token response is treated as a
			// misbehaving issuer (fail-closed), never a silent empty token.
			return TokenResponse{}, fmt.Errorf("%w: malformed token response", ErrHydraUnavailable)
		}
		return TokenResponse{AccessToken: parsed.AccessToken, ExpiresIn: parsed.ExpiresIn}, nil
	case 4:
		// OAuth2 client/grant rejection — invalid/expired/revoked credential.
		// The raw body is intentionally NOT included (no auth oracle).
		return TokenResponse{}, ErrHydraRejected
	default:
		// 5xx and anything else — issuer failure.
		return TokenResponse{}, fmt.Errorf("%w: token endpoint status %d", ErrHydraUnavailable, resp.StatusCode)
	}
}
