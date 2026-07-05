// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hydra_trust_grants.go — Ory Hydra Admin API for RFC 7523 jwt-bearer
// trust-grants (`POST /admin/trust/grants/jwt-bearer/issuers`).
//
// A federated SA-key (trusted_subjects non-empty) is a Hydra client with
// `grant_types=[jwt-bearer]`; for each trusted subject kacho-iam registers an
// EXACT-subject trust-grant so Hydra accepts an external assertion only when its
// `sub` equals the granted subject verbatim. `allow_any_subject` is always false
// — trusting an issuer must NOT mean trusting an arbitrary subject from it (any
// pod of the cluster would otherwise obtain a token).
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// JWTBearerTrustGrant — one exact-subject trust relationship registered with
// Hydra. Subject is the literal subject Hydra matches verbatim; AllowAnySubject
// is kept false by the federated Issue path.
type JWTBearerTrustGrant struct {
	Issuer          string
	Subject         string
	AllowAnySubject bool
	Scope           []string
	ExpiresAt       time.Time
}

// trustGrantPayload — the Hydra Admin request body.
type trustGrantPayload struct {
	Issuer          string   `json:"issuer"`
	Subject         string   `json:"subject,omitempty"`
	AllowAnySubject bool     `json:"allow_any_subject"`
	Scope           []string `json:"scope"`
	ExpiresAt       string   `json:"expires_at"`
}

// CreateJWTBearerTrustGrant registers an exact-subject jwt-bearer trust-grant.
func (c *HydraAdminClient) CreateJWTBearerTrustGrant(ctx context.Context, g JWTBearerTrustGrant) error {
	scope := g.Scope
	if scope == nil {
		scope = []string{}
	}
	payload := trustGrantPayload{
		Issuer:          g.Issuer,
		Subject:         g.Subject,
		AllowAnySubject: g.AllowAnySubject,
		Scope:           scope,
		ExpiresAt:       g.ExpiresAt.UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal trust-grant: %w", err)
	}
	url := c.BaseURL + "/admin/trust/grants/jwt-bearer/issuers"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("hydra create-trust-grant: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return hydraAPIError(resp.StatusCode, b)
	}
	return nil
}
