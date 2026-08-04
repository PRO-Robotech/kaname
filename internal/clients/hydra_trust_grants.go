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
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// trustGrantPath — общий префикс обеих операций. Назван один раз: постановка и
// снятие обязаны адресовать один и тот же ресурс, а две строки разъезжаются.
const trustGrantPath = "/admin/trust/grants/jwt-bearer/issuers"

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

// CreateJWTBearerTrustGrant registers an exact-subject jwt-bearer trust-grant and
// returns the identifier the provider assigned to it.
//
// WHY THE IDENTIFIER IS RETURNED AT ALL. Registering trust for N subjects is a
// fan-out of N independent calls, and the provider has no notion of the group.
// A failure on call k leaves k-1 grants standing, and the ONLY coordinate by
// which any of them can later be withdrawn is the identifier the provider
// assigned. Discarding it — as this method used to — made the leak
// irreversible by construction: the grants existed, nothing in our database
// named them, and no method to remove them existed either.
func (c *HydraAdminClient) CreateJWTBearerTrustGrant(ctx context.Context, g JWTBearerTrustGrant) (string, error) {
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
		return "", fmt.Errorf("marshal trust-grant: %w", err)
	}
	url := c.BaseURL + trustGrantPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("hydra create-trust-grant: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode/100 != 2 {
		return "", hydraAPIError(resp.StatusCode, respBody)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("unmarshal trust-grant response: %w", err)
	}
	if out.ID == "" {
		// Грант создан, а координаты снятия нет. Молчать нельзя: вызывающий
		// обязан узнать, что этот грант он убрать не сможет, — иначе «успех»
		// означал бы, что компенсация покрывает всё, а она не покроет.
		return "", errors.New("hydra returned a trust-grant without an id: " +
			"the grant exists and cannot be withdrawn by any coordinate")
	}
	return out.ID, nil
}

// DeleteJWTBearerTrustGrant withdraws a previously registered trust-grant by the
// identifier the provider assigned to it.
//
// IDEMPOTENT BY CONTRACT: a grant that is already gone answers 404, and 404 is
// reported as success. Compensation is delivered at least once, so a second
// delivery must not turn a completed withdrawal into a failure that retries
// forever.
func (c *HydraAdminClient) DeleteJWTBearerTrustGrant(ctx context.Context, grantID string) error {
	if grantID == "" {
		return errors.New("hydra delete-trust-grant: grant id required")
	}
	url := c.BaseURL + trustGrantPath + "/" + grantID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("hydra delete-trust-grant: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return hydraAPIError(resp.StatusCode, b)
	}
	return nil
}
