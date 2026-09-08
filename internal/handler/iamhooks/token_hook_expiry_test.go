// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_hook_expiry_test.go — what the provider gets back when the credential
// behind the token request has expired.
//
// This is the OBSERVABLE half of the expiry gate: the enricher's sentinel is
// worth nothing unless the hook turns it into a refusal Hydra honours. Ory
// Hydra denies the token request when the token hook answers 403 (any other
// non-2xx becomes a server error); the sibling refresh hook already relies on
// exactly that. So these tests assert the HTTP status, the body, the ABSENCE
// of minted claims, and the audit trail — not that some function was called.
package iamhooks_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// expirySAPort — SA-key mapping resolved by Hydra client_id (the
// client_credentials shape), carrying a programmable expiry.
type expirySAPort struct {
	soc domain.ServiceAccountOAuthClient
	sa  domain.ServiceAccount
}

func (p expirySAPort) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return p.soc, nil
}

func (p expirySAPort) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return p.sa, nil
}

func (p expirySAPort) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

// newExpiryTokenHook wires a token hook over an SA mapping expiring at
// expiresAt. Wall-clock is used deliberately: the callers pass instants far
// enough from now that the verdict cannot flip on a slow machine.
func newExpiryTokenHook(t *testing.T, expiresAt *time.Time, audit *fakeAudit) *iamhooks.TokenHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	saPort := expirySAPort{
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "soc_01abcdefghjkmnpqr",
			SvaID:          "sva_01abcdefghjkmnpqr",
			OAuthClientID:  "kacho-sak-expiry",
			ExpiresAt:      expiresAt,
		},
		sa: domain.ServiceAccount{
			ID:        "sva_01abcdefghjkmnpqr",
			AccountID: "acc_01abcdefghjkmnpqr",
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{},
	).WithSAPort(saPort)
	return iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{
			HookSharedSecret: "secret-hook-token",
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		},
		enricher,
		newFakeRevocations(),
		audit,
		logger,
	)
}

// clientCredentialsHookBody — the payload Hydra posts for a client_credentials
// grant: no end-user subject, the client_id in its place.
func clientCredentialsHookBody(t *testing.T, clientID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"session": map[string]any{
			"client_id": clientID,
			"acr":       "0",
		},
		"request": map[string]any{
			"client_id":      clientID,
			"granted_scopes": []string{},
			"grant_types":    []string{"client_credentials"},
			"payload":        map[string][]string{"grant_type": {"client_credentials"}},
		},
	})
	require.NoError(t, err)
	return string(body)
}

func postTokenHook(t *testing.T, h *iamhooks.TokenHookHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func auditEventTypes(events []iamhooks.AuditEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType)
	}
	return out
}

// TestTokenHook_ExpiredSAKey_Denied — the caller-visible contract for an
// expired service-account key: 403 with an `invalid_client` body (RFC 6749 §5.2
// — client authentication failed), and NOT a single claim minted.
func TestTokenHook_ExpiredSAKey_Denied(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)
	audit := &fakeAudit{}
	h := newExpiryTokenHook(t, &expired, audit)

	rec := postTokenHook(t, h, clientCredentialsHookBody(t, "kacho-sak-expiry"))

	require.Equal(t, http.StatusForbidden, rec.Code,
		"Hydra denies the token request only on 403; anything else mints the token or 500s")
	assert.JSONEq(t, `{"error":"invalid_client"}`, strings.TrimSpace(rec.Body.String()),
		"the deny body is the diagnostic Hydra surfaces to the operator")
	assert.NotContains(t, rec.Body.String(), "ext_claims",
		"a denied request must not carry an enriched claim set")

	types := auditEventTypes(audit.Events())
	assert.Contains(t, types, "authn.token.denied",
		"a refused credential must leave an audit trail")
	assert.NotContains(t, types, "authn.token.issued",
		"nothing was issued — the issued-trail must not be written")
}

// TestTokenHook_LiveSAKey_Issues — the same wiring with life left mints as
// before. Without this the deny test could pass by denying everything.
func TestTokenHook_LiveSAKey_Issues(t *testing.T) {
	live := time.Now().Add(24 * time.Hour)
	audit := &fakeAudit{}
	h := newExpiryTokenHook(t, &live, audit)

	rec := postTokenHook(t, h, clientCredentialsHookBody(t, "kacho-sak-expiry"))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	claims, ok := resp.Session.AccessToken["ext_claims"].(map[string]any)
	require.True(t, ok, "a live key must still enrich")
	assert.Equal(t, "sva_01abcdefghjkmnpqr", claims["kaname_principal_id"])
	assert.Contains(t, auditEventTypes(audit.Events()), "authn.token.issued")
}

// TestTokenHook_NonExpiringSAKey_Issues — a NULL expiry stays non-expiring.
// This is the bootstrap-admin row shape (mint #58 inserts its mapping with no
// expiry), so a regression here takes the cluster-admin credential offline.
func TestTokenHook_NonExpiringSAKey_Issues(t *testing.T) {
	audit := &fakeAudit{}
	h := newExpiryTokenHook(t, nil, audit)

	rec := postTokenHook(t, h, clientCredentialsHookBody(t, "kacho-sak-expiry"))

	require.Equal(t, http.StatusOK, rec.Code,
		"a key with no stated expiry must keep working (bootstrap-admin / pre-TTL rows)")
	assert.Contains(t, rec.Body.String(), "kaname_principal_id")
}
