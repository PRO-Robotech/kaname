// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_hook_federated_test.go — Phase 3b federation IN: verifies the
// handler decodes the jwt-bearer assertion's `iss` claim and forwards it
// through TokenHookContext.ExternalIssuer + GrantType so the enricher can
// dispatch to the federated SA path.
package iamhooks_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// fakeSAPort records the FindByExternalSubject call so the test can assert
// the handler forwarded (iss, sub) through the hookCtx as expected.
type fakeSAPort struct {
	mu        sync.Mutex
	lookups   []struct{ Iss, Sub string }
	mapping   domain.ServiceAccountOAuthClient
	mappingOK bool
	sa        domain.ServiceAccount
}

func (f *fakeSAPort) LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "not found")
}
func (f *fakeSAPort) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return f.sa, nil
}
func (f *fakeSAPort) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, struct{ Iss, Sub string }{issuer, sub})
	if f.mappingOK {
		return f.mapping, nil
	}
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject")
}

func mustB64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// mkUnsignedJWT builds a `header.payload.<empty>` token. Hydra has already
// verified the signature; the kaname handler decodes the claim body only.
func mkUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	require.NoError(t, err)
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	return mustB64URL(hdr) + "." + mustB64URL(body) + ".sig"
}

func TestTokenHook_FederatedPath_ForwardsIssuerToEnricher(t *testing.T) {
	users := &fakeUserLookup{}
	saPort := &fakeSAPort{
		mappingOK: true,
		mapping: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "soc_01abcdefghjkmnpqr",
			SvaID:          "sva_01abcdefghjkmnpqr",
		},
		sa: domain.ServiceAccount{
			ID:        "sva_01abcdefghjkmnpqr",
			AccountID: "acc_01abcdefghjkmnpqr",
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	).WithSAPort(saPort)
	h := iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{HookSharedSecret: "tok", Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		enricher,
		newFakeRevocations(),
		&fakeAudit{},
		logger,
	)

	assertion := mkUnsignedJWT(t, map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:acme/infra:ref:refs/heads/main",
	})
	// External assertion's `sub` ends up as the session's token subject.
	payload := map[string]any{
		"session": map[string]any{
			"client_id": "hydra-cli-fake",
			"id_token":  map[string]any{"subject": "repo:acme/infra:ref:refs/heads/main"},
			"cnf":       map[string]any{},
		},
		"request": map[string]any{
			"client_id":   "hydra-cli-fake",
			"grant_types": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"payload": map[string][]string{
				"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				"assertion":  {assertion},
			},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(string(body)))
	req.Header.Set("X-Kacho-Hook-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// Enricher must have been asked for the (issuer, sub) tuple.
	require.Len(t, saPort.lookups, 1)
	assert.Equal(t, "https://token.actions.githubusercontent.com", saPort.lookups[0].Iss)
	assert.Equal(t, "repo:acme/infra:ref:refs/heads/main", saPort.lookups[0].Sub)

	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	claims, ok := resp.Session.AccessToken["ext_claims"].(map[string]any)
	require.True(t, ok, "ext_claims must be present")

	assert.Equal(t, "service_account", claims["kaname_principal_type"])
	assert.Equal(t, "sva_01abcdefghjkmnpqr", claims["kaname_principal_id"])
	assert.Equal(t, "https://token.actions.githubusercontent.com", claims["kaname_federation_issuer"])
	assert.Equal(t, "repo:acme/infra:ref:refs/heads/main", claims["kaname_federation_subject"])
	assert.Equal(t, "jwt-bearer", claims["kaname_federation_mode"])
	assert.Equal(t, "hydra-cli-fake", claims["kaname_hydra_client_id"])
}

// TestTokenHook_NonFederatedRequest_NoExternalIssuerForwarded — when grant
// type is client_credentials the handler must NOT attempt to extract an
// assertion issuer (no assertion present). The federated lookup MUST stay
// empty so Phase 3a behaviour is preserved.
//
// The client used here maps to nothing (fakeSAPort resolves neither lookup), so
// the request is also refused — see token_hook_unmapped_client_test.go for that
// contract. What this test pins is the absence of the federated lookup, which
// holds either way.
func TestTokenHook_NonFederatedRequest_NoExternalIssuerForwarded(t *testing.T) {
	users := &fakeUserLookup{}
	saPort := &fakeSAPort{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "x", HydraIssuer: "y"},
		users,
	).WithSAPort(saPort)
	h := iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{HookSharedSecret: "tok", Domain: "x", HydraIssuer: "y"},
		enricher,
		newFakeRevocations(),
		&fakeAudit{},
		logger,
	)
	payload := map[string]any{
		"session": map[string]any{
			"client_id": "hydra-cli-fake",
			"id_token":  map[string]any{"subject": "hydra-cli-fake"},
			"cnf":       map[string]any{},
		},
		"request": map[string]any{
			"client_id":   "hydra-cli-fake",
			"grant_types": []string{"client_credentials"},
			"payload": map[string][]string{
				"grant_type": {"client_credentials"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(string(body)))
	req.Header.Set("X-Kacho-Hook-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"the client resolves to nothing, so the request is refused — and a missing assertion is not what "+
			"decides that, nor is it a server error; body: %s", w.Body.String())
	saPort.mu.Lock()
	defer saPort.mu.Unlock()
	require.Len(t, saPort.lookups, 0, "federated lookup must NOT happen for client_credentials")
}
