// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_hook_provider_body_test.go — the hook is driven with the body the
// provider actually posts, key for key.
//
// Every other token-hook test in this package states the subject in places the
// provider never fills, so the corpus could stay green while the handler read
// nothing at all from a live request. The bodies here are built from the
// provider's own request type: the exchange it describes carries
//
//	{"session": {"id_token": {"subject": …}, "client_id": …},
//	 "request": {"client_id": …, "grant_types": […], "payload": {…}}}
//
// — the identity of the human sits INSIDE the token-shaped part of the session,
// and the grant the exchange ran under is a field of the request in its own
// right, not an echo of the submitted form.
package iamhooks_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// grantJWTBearer — the federated machine grant, spelled the way the protocol
// spells it (RFC 7523 §2.1).
const grantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// providerBody assembles a token-hook body in the provider's shape.
//
// endUserSubject is placed where the provider places it and NOWHERE else, so a
// handler that reads any other location sees a subjectless request. Pass "" for
// the grants that carry no end user.
func providerBody(clientID, endUserSubject string, grantTypes []string, form map[string][]string) map[string]any {
	return map[string]any{
		"session": map[string]any{
			"id_token":  map[string]any{"subject": endUserSubject},
			"extra":     map[string]any{},
			"client_id": clientID,
		},
		"request": map[string]any{
			"client_id":        clientID,
			"granted_scopes":   []string{},
			"granted_audience": []string{},
			"grant_types":      grantTypes,
			"payload":          form,
		},
	}
}

// newTokenHookWithSAPort wires the handler against the recording SA port, so a
// test can assert whether the federated (issuer, subject) lookup happened.
func newTokenHookWithSAPort(t *testing.T, users *fakeUserLookup, sas *fakeSAPort, audit *fakeAudit) *iamhooks.TokenHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	).WithSAPort(sas)
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

// TestTokenHook_ProviderBody_InteractiveIdentity_ResolvesToItsUser — the
// location the subject is read from decides WHO the token belongs to. Read from
// anywhere else the request looks subjectless, the handler adopts the client id
// in its place, and the token comes back belonging to nobody — or, once a
// machine credential that resolves to nothing is refused, does not come back at
// all: every interactive login falls into that refusal.
func TestTokenHook_ProviderBody_InteractiveIdentity_ResolvesToItsUser(t *testing.T) {
	users := &fakeUserLookup{users: []domain.User{{
		ID:           "usr_01abcdefghjkmnpqr",
		AccountID:    "acc_01abcdefghjkmnpqr",
		ExternalID:   "kratos-uuid-1",
		InviteStatus: domain.InviteStatusActive,
	}}}
	h := newFullyWiredTokenHook(t, users, stubMappedSA{}, &fakeAudit{})

	w := postHookPayload(t, h, providerBody(
		"kacho-ui",
		"kratos-uuid-1",
		[]string{"authorization_code"},
		map[string][]string{"grant_type": {"authorization_code"}},
	))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	claims := extClaimsOf(t, w)
	assert.Equal(t, "user", claims["kacho_principal_type"])
	assert.Equal(t, "usr_01abcdefghjkmnpqr", claims["kacho_principal_id"])
	assert.Equal(t, "acc_01abcdefghjkmnpqr", claims["kacho_active_account"])
}

// TestTokenHook_ProviderBody_ClientCredentials_SubjectlessSession_MappedSAKey_StillMints
// — the machine grant, driven through the subjectless branch.
//
// The provider actually states the client id as the subject of such an
// exchange (there is no end user, so it puts the client there), and
// clientCredentialsPayload models THAT. This body models the other reading the
// handler tolerates — a session with no subject at all — and pins that the
// client id is adopted from the request instead, so a live mapping row mints
// either way.
func TestTokenHook_ProviderBody_ClientCredentials_SubjectlessSession_MappedSAKey_StillMints(t *testing.T) {
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{
		found: true,
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "soc_01abcdefghjkmnpqr",
			SvaID:          "sva_01abcdefghjkmnpqr",
			OAuthClientID:  "soc_01abcdefghjkmnpqr",
		},
		sa: domain.ServiceAccount{
			ID:        "sva_01abcdefghjkmnpqr",
			AccountID: "acc_01abcdefghjkmnpqr",
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}, &fakeAudit{})

	w := postHookPayload(t, h, providerBody(
		"soc_01abcdefghjkmnpqr",
		"",
		[]string{"client_credentials"},
		map[string][]string{"grant_type": {"client_credentials"}},
	))

	require.Equal(t, http.StatusOK, w.Code, "a live SA key must still mint; body: %s", w.Body.String())
	claims := extClaimsOf(t, w)
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
	assert.Equal(t, "sva_01abcdefghjkmnpqr", claims["kacho_principal_id"])
}

// ───────────── which grant ran: the provider's word, not the client's form ─────────────

// The form the client submitted reaches us only because the provider currently
// chooses to forward that key; the list of forwarded parameters is its
// decision, not ours, and it sanitises the form before sending. The grant the
// exchange actually ran under is a field of the request in its own right. The
// tests below state ONLY that field, so a handler still reading the echo sees a
// request with no grant name at all.

// TestTokenHook_ProviderBody_JwtBearer_StatedOnlyAuthoritatively_Refused — the
// federated machine grant is the one that has no second signal: its subject is
// the external assertion's, so it neither is the client id nor is missing. Lose
// the grant name and nothing else in the body says "machine" — an assertion
// matching no trusted subject mints instead of being refused.
func TestTokenHook_ProviderBody_JwtBearer_StatedOnlyAuthoritatively_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	assertion := mkUnsignedJWT(t, map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:stranger/infra:ref:refs/heads/main",
	})
	w := postHookPayload(t, h, providerBody(
		"cli-not-ours",
		"repo:stranger/infra:ref:refs/heads/main",
		[]string{grantJWTBearer},
		map[string][]string{"assertion": {assertion}},
	))

	require.Equal(t, http.StatusForbidden, w.Code,
		"an assertion matching no trusted subject must not mint; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_client")
}

// TestTokenHook_ProviderBody_JwtBearer_StatedOnlyAuthoritatively_ResolvesFederatedSubject
// — the same field also decides whether the assertion is opened at all. A
// federated service account is found by (issuer, subject) taken from inside the
// assertion, and that only happens for a request recognised as this grant.
func TestTokenHook_ProviderBody_JwtBearer_StatedOnlyAuthoritatively_ResolvesFederatedSubject(t *testing.T) {
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
	h := newTokenHookWithSAPort(t, &fakeUserLookup{}, saPort, &fakeAudit{})

	assertion := mkUnsignedJWT(t, map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:acme/infra:ref:refs/heads/main",
	})
	w := postHookPayload(t, h, providerBody(
		"hydra-cli-fake",
		"repo:acme/infra:ref:refs/heads/main",
		[]string{grantJWTBearer},
		map[string][]string{"assertion": {assertion}},
	))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	saPort.mu.Lock()
	defer saPort.mu.Unlock()
	require.Len(t, saPort.lookups, 1, "the assertion must have been opened and its issuer looked up")
	assert.Equal(t, "https://token.actions.githubusercontent.com", saPort.lookups[0].Iss)
	assert.Equal(t, "repo:acme/infra:ref:refs/heads/main", saPort.lookups[0].Sub)
}

// TestTokenHook_ProviderBody_ClientCredentials_StatedOnlyAuthoritatively_Refused
// — same reading for the non-federated machine grant, isolated from the other
// two signals: the subject is present and is not either client id.
func TestTokenHook_ProviderBody_ClientCredentials_StatedOnlyAuthoritatively_Refused(t *testing.T) {
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, &fakeAudit{})

	w := postHookPayload(t, h, providerBody(
		"cli-nobody-knows",
		"a-subject-that-is-not-the-client",
		[]string{"client_credentials"},
		map[string][]string{},
	))

	require.Equal(t, http.StatusForbidden, w.Code,
		"the grant the provider states is enough to know there is no human; body: %s", w.Body.String())
}

// TestTokenHook_ProviderBody_FormGrantNameStillHonoured — the echo remains a
// fallback rather than being dropped: the provider is free to stop forwarding
// it, but while it does, a request that states the grant ONLY there is still
// read correctly.
func TestTokenHook_ProviderBody_FormGrantNameStillHonoured(t *testing.T) {
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, &fakeAudit{})

	w := postHookPayload(t, h, providerBody(
		"cli-nobody-knows",
		"a-subject-that-is-not-the-client",
		nil,
		map[string][]string{"grant_type": {"client_credentials"}},
	))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a machine grant named only in the submitted form is still a machine grant; body: %s", w.Body.String())
}
