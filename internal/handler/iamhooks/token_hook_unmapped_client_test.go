// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_hook_unmapped_client_test.go — a token request whose credential IS the
// OAuth client must resolve to a kacho principal or be refused.
//
// The population these tests separate:
//
//   - MACHINE token request — `client_credentials` / `jwt-bearer`, or any request
//     whose subject is the OAuth client itself. The credential presented is the
//     client registration; every legitimate one of these was created by kacho-iam
//     together with its mapping row (SA key, user token, bootstrap, federation),
//     so "no mapping" means "not a kacho credential" and the only correct answer
//     is a refusal.
//   - INTERACTIVE token request — a human authenticated at the identity provider
//     and the subject is their identity, not a client id. Their kacho mirror is
//     provisioned asynchronously (the provision hook returns as soon as the
//     Operation is accepted), so the FIRST token after signup can legitimately be
//     minted before the User row commits. That request must still succeed.
//
// Every assertion here is on what the caller received — the status code and the
// response body — never on which collaborator was called.
package iamhooks_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// ─────────────────── programmable ports (production wiring shape) ───────────────────

// stubMappedSA — SA-mapping lookup. Zero value resolves NOTHING: that is exactly
// what the reader sees after a key is revoked (the row is deleted) and what it
// sees for a client that kacho-iam never registered.
type stubMappedSA struct {
	soc   domain.ServiceAccountOAuthClient
	found bool
	sa    domain.ServiceAccount
}

func (s stubMappedSA) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if s.found {
		return s.soc, nil
	}
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such oauth client")
}

func (s stubMappedSA) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return s.sa, nil
}

func (s stubMappedSA) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject")
}

// stubUserTokens — personal-access-token mapping lookup; resolves nothing.
type stubUserTokens struct{}

func (stubUserTokens) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.UserOAuthClient, error) {
	return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such user-token client")
}

func (stubUserTokens) GetUser(_ context.Context, _ domain.UserID) (domain.User, error) {
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such user")
}

// newFullyWiredTokenHook builds the handler the way the composition root does —
// SA port and user-token port both present — so "unmapped" means the stores were
// asked and had nothing, not that a lookup was skipped.
func newFullyWiredTokenHook(t *testing.T, users *fakeUserLookup, sas stubMappedSA, audit *fakeAudit) *iamhooks.TokenHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	).WithSAPort(sas).WithUserTokenPort(stubUserTokens{})
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

// postHookPayload marshals the provider payload and drives the hook.
func postHookPayload(t *testing.T, h *iamhooks.TokenHookHandler, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	return postTokenHook(t, h, string(body))
}

// extClaimsOf decodes the enriched claim map the hook handed back, or fails.
func extClaimsOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	claims, ok := resp.Session.AccessToken["ext_claims"].(map[string]any)
	require.True(t, ok, "ext_claims must be present")
	return claims
}

// clientCredentialsPayload — the shape the provider sends for
// `client_credentials`: there is no end user, so the subject IS the client id.
func clientCredentialsPayload(clientID string) map[string]any {
	return map[string]any{
		"session": map[string]any{
			"client_id": clientID,
			"id_token":  map[string]any{"subject": clientID},
			"cnf":       map[string]any{},
		},
		"request": map[string]any{
			"client_id":   clientID,
			"grant_types": []string{"client_credentials"},
			"payload":     map[string][]string{"grant_type": {"client_credentials"}},
		},
	}
}

// ─────────────────── the machine population: must NOT mint ───────────────────

// TestTokenHook_ClientCredentials_UnmappedClient_Refused — a client id that maps
// to no kacho subject must not obtain a token. Before the fix the hook answered
// 200 with a claim set carrying no principal id.
func TestTokenHook_ClientCredentials_UnmappedClient_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, clientCredentialsPayload("cli-nobody-knows"))

	require.Equal(t, http.StatusForbidden, w.Code,
		"an unmapped client must be refused a token; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_client",
		"the refusal names client authentication as what failed (RFC 6749 §5.2)")
	assert.NotContains(t, w.Body.String(), "ext_claims",
		"a refused request must carry no claim set at all")
}

// TestTokenHook_RevokedSAKey_OrphanedProviderClient_CannotMint — the second hole.
// Revoke deletes the mapping row and then asks the provider to delete the client;
// when that second step fails the client stays alive with no row behind it. What
// the surviving client sees on its next token request is exactly this: the stores
// resolve nothing. It must be refused — that is what makes the revocation
// effective at commit rather than whenever the provider is next reachable.
func TestTokenHook_RevokedSAKey_OrphanedProviderClient_CannotMint(t *testing.T) {
	audit := &fakeAudit{}
	// The mapping row is gone (revoke committed); the provider client survived.
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, clientCredentialsPayload("soc_orphaned_after_revoke"))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a revoked key whose provider client outlived it must not mint; body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "ext_claims")
}

// TestTokenHook_UnmappedClient_RefusalIsAudited — the refusal must leave a record.
// An orphaned or unknown client that keeps trying is the only signal an operator
// gets that a provider-side registration outlived its kacho row.
func TestTokenHook_UnmappedClient_RefusalIsAudited(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, clientCredentialsPayload("soc_orphaned_after_revoke"))
	require.Equal(t, http.StatusForbidden, w.Code)

	events := audit.Events()
	require.Len(t, events, 1, "the refusal must be recorded, and the issued-trail must not be")
	assert.Equal(t, "authn.token.denied", events[0].EventType)
	assert.Equal(t, "soc_orphaned_after_revoke", events[0].Payload["client_id"])
	assert.Equal(t, "principal_not_found", events[0].Payload["reason"],
		"the reason distinguishes an unresolvable credential from an expired one")
}

// TestTokenHook_JwtBearer_UnmappedAssertion_Refused — the federated machine grant.
// Neither the assertion's (issuer, subject) nor the client id resolves to a kacho
// service account, so there is no principal to mint for.
func TestTokenHook_JwtBearer_UnmappedAssertion_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	assertion := mkUnsignedJWT(t, map[string]any{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:stranger/infra:ref:refs/heads/main",
	})
	w := postHookPayload(t, h, map[string]any{
		"session": map[string]any{
			"client_id": "cli-not-ours",
			"id_token":  map[string]any{"subject": "repo:stranger/infra:ref:refs/heads/main"},
			"cnf":       map[string]any{},
		},
		"request": map[string]any{
			"client_id": "cli-not-ours",
			"payload": map[string][]string{
				"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				"assertion":  {assertion},
			},
		},
	})

	require.Equal(t, http.StatusForbidden, w.Code,
		"an assertion matching no trusted subject must not mint; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_client")
}

// TestTokenHook_ClientIsTheSubject_NoGrantTypeStated_Refused — the grant name is
// the primary discriminator, but it arrives in a form payload the provider is not
// obliged to forward. A request whose subject IS its own client id has no human
// behind it whatever the payload says, so it is refused on that second reading.
func TestTokenHook_ClientIsTheSubject_NoGrantTypeStated_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, map[string]any{
		"session": map[string]any{
			"client_id": "cli-nobody-knows",
			"id_token":  map[string]any{"subject": "cli-nobody-knows"},
		},
		"request": map[string]any{"client_id": "cli-nobody-knows"},
	})

	require.Equal(t, http.StatusForbidden, w.Code,
		"a self-subject client request must be refused even with no grant name; body: %s", w.Body.String())
}

// TestTokenHook_NoSubjectAtAll_UnmappedClient_Refused — the handler falls back to
// the client id when the payload carries no subject. Reaching the fallback proves
// there is no end user, so an unmapped client on that path is refused too.
func TestTokenHook_NoSubjectAtAll_UnmappedClient_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, map[string]any{
		"session": map[string]any{"client_id": "", "id_token": map[string]any{"subject": ""}},
		"request": map[string]any{"client_id": "cli-nobody-knows"},
	})

	require.Equal(t, http.StatusForbidden, w.Code,
		"a subject recovered from the client id, mapping to nothing, must be refused; body: %s", w.Body.String())
}

// ─────────────────── the machine population that DOES resolve: must still mint ───────────────────

// TestTokenHook_ClientCredentials_MappedSAKey_StillMints — the working machine
// path is untouched. A live SA key mints exactly as before, with its principal id.
func TestTokenHook_ClientCredentials_MappedSAKey_StillMints(t *testing.T) {
	audit := &fakeAudit{}
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
	}, audit)

	w := postHookPayload(t, h, clientCredentialsPayload("soc_01abcdefghjkmnpqr"))

	require.Equal(t, http.StatusOK, w.Code, "a live SA key must still mint; body: %s", w.Body.String())
	claims := extClaimsOf(t, w)
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
	assert.Equal(t, "sva_01abcdefghjkmnpqr", claims["kacho_principal_id"])
	assert.Equal(t, "acc_01abcdefghjkmnpqr", claims["kacho_account_id"])
}

// ─────────────────── the interactive population: must still mint ───────────────────

// TestTokenHook_InteractiveFirstLogin_MirrorNotMaterialized_StillMints — the flow
// the refusal must NOT touch. The provision hook accepts the Operation and returns;
// the bootstrap transaction that writes the User row runs after that, so the first
// token of a freshly registered human can be requested before the row exists. The
// subject here is the identity, not a client id — there IS a human behind it — and
// the reduced claim set is what carries them until the mirror catches up.
func TestTokenHook_InteractiveFirstLogin_MirrorNotMaterialized_StillMints(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, map[string]any{
		"session": map[string]any{
			"client_id": "kacho-ui",
			"id_token":  map[string]any{"subject": "kratos-identity-just-registered"},
			"acr":       "2",
		},
		"request": map[string]any{
			"client_id":      "kacho-ui",
			"granted_scopes": []string{"openid"},
			"payload":        map[string][]string{"grant_type": {"authorization_code"}},
		},
	})

	require.Equal(t, http.StatusOK, w.Code,
		"a human whose mirror has not committed yet must still receive a token; body: %s", w.Body.String())
	claims := extClaimsOf(t, w)
	assert.Equal(t, "kratos-identity-just-registered", claims["kacho_external_id"])
}

// TestTokenHook_InteractiveRefreshOfUnmirroredIdentity_StillMints — same
// population reached by the other interactive grant.
func TestTokenHook_InteractiveRefreshOfUnmirroredIdentity_StillMints(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, map[string]any{
		"session": map[string]any{
			"client_id": "kacho-ui",
			"id_token":  map[string]any{"subject": "kratos-identity-just-registered"},
		},
		"request": map[string]any{
			"client_id": "kacho-ui",
			"payload":   map[string][]string{"grant_type": {"refresh_token"}},
		},
	})

	require.Equal(t, http.StatusOK, w.Code,
		"the interactive refresh grant keeps the reduced claim set; body: %s", w.Body.String())
}
