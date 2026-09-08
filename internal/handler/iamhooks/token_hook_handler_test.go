// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

import (
	"context"
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
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type fakeUserLookup struct {
	users []domain.User
	err   error
}

// FindByExternalID returns every row for the identity, whatever its state —
// the shape the wired repository returns, so a blocked row reaches the handler
// exactly as it does in production. The fake used to expose only an
// ACTIVE-named method that did NOT filter on the state, which handed the
// handler rows the real query would never return and kept a test green over a
// branch production could not reach.
func (f *fakeUserLookup) FindByExternalID(_ context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]domain.User, 0, len(f.users))
	for _, u := range f.users {
		if u.ExternalID == externalID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeUserLookup) GetByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return domain.User{}, nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []iamhooks.AuditEvent
}

func (f *fakeAudit) Emit(ctx context.Context, evt iamhooks.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evt)
	return nil
}

func (f *fakeAudit) Events() []iamhooks.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]iamhooks.AuditEvent, len(f.events))
	copy(out, f.events)
	return out
}

func newTokenHookHandler(t *testing.T, users *fakeUserLookup, audit *fakeAudit) *iamhooks.TokenHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{
			Domain:      "api.test.cloud",
			HydraIssuer: "https://hydra.test.cloud",
		},
		users,
	)
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

func TestTokenHook_HappyPath_EnrichesClaims(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			Email:        "alice@example.com",
			InviteStatus: domain.InviteStatusActive,
		}},
	}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	payload := map[string]any{
		"session": map[string]any{
			"client_id": "kacho-ui",
			"id_token":  map[string]any{"subject": "kratos-uuid-1"},
			"auth_time": int64(1700000000),
			"acr":       "2",
			"cnf": map[string]any{
				"jkt": "abc-thumbprint",
			},
		},
		"request": map[string]any{
			"client_id":      "kacho-ui",
			"granted_scopes": []string{"openid", "webauthn"},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(string(body)))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	claims, ok := resp.Session.AccessToken["ext_claims"].(map[string]any)
	require.True(t, ok, "ext_claims must be present")
	assert.Equal(t, "kratos-uuid-1", claims["kaname_external_id"])
	assert.Equal(t, "usr_01abcdefghjkmnpqr", claims["kaname_user_id"])
	assert.Equal(t, "acc_01abcdefghjkmnpqr", claims["kaname_active_account"])
	assert.Equal(t, "user", claims["kaname_principal_type"])
	assert.Equal(t, "attested", claims["kaname_device_compliance"]) // webauthn scope
	assert.Equal(t, "abc-thumbprint", claims["kaname_jkt"])
	assert.Equal(t, "api.test.cloud", claims["kaname_audience"])
	assert.Equal(t, "https://hydra.test.cloud", claims["kaname_issuer"])

	// Audit emitted.
	require.Len(t, audit.Events(), 1)
	assert.Equal(t, "authn.token.issued", audit.Events()[0].EventType)
}

func TestTokenHook_MissingBearer_Rejected(t *testing.T) {
	users := &fakeUserLookup{}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(`{"subject":"x"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_hook_token")
}

func TestTokenHook_WrongBearer_Rejected(t *testing.T) {
	users := &fakeUserLookup{}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(`{"subject":"x"}`))
	req.Header.Set("X-Kacho-Hook-Token", "wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTokenHook_MissingSubject_BadRequest(t *testing.T) {
	users := &fakeUserLookup{}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(`{}`))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing_subject")
}

// emptySubjectClientCredentialsPayload — client_credentials (RFC 6749 §4.4)
// carries no end user. The provider fills the session subject with the client
// id for exactly that reason; this body omits it entirely, which is the branch
// where the client id has to be adopted from the request instead.
func emptySubjectClientCredentialsPayload(clientID string) map[string]any {
	return map[string]any{
		"session": map[string]any{
			"client_id": clientID,
			"id_token":  map[string]any{"subject": ""},
		},
		"request": map[string]any{
			"client_id":   clientID,
			"grant_types": []string{"client_credentials"},
			"payload":     map[string][]string{"grant_type": {"client_credentials"}},
		},
	}
}

// TestTokenHook_ClientCredentials_EmptySubject_FallsBackToClientID — the kacho
// principal of such a token is the service account behind the OAuth client, so
// the handler must adopt the client id as the subject rather than reject the
// request as subjectless.
//
// The client is MAPPED here on purpose. That is what makes the test say what it
// is about and nothing else: the enricher can only find that service account by
// looking the client id up as the subject, so a mint carrying its principal id
// IS the evidence of the fallback — and the outcome is an exact status that
// does not move with the refusal of unresolvable credentials. The unmapped
// variant of this same body is the test below.
func TestTokenHook_ClientCredentials_EmptySubject_FallsBackToClientID(t *testing.T) {
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{
		found: true,
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "soc_01abcdefghjkmnpqr",
			SvaID:          "sva_01abcdefghjkmnpqr",
			OAuthClientID:  "cc-client-uuid",
		},
		sa: domain.ServiceAccount{
			ID:        "sva_01abcdefghjkmnpqr",
			AccountID: "acc_01abcdefghjkmnpqr",
			// This account may authenticate; the refusal under test is a different one.
			Enabled: true,
		},
	}, &fakeAudit{})

	w := postHookPayload(t, h, emptySubjectClientCredentialsPayload("cc-client-uuid"))

	require.Equal(t, http.StatusOK, w.Code,
		"empty-subject client_credentials must fall back to client_id, not be rejected as subjectless; body: %s",
		w.Body.String())
	assert.NotContains(t, w.Body.String(), "missing_subject")
	claims := extClaimsOf(t, w)
	assert.Equal(t, "cc-client-uuid", claims["kaname_external_id"],
		"the subject the handler proceeded with is the client id it fell back to")
	assert.Equal(t, "sva_01abcdefghjkmnpqr", claims["kaname_principal_id"],
		"only a lookup keyed on the adopted client id could have reached this service account")
}

// TestTokenHook_ClientCredentials_EmptySubject_UnmappedClient_Refused — the same
// body with nothing behind the client. The fallback still happens; what changes
// is that the adopted subject resolves to no principal, and the answer to that
// is a refusal naming client authentication as what failed.
func TestTokenHook_ClientCredentials_EmptySubject_UnmappedClient_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{}, audit)

	w := postHookPayload(t, h, emptySubjectClientCredentialsPayload("cc-client-uuid"))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a client that resolves to no principal must not mint; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_client")
	assert.NotContains(t, w.Body.String(), "missing_subject",
		"the request was refused for what its credential resolves to, not for lacking a subject")

	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.token.denied", events[0].EventType)
	assert.Equal(t, "cc-client-uuid", events[0].Payload["subject"],
		"the record names the subject the handler proceeded with — the client id it fell back to")
}

func TestTokenHook_UserNotFound_EmitsMinimalClaims(t *testing.T) {
	users := &fakeUserLookup{} // no users — FindActiveByExternalID returns empty
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	body := []byte(`{"session":{"id_token":{"subject":"unknown-sub"}},"request":{}}`)
	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(string(body)))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	claims := resp.Session.AccessToken["ext_claims"].(map[string]any)
	assert.Equal(t, "unknown-sub", claims["kaname_external_id"])
	assert.Equal(t, "user", claims["kaname_principal_type"],
		"the reduced set is for a human whose mirror has not committed yet")
	assert.Empty(t, claims["kaname_principal_id"],
		"it names no kacho principal, which is what makes it authorize nothing")
}

func TestTokenHook_MethodNotAllowed(t *testing.T) {
	h := newTokenHookHandler(t, &fakeUserLookup{}, &fakeAudit{})

	req := httptest.NewRequest("GET", "/iam/v1/hooks/token", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestTokenHook_BodyDecodeError(t *testing.T) {
	h := newTokenHookHandler(t, &fakeUserLookup{}, &fakeAudit{})

	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(`not-json`))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenHook_EmptyHookSecret_FailsClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "x", HydraIssuer: "y"},
		&fakeUserLookup{},
	)
	h := iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{HookSharedSecret: "", Domain: "x", HydraIssuer: "y"},
		enricher,
		newFakeRevocations(),
		&fakeAudit{},
		logger,
	)
	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(`{}`))
	req.Header.Set("X-Kacho-Hook-Token", "anything")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "empty configured secret must fail-closed")
}

// TestTokenHook_OversizedBody_413 — post-auth body-size cap on the token hook
// (CWE-770 guard; shared decodeHookBody helper).
func TestTokenHook_OversizedBody_413(t *testing.T) {
	users := &fakeUserLookup{}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	huge := strings.Repeat("a", (1<<20)+4096)
	body := `{"subject":"` + huge + `"}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized token hook body must be capped at 413; body: %s", w.Body.String())
}
