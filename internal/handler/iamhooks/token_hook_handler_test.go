// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

type fakeUserLookup struct {
	users []domain.User
	err   error
}

func (f *fakeUserLookup) FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
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
		"subject": "kratos-uuid-1",
		"session": map[string]any{
			"client_id": "kacho-ui",
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
	assert.Equal(t, "kratos-uuid-1", claims["kacho_external_id"])
	assert.Equal(t, "usr_01abcdefghjkmnpqr", claims["kacho_user_id"])
	assert.Equal(t, "acc_01abcdefghjkmnpqr", claims["kacho_active_account"])
	assert.Equal(t, "user", claims["kacho_principal_type"])
	assert.Equal(t, "attested", claims["kacho_device_compliance"]) // webauthn scope
	assert.Equal(t, "abc-thumbprint", claims["kacho_jkt"])
	assert.Equal(t, "api.test.cloud", claims["kacho_audience"])
	assert.Equal(t, "https://hydra.test.cloud", claims["kacho_issuer"])

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

func TestTokenHook_ClientCredentials_EmptySubject_FallsBackToClientID(t *testing.T) {
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, &fakeUserLookup{}, audit)

	// client_credentials (RFC 6749 §4.4) несёт пустой subject — end-user'а нет.
	// kacho-принципал — это ServiceAccount за OAuth2-клиентом, поэтому handler
	// обязан взять client_id как subject (а не отвергать 400 missing_subject),
	// чтобы enricher резолвил SA через LookupByOAuthClientID.
	payload := map[string]any{
		"subject": "",
		"session": map[string]any{"client_id": "cc-client-uuid", "subject": ""},
		"request": map[string]any{
			"client_id": "cc-client-uuid",
			"payload":   map[string][]string{"grant_type": {"client_credentials"}},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/iam/v1/hooks/token", strings.NewReader(string(body)))
	req.Header.Set("X-Kacho-Hook-Token", "secret-hook-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code,
		"empty-subject client_credentials must fall back to client_id; body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "missing_subject")
}

func TestTokenHook_UserNotFound_EmitsMinimalClaims(t *testing.T) {
	users := &fakeUserLookup{} // no users — FindActiveByExternalID returns empty
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	body := []byte(`{"subject":"unknown-sub","session":{},"request":{}}`)
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
	assert.Equal(t, "unknown-sub", claims["kacho_external_id"])
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
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
