// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// fakeRevocations — the revoke-all cutoff store, as both hooks read it.
//
// It carries ONLY what the port declares. It used to also model per-jti
// revocations and the write path, which no consumer in this package asks for —
// a double wider than its port lets a case describe a state the handler can
// never be in.
type fakeRevocations struct {
	mu sync.Mutex
	// Cutoffs keyed by user_id.
	userBefore    map[string]time.Time
	userBeforeErr error // when non-nil, UserRevokedBefore returns this error
}

func newFakeRevocations() *fakeRevocations {
	return &fakeRevocations{userBefore: map[string]time.Time{}}
}

func (f *fakeRevocations) UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.userBeforeErr != nil {
		return time.Time{}, false, f.userBeforeErr
	}
	t, ok := f.userBefore[userID]
	return t, ok, nil
}

func (f *fakeRevocations) MarkUserRevokedBefore(userID string, before time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userBefore[userID] = before
}

func newRefreshHandler(t *testing.T, users *fakeUserLookup, revs *fakeRevocations, audit *fakeAudit) *iamhooks.RefreshHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Тот же производитель состава утверждений, что держит полоса выпуска
	// (#2052). Дублёра здесь быть не может: предмет — что обе полосы отдают
	// один состав, а подставной сборщик отвечал бы за них обеих.
	claims := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{
			Domain:      "api.test.cloud",
			HydraIssuer: "https://hydra.test.cloud",
		},
		users,
	)
	return iamhooks.NewRefreshHookHandler(
		iamhooks.RefreshHookConfig{
			HookSharedSecret: "secret",
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		},
		users, claims, revs, audit, logger,
	)
}

func TestRefreshHook_HappyPath(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			Email:        "alice@example.com",
			InviteStatus: domain.InviteStatusActive,
		}},
	}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := `{
		"subject": "kratos-uuid-1",
		"session": {"client_id":"kacho-ui","cnf":{"jkt":"abc"},
		            "id_token":{"subject":"kratos-uuid-1",
		                        "id_token_claims":{"auth_time":"2026-07-29T03:18:40Z","acr":"2"}}},
		"requester": {"client_id":"kacho-ui","granted_scopes":["openid","webauthn"],"granted_audience":["kacho"]},
		"client_id": "kacho-ui",
		"granted_scopes": ["openid","webauthn"]
	}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	claims := resp.Session.AccessToken["ext_claims"].(map[string]any)
	assert.Equal(t, "kratos-uuid-1", claims["kaname_external_id"])
	assert.Equal(t, "attested", claims["kaname_device_compliance"])
	// One audit row.
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.issued", events[0].EventType)
}

func TestRefreshHook_BlockedUser_403(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			Email:        "alice@example.com",
			InviteStatus: domain.InviteStatusBlocked,
		}},
	}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := `{"subject":"kratos-uuid-1","session":{},"request":{},"access_token_claims":{"jti":"A1"}}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "user_disabled")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "user_blocked", events[0].Payload["reason"])
}

func TestRefreshHook_UserNotFound_403(t *testing.T) {
	users := &fakeUserLookup{}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := `{"subject":"unknown","session":{},"request":{},"access_token_claims":{}}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "user_not_found", events[0].Payload["reason"])
}

// refreshUser — a single ACTIVE user-row helper for the user-level gate tests.
func refreshUser(id, ext string) *fakeUserLookup {
	return &fakeUserLookup{users: []domain.User{{
		ID:           domain.UserID(id),
		AccountID:    "acc_01abcdefghjkmnpqr",
		ExternalID:   domain.ExternalSubject(ext),
		InviteStatus: domain.InviteStatusActive,
	}}}
}

// refreshBody builds a refresh-hook payload in the shape the provider actually
// posts (testdata/README.md): the subject top-level, the session's
// authentication instant among the OIDC claims of the token-shaped part as an
// RFC3339 string, and the exchange under `requester`.
//
// It used to state the instant as a unix number one level up and to carry an
// `access_token_claims.jti`, neither of which the provider sends. Every case
// built on it therefore exercised a body that could not occur, which is how a
// hook that refused every real refresh kept a green suite.
func refreshBody(subject string, authTime int64) string {
	instant := "0001-01-01T00:00:00Z"
	if authTime > 0 {
		instant = time.Unix(authTime, 0).UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf(
		`{"subject":%q,
		  "session":{"client_id":"kacho-ui","id_token":{"subject":%q,
		     "id_token_claims":{"auth_time":%q,"acr":"2","amr":["pwd"]}}},
		  "requester":{"client_id":"kacho-ui","granted_scopes":["openid"],"granted_audience":["kacho"]},
		  "client_id":"kacho-ui","granted_scopes":["openid"],"granted_audience":["kacho"]}`,
		subject, subject, instant)
}

// TestRefreshHook_UserLevelRevocation_DeniesOlderToken — the core fix: a
// user-level revoke_before cutoff MUST deny a token whose session auth_time is
// at-or-before the cutoff, EVEN THOUGH the token's jti is not individually
// revoked. This is exactly what ForceLogout / Revoke(revoke_all) rely on.
func TestRefreshHook_UserLevelRevocation_DeniesOlderToken(t *testing.T) {
	users := refreshUser("usr_victim01abcdef", "kratos-uuid-1")
	revs := newFakeRevocations()
	now := time.Now().UTC()
	revs.MarkUserRevokedBefore("usr_victim01abcdef", now) // revoke-all as of now

	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	// Token's session authenticated 1h ago → before the cutoff → DENY.
	body := refreshBody("kratos-uuid-1", now.Add(-time.Hour).Unix())
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"a token older than the user-level revoke_before cutoff must be denied; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_grant")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "user_revoked", events[0].Payload["reason"])
}

// TestRefreshHook_UserLevelRevocation_AllowsNewerToken — after the user
// re-authenticates, the new session's auth_time advances PAST the cutoff, so
// the refreshed token is allowed (no permanent lockout).
func TestRefreshHook_UserLevelRevocation_AllowsNewerToken(t *testing.T) {
	users := refreshUser("usr_victim01abcdef", "kratos-uuid-1")
	revs := newFakeRevocations()
	cutoff := time.Now().UTC().Add(-time.Hour)
	revs.MarkUserRevokedBefore("usr_victim01abcdef", cutoff)

	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	// Token's session authenticated AFTER the cutoff (just now) → ALLOW.
	body := refreshBody("kratos-uuid-1", time.Now().UTC().Unix())
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code,
		"a token newer than the user-level cutoff must be allowed; body: %s", w.Body.String())
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.issued", events[0].EventType)
}

// TestRefreshHook_UserLevelRevocation_OtherUserUnaffected — a cutoff for one
// user must never deny a different user's token.
func TestRefreshHook_UserLevelRevocation_OtherUserUnaffected(t *testing.T) {
	users := refreshUser("usr_bystander01abc", "kratos-uuid-2")
	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore("usr_victim01abcdef", time.Now().UTC()) // only victim revoked

	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := refreshBody("kratos-uuid-2", time.Now().UTC().Add(-2*time.Hour).Unix())
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "bystander must be unaffected; body: %s", w.Body.String())
}

// TestRefreshHook_UserLevelRevocation_NoAuthTime_DeniesWhenRevoked — defensive:
// if the session carries no auth_time (0) we cannot prove the token post-dates
// the cutoff, so a user with an active revoke-all marker is denied (fail-safe,
// never a silent allow).
func TestRefreshHook_UserLevelRevocation_NoAuthTime_DeniesWhenRevoked(t *testing.T) {
	users := refreshUser("usr_victim01abcdef", "kratos-uuid-1")
	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore("usr_victim01abcdef", time.Now().UTC())

	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := refreshBody("kratos-uuid-1", 0) // auth_time absent
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"missing auth_time under an active user-level revocation must fail-safe deny; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_grant")
}

// TestRefreshHook_UserLevelRevocationCheckError_FailsClosed — a non-nil
// UserRevokedBefore error must fail-closed, never mint a refreshed token.
func TestRefreshHook_UserLevelRevocationCheckError_FailsClosed(t *testing.T) {
	users := refreshUser("usr_victim01abcdef", "kratos-uuid-1")
	revs := newFakeRevocations()
	revs.userBeforeErr = errors.New("user_token_revocations: backend unavailable")

	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := refreshBody("kratos-uuid-1", time.Now().UTC().Unix())
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"user-level revocation-check error must fail-closed; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_grant")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "revocation_check_failed", events[0].Payload["reason"])
}

func TestRefreshHook_AuthFailure(t *testing.T) {
	h := newRefreshHandler(t, &fakeUserLookup{}, newFakeRevocations(), &fakeAudit{})
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(`{"subject":"x"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRefreshHook_OversizedBody_413 — post-auth body-size cap on the refresh
// hook (CWE-770 guard; shared decodeHookBody helper).
func TestRefreshHook_OversizedBody_413(t *testing.T) {
	users := &fakeUserLookup{}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	huge := strings.Repeat("a", (1<<20)+4096)
	body := `{"subject":"` + huge + `"}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized refresh hook body must be capped at 413; body: %s", w.Body.String())
}
