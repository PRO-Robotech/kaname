// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/iamhooks"
)

type fakeRevocations struct {
	mu           sync.Mutex
	revoked      map[string]bool
	calls        []domain.SessionRevocation
	isRevokedErr error // when non-nil, IsRevoked returns this error (backend down)

	// User-level revoke-all cutoffs keyed by user_id.
	userBefore    map[string]time.Time
	userBeforeErr error // when non-nil, UserRevokedBefore returns this error
}

func newFakeRevocations() *fakeRevocations {
	return &fakeRevocations{revoked: map[string]bool{}, userBefore: map[string]time.Time{}}
}

func (f *fakeRevocations) Revoke(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[rev.TokenJTI] = true
	f.calls = append(f.calls, rev)
	return nil
}

func (f *fakeRevocations) IsRevoked(ctx context.Context, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isRevokedErr != nil {
		return false, f.isRevokedErr
	}
	return f.revoked[jti], nil
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

func (f *fakeRevocations) MarkRevoked(jti string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[jti] = true
}

func (f *fakeRevocations) MarkUserRevokedBefore(userID string, before time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userBefore[userID] = before
}

func newRefreshHandler(t *testing.T, users *fakeUserLookup, revs *fakeRevocations, audit *fakeAudit) *iamhooks.RefreshHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return iamhooks.NewRefreshHookHandler(
		iamhooks.RefreshHookConfig{
			HookSharedSecret: "secret",
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		},
		users, revs, audit, logger,
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
		"session": {"client_id":"kacho-ui","acr":"2","cnf":{"jkt":"abc"}},
		"request": {"client_id":"kacho-ui","granted_scopes":["openid","webauthn"]},
		"access_token_claims": {"jti":"A1"}
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
	assert.Equal(t, "kratos-uuid-1", claims["kacho_external_id"])
	assert.Equal(t, "attested", claims["kacho_device_compliance"])
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

func TestRefreshHook_RevokedJti_403(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			InviteStatus: domain.InviteStatusActive,
		}},
	}
	revs := newFakeRevocations()
	revs.MarkRevoked("A1")
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := `{"subject":"kratos-uuid-1","session":{},"request":{},"access_token_claims":{"jti":"A1"}}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "jti_revoked", events[0].Payload["reason"])
}

// TestRefreshHook_RevocationCheckError_FailsClosed — H1: a non-nil IsRevoked
// error MUST fail-closed (403 invalid_grant + denied audit), never fall
// through and mint a refreshed token. The revocation cache is an authoritative
// gate; an error means "cannot prove the jti is NOT revoked" → deny.
func TestRefreshHook_RevocationCheckError_FailsClosed(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			InviteStatus: domain.InviteStatusActive,
		}},
	}
	revs := newFakeRevocations()
	revs.isRevokedErr = errors.New("session_revocations: backend unavailable")
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	body := `{"subject":"kratos-uuid-1","session":{},"request":{},"access_token_claims":{"jti":"A1"}}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// MUST deny — fail-closed on an authoritative revocation gate.
	require.Equal(t, http.StatusForbidden, w.Code, "revocation-check error must fail-closed, not mint a token; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_grant")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType,
		"revocation-check error must emit a denied event, never authn.refresh.issued")
	assert.Equal(t, "revocation_check_failed", events[0].Payload["reason"])
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

// refreshBody builds a refresh-hook payload with the Hydra session auth_time
// (unix seconds) carried — the session timestamp the user-level gate compares
// against the per-user revoke_before cutoff.
func refreshBody(subject, jti string, authTime int64) string {
	return fmt.Sprintf(
		`{"subject":%q,"session":{"auth_time":%d},"request":{},"access_token_claims":{"jti":%q}}`,
		subject, authTime, jti)
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
	body := refreshBody("kratos-uuid-1", "live-jti-1", now.Add(-time.Hour).Unix())
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
	body := refreshBody("kratos-uuid-1", "fresh-jti-1", time.Now().UTC().Unix())
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

	body := refreshBody("kratos-uuid-2", "bystander-jti", time.Now().UTC().Add(-2*time.Hour).Unix())
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

	body := refreshBody("kratos-uuid-1", "no-authtime-jti", 0) // auth_time absent
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

	body := refreshBody("kratos-uuid-1", "jti-x", time.Now().UTC().Unix())
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

// TestRefreshHook_MissingJti_FailsClosed — the jti gate must not be skippable.
// A refresh payload with an empty access_token_claims.jti previously bypassed
// the IsRevoked check entirely (fail-OPEN): a token minted/refreshed without a
// jti was never subject to revocation. The refresh path now REQUIRES a jti — an
// empty one is denied (403 invalid_grant + denied audit), consistent with the
// way a revoked jti is denied. Never fall through and mint a refreshed token.
func TestRefreshHook_MissingJti_FailsClosed(t *testing.T) {
	users := &fakeUserLookup{
		users: []domain.User{{
			ID:           "usr_01abcdefghjkmnpqr",
			AccountID:    "acc_01abcdefghjkmnpqr",
			ExternalID:   "kratos-uuid-1",
			InviteStatus: domain.InviteStatusActive,
		}},
	}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	// Active user, no per-jti or user-level revocation set — the ONLY reason to
	// deny is the missing jti. The happy-path body is identical except jti="".
	body := `{"subject":"kratos-uuid-1","session":{"auth_time":1},"request":{},"access_token_claims":{"jti":""}}`
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"a refresh without a jti must fail-closed (the revocation gate is unskippable); body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_grant")
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType,
		"missing jti must emit a denied event, never authn.refresh.issued")
	assert.Equal(t, "missing_jti", events[0].Payload["reason"])
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
