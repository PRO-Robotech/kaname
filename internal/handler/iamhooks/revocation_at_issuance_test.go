// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_at_issuance_test.go — the revoke-all cutoff, asserted where a token
// is MINTED and against the body the provider actually posts.
//
// The bar every case holds is deliberately not "the revocation port was
// consulted". A handler that reads the cutoff and mints anyway passes that bar,
// which is how the gap survived: the cutoff was written by three call sites and
// read by one, on the path taken only when an existing token is REFRESHED. The
// assertion is on the observable — after a cutoff, no usable token comes back:
// the status refuses AND the response carries no claims to mint from.
//
// Bodies come from testdata/ (see the README there): verbatim captures from the
// provider at this stand's version. Cases override only the fields they are
// about, so the surrounding structure stays the producer's and not the reader's.
package iamhooks_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// --- fixture plumbing -------------------------------------------------------

func capturedBody(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err, "captured provider body must be present")
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// at walks to a nested object in the captured body, failing if the path is
// absent. A path that stops resolving means the capture changed shape — a
// finding about the provider, not something to route around.
func at(t *testing.T, body map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := body
	for i, p := range path {
		next, ok := cur[p].(map[string]any)
		require.Truef(t, ok, "captured body has no object at %q", strings.Join(path[:i+1], "."))
		cur = next
	}
	return cur
}

// sessionClaims returns the object the provider fills with the session's OIDC
// claims — where the authentication instant actually lives.
func sessionClaims(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	return at(t, body, "session", "id_token", "id_token_claims")
}

// capturedAuthTime reads the session's authentication instant OUT OF the
// fixture rather than restating it, so a re-capture cannot leave expectations
// pointing at a stale moment.
func capturedAuthTime(t *testing.T, body map[string]any) time.Time {
	t.Helper()
	raw, ok := sessionClaims(t, body)["auth_time"].(string)
	require.True(t, ok, "captured body must carry a session auth_time")
	ts, err := time.Parse(time.RFC3339, raw)
	require.NoError(t, err)
	require.False(t, ts.IsZero(), "captured session must have authenticated at a real instant")
	return ts
}

func postCaptured(t *testing.T, h http.Handler, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(raw)))
	req.Header.Set("X-Kacho-Hook-Token", issuanceHookSecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// mintedClaims returns the ext_claims handed back for the provider to stamp
// into a token, and whether any came back. "No usable token" means none did — a
// 403 carrying a full claim set would still be a finding.
func mintedClaims(t *testing.T, w *httptest.ResponseRecorder) (map[string]any, bool) {
	t.Helper()
	var resp struct {
		Session struct {
			AccessToken struct {
				ExtClaims map[string]any `json:"ext_claims"`
			} `json:"access_token"`
		} `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		return nil, false
	}
	return resp.Session.AccessToken.ExtClaims, len(resp.Session.AccessToken.ExtClaims) > 0
}

func deniedReasons(a *fakeAudit) []string {
	var out []string
	for _, e := range a.Events() {
		if r, ok := e.Payload["reason"].(string); ok {
			out = append(out, r)
		}
	}
	return out
}

const (
	issuanceHookSecret  = "secret-hook-token"
	capturedSubject     = "cap-user-external-sub"
	capturedInteractive = "cap-inter"
	capturedMachine     = "cap-machine"
	cutoffUserID        = "usr_01abcdefghjkmnpqx"
	cutoffAccountID     = "acc_01abcdefghjkmnpqx"
)

func cutoffUser() *fakeUserLookup {
	return &fakeUserLookup{users: []domain.User{{
		ID:           cutoffUserID,
		AccountID:    cutoffAccountID,
		ExternalID:   capturedSubject,
		Email:        "cutoff@example.com",
		InviteStatus: domain.InviteStatusActive,
	}}}
}

// machineShaped turns a captured client_credentials body into one whose client
// is the named registration: no end-user subject, the client stated where the
// provider states it.
func machineShaped(t *testing.T, body map[string]any, clientID string) {
	t.Helper()
	at(t, body, "session", "id_token")["subject"] = ""
	at(t, body, "session")["client_id"] = clientID
	at(t, body, "request")["client_id"] = clientID
}

func newIssuanceHook(
	t *testing.T,
	users *fakeUserLookup,
	revs iamhooks.UserRevocationLookup,
	audit *fakeAudit,
	userTokens service.TokenEnrichmentUserTokenPort,
	sas service.TokenEnrichmentSAPort,
) *iamhooks.TokenHookHandler {
	t.Helper()
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	)
	if sas != nil {
		enricher = enricher.WithSAPort(sas)
	}
	if userTokens != nil {
		enricher = enricher.WithUserTokenPort(userTokens)
	}
	return iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{
			HookSharedSecret: issuanceHookSecret,
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		},
		enricher, revs, audit,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// --- the session's own statements are read where the provider makes them -----

// TestTokenHook_ReadsSessionAuthTimeWhereProviderPutsIt — the claims derived
// from the session's authentication instant and assurance level are stamped for
// a captured interactive exchange.
//
// A reader that declares those one level up, or the instant as a number, sees
// nothing on every real request and the derived claims are silently absent
// forever. The value is asserted against the fixture's own instant, so the case
// cannot be satisfied by a reader that merely defaults it.
func TestTokenHook_ReadsSessionAuthTimeWhereProviderPutsIt(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")
	want := capturedAuthTime(t, body)

	h := newIssuanceHook(t, cutoffUser(), newFakeRevocations(), &fakeAudit{}, nil, nil)
	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	claims, ok := mintedClaims(t, w)
	require.True(t, ok, "an interactive exchange must mint claims")
	assert.EqualValues(t, want.Unix(), claims["kacho_mfa_at"],
		"the session's authentication instant must be read from the captured location")
	assert.Equal(t, "2", claims["kacho_acr"],
		"the session's assurance level must be read from the captured location")
}

// --- the cutoff refuses issuance --------------------------------------------

// TestTokenHook_RevokeAllCutoff_NoUsableTokenIsIssued — the planted bar. An
// administrator forces the subject out; the subject's live session then asks
// the provider for a fresh token. The exchange must not produce one.
func TestTokenHook_RevokeAllCutoff_NoUsableTokenIsIssued(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")
	authTime := capturedAuthTime(t, body)

	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, authTime.Add(time.Second))
	audit := &fakeAudit{}
	h := newIssuanceHook(t, cutoffUser(), revs, audit, nil, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)

	require.Equalf(t, http.StatusForbidden, w.Code,
		"a session revoked by an administrator must not obtain a fresh token; body: %s", w.Body.String())
	claims, any := mintedClaims(t, w)
	assert.Falsef(t, any, "the refusal must carry no claims to mint from, got %v", claims)
	assert.Contains(t, deniedReasons(audit), "user_revoked",
		"the refusal must be recorded for the operator")
}

// TestTokenHook_ReAuthAfterCutoff_IsIssued — the cutoff must not become a
// permanent lockout: a session that authenticated AFTER it is the subject
// proving themselves again, and is served.
func TestTokenHook_ReAuthAfterCutoff_IsIssued(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")
	authTime := capturedAuthTime(t, body)

	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, authTime.Add(-time.Hour))
	h := newIssuanceHook(t, cutoffUser(), revs, &fakeAudit{}, nil, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	_, any := mintedClaims(t, w)
	assert.True(t, any, "a re-authenticated session must be served")
}

// TestTokenHook_CutoffWithoutSessionInstant_Refuses — a cutoff exists and the
// exchange states no instant to weigh it against. We cannot show the credential
// post-dates the revoke-all, so we refuse.
func TestTokenHook_CutoffWithoutSessionInstant_Refuses(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")
	authTime := capturedAuthTime(t, body)
	// The zero instant the provider itself sends for a session it never
	// authenticated.
	sessionClaims(t, body)["auth_time"] = "0001-01-01T00:00:00Z"

	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, authTime)
	h := newIssuanceHook(t, cutoffUser(), revs, &fakeAudit{}, nil, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	_, any := mintedClaims(t, w)
	assert.False(t, any)
}

// TestTokenHook_RevocationLookupFails_Refuses — an authoritative gate, so an
// unavailable answer is not a "no". Fail closed.
func TestTokenHook_RevocationLookupFails_Refuses(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")

	revs := newFakeRevocations()
	revs.userBeforeErr = errors.New("user_token_revocations: backend unavailable")
	audit := &fakeAudit{}
	h := newIssuanceHook(t, cutoffUser(), revs, audit, nil, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	_, any := mintedClaims(t, w)
	assert.False(t, any)
	assert.Contains(t, deniedReasons(audit), "revocation_check_failed")
}

// TestTokenHook_NoCutoff_IsIssued — the control. Without a cutoff the same
// exchange is served, so the cases above are pinning the cutoff and not merely
// a hook that refuses everything.
func TestTokenHook_NoCutoff_IsIssued(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-authorization-code.json")
	h := newIssuanceHook(t, cutoffUser(), newFakeRevocations(), &fakeAudit{}, nil, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	_, any := mintedClaims(t, w)
	assert.True(t, any)
}

// --- the standing personal credential ---------------------------------------

// TestTokenHook_PersonalToken_IssuedBeforeCutoff_NoUsableToken — a personal
// access token has no session, so the instant to weigh is its own issuance. One
// issued BEFORE the administrator forced the owner out is part of what "log
// this person out everywhere" means.
//
// This is the case with no other point of enforcement anywhere: the grant it is
// presented under has no refresh hook, so a token minted through it is never
// re-examined after issuance. It also does not depend on where the session's
// authentication instant is carried — this exchange has no session at all.
func TestTokenHook_PersonalToken_IssuedBeforeCutoff_NoUsableToken(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-client-credentials.json")
	machineShaped(t, body, capturedMachine)

	issued := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	users := cutoffUser()
	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, issued.Add(time.Hour))
	h := newIssuanceHook(t, users, revs, &fakeAudit{}, &fakeUserTokenPort{
		client: domain.UserOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "utk_01abcdefghjkmnpqx", UserID: cutoffUserID,
			OAuthClientID: capturedMachine, CreatedAt: issued,
		},
		user: users.users[0],
	}, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	claims, any := mintedClaims(t, w)
	assert.Falsef(t, any, "a personal token predating the force-logout must not mint, got %v", claims)
}

// TestTokenHook_PersonalToken_IssuedAfterCutoff_IsIssued — the same subject
// mints a NEW personal token after being forced out. It post-dates the cutoff,
// so it works: the cutoff ends sessions, it does not brick the account.
func TestTokenHook_PersonalToken_IssuedAfterCutoff_IsIssued(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-client-credentials.json")
	machineShaped(t, body, capturedMachine)

	cutoff := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	users := cutoffUser()
	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, cutoff)
	h := newIssuanceHook(t, users, revs, &fakeAudit{}, &fakeUserTokenPort{
		client: domain.UserOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             "utk_01abcdefghjkmnpqy", UserID: cutoffUserID,
			OAuthClientID: capturedMachine, CreatedAt: cutoff.Add(time.Hour),
		},
		user: users.users[0],
	}, nil)

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	_, any := mintedClaims(t, w)
	assert.True(t, any)
}

// TestTokenHook_ServiceAccountKey_UnaffectedByUserCutoff — a service account's
// key is not a person's session. Forcing a USER out must not silently disable
// machine credentials that merely share an account with them.
func TestTokenHook_ServiceAccountKey_UnaffectedByUserCutoff(t *testing.T) {
	body := capturedBody(t, "provider-token-hook-client-credentials.json")
	machineShaped(t, body, capturedMachine)

	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, time.Now().UTC().Add(time.Hour))
	h := newIssuanceHook(t, cutoffUser(), revs, &fakeAudit{}, nil, &fakeIssuanceSAPort{
		mapping: domain.ServiceAccountOAuthClient{ID: "sak_01abcdefghjkmnpqx", SvaID: "sva_01abcdefghjkmnpqx"},
		sa: domain.ServiceAccount{
			ID: "sva_01abcdefghjkmnpqx", AccountID: cutoffAccountID, Enabled: true,
		},
		clientID: capturedMachine,
	})

	w := postCaptured(t, h, "/iam/v1/hooks/token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	claims, any := mintedClaims(t, w)
	require.True(t, any)
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
}

// --- the refresh path, driven with the body the provider actually posts ------

// TestRefreshHook_CapturedBody_NotRefusedForAnAbsentTokenClaim — this hook's
// body carries no token-claims object at all (testdata/README.md), so a gate
// keyed on one refuses EVERY refresh and everything behind it is unreachable.
// A live session with no cutoff against it must refresh.
//
// Replaces a case that asserted the opposite — that an absent jti must be
// refused — which was green precisely because the condition it demanded holds
// on every real request.
func TestRefreshHook_CapturedBody_NotRefusedForAnAbsentTokenClaim(t *testing.T) {
	body := capturedBody(t, "provider-refresh-hook.json")
	audit := &fakeAudit{}
	h := newRefreshHandler(t, cutoffUser(), newFakeRevocations(), audit)

	w := postCapturedRefresh(t, h, body)
	require.Equalf(t, http.StatusOK, w.Code,
		"a healthy session must refresh; refusals so far: %v", deniedReasons(audit))
}

// TestRefreshHook_CapturedBody_CutoffRefuses — with a cutoff against it the
// refresh is refused FOR THAT REASON.
//
// Asserting the recorded reason and not merely the status is what makes this
// discriminating: while the hook refused every refresh for an absent token
// claim, a status-only assertion passed here without the cutoff ever being read.
func TestRefreshHook_CapturedBody_CutoffRefuses(t *testing.T) {
	body := capturedBody(t, "provider-refresh-hook.json")
	authTime := capturedAuthTime(t, body)

	revs := newFakeRevocations()
	revs.MarkUserRevokedBefore(cutoffUserID, authTime.Add(time.Second))
	audit := &fakeAudit{}
	h := newRefreshHandler(t, cutoffUser(), revs, audit)

	w := postCapturedRefresh(t, h, body)
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, deniedReasons(audit), "user_revoked",
		"the refusal must be the cutoff's, not an absent field's")
}

// TestRefreshHook_CapturedBody_RecordsTheClient — the refresh body states the
// client where the token body does not, and the audit trail must carry it. An
// empty client id in an authn record is an operator looking at nothing.
func TestRefreshHook_CapturedBody_RecordsTheClient(t *testing.T) {
	body := capturedBody(t, "provider-refresh-hook.json")
	audit := &fakeAudit{}
	h := newRefreshHandler(t, cutoffUser(), newFakeRevocations(), audit)

	w := postCapturedRefresh(t, h, body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	events := audit.Events()
	require.NotEmpty(t, events)
	assert.Equal(t, capturedInteractive, events[len(events)-1].Payload["client_id"],
		"the client must be read from where this body states it")
}

// TestRefreshHook_CapturedBody_ReflectsSessionAssurance — the assurance level of
// the refreshed session is re-stamped from the captured location.
func TestRefreshHook_CapturedBody_ReflectsSessionAssurance(t *testing.T) {
	body := capturedBody(t, "provider-refresh-hook.json")
	h := newRefreshHandler(t, cutoffUser(), newFakeRevocations(), &fakeAudit{})

	w := postCapturedRefresh(t, h, body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	claims, ok := mintedClaims(t, w)
	require.True(t, ok)
	assert.Equal(t, "2", claims["kacho_acr"])
}

// postCapturedRefresh posts to the refresh hook, whose fixtures use their own
// shared secret.
func postCapturedRefresh(t *testing.T, h http.Handler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/iam/v1/hooks/refresh", strings.NewReader(string(raw)))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// --- doubles ----------------------------------------------------------------

// fakeUserTokenPort — a personal access token and its owner. It answers
// NotFound for any other client, so a case cannot pass by the port being
// indiscriminate.
type fakeUserTokenPort struct {
	client domain.UserOAuthClient
	user   domain.User
}

func (f *fakeUserTokenPort) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	if id == f.client.OAuthClientID {
		return f.client, nil
	}
	return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user token for %s", id)
}

func (f *fakeUserTokenPort) GetUser(_ context.Context, id domain.UserID) (domain.User, error) {
	if id == f.user.ID {
		return f.user, nil
	}
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
}

// fakeIssuanceSAPort — a service-account key mapping. Distinct from the
// federation double in this package, which answers NotFound to every
// client-id lookup by design.
type fakeIssuanceSAPort struct {
	clientID string
	mapping  domain.ServiceAccountOAuthClient
	sa       domain.ServiceAccount
}

func (f *fakeIssuanceSAPort) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if string(id) == f.clientID {
		return f.mapping, nil
	}
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa key for %s", id)
}

func (f *fakeIssuanceSAPort) GetServiceAccount(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if id == f.sa.ID {
		return f.sa, nil
	}
	return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa %s", id)
}

func (f *fakeIssuanceSAPort) FindByExternalSubject(_ context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject (%s,%s)", issuer, sub)
}
