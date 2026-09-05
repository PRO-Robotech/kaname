// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// blocked_subject_test.go — a blocked user gets nothing, on BOTH hooks.
//
// The two hooks disagreed, and the disagreement was invisible because neither
// ever asked about the subject's state. Both resolved the identity through a
// query that filters `invite_status = 'ACTIVE'`, which silently turns "blocked"
// into "absent" — and then read absence in opposite directions:
//
//   - the refresh hook read it as a refusal and answered 403;
//   - the issuance hook read it as "the mirror has not committed yet" — the real
//     and legitimate first-login case — and answered 200 with the reduced claim
//     set. It ISSUED to a blocked user.
//
// A filter is not a verdict. These tests pin the verdict: on both hooks a user
// whose state forbids authentication is refused, and a subject with no row at
// all still mints the reduced set, because that is first login and refusing it
// would break the one case the fallback exists for.
//
// The blocked row here carries a non-empty external id, which the DB CHECK
// users_invite_status_consistency permits only for ACTIVE and BLOCKED — so a
// row found by external id is one of those two and never a pending invitee.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

const blockedSubject = "kratos-blocked-sub"

// blockedUserRow — a real row for the identity, in a state that forbids
// authentication.
func blockedUserRow() domain.User {
	return domain.User{
		ID:           "usr_01blockedblocked1",
		AccountID:    "acc_01blockedblocked1",
		ExternalID:   blockedSubject,
		Email:        "blocked@example.com",
		InviteStatus: domain.InviteStatusBlocked,
	}
}

func activeUserRow(sub string) domain.User {
	return domain.User{
		ID:           "usr_01activeactive001",
		AccountID:    "acc_01activeactive001",
		ExternalID:   domain.ExternalSubject(sub),
		Email:        "active@example.com",
		InviteStatus: domain.InviteStatusActive,
	}
}

func interactiveTokenHookBody(sub string) string {
	return `{
		"session": {"client_id":"kacho-ui","id_token":{"subject":"` + sub + `"},"acr":"1"},
		"request": {"client_id":"kacho-ui","granted_scopes":["openid"]}
	}`
}

func postHook(t *testing.T, h http.Handler, path, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// ── Issuance hook ───────────────────────────────────────────────────────────

func TestTokenHook_BlockedUser_Refused(t *testing.T) {
	users := &fakeUserLookup{users: []domain.User{blockedUserRow()}}
	audit := &fakeAudit{}
	h := newTokenHookHandler(t, users, audit)

	w := postHook(t, h, "/iam/v1/hooks/token", "secret-hook-token",
		interactiveTokenHookBody(blockedSubject))

	require.Equal(t, http.StatusForbidden, w.Code,
		"a blocked user must be refused, not issued a reduced token; 403 is the only "+
			"status the provider reads as 'refuse this token request'. body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "user_disabled",
		"the same diagnostic the refresh hook returns — one subject state, one answer")

	// Nothing was minted: no claims of any size reached the response.
	assert.NotContains(t, w.Body.String(), "ext_claims")
	assert.NotContains(t, w.Body.String(), "kacho_external_id")

	for _, e := range audit.Events() {
		assert.NotEqual(t, "authn.token.issued", e.EventType,
			"a refused request must not be audited as an issuance")
	}
}

// The reduced claim set exists for ONE case: a human authenticated at the
// identity provider and their mirror has not committed yet. That case must keep
// working — refusing the blocked user must not refuse first login.
func TestTokenHook_UnknownSubject_StillMintsMinimalClaims(t *testing.T) {
	users := &fakeUserLookup{} // no rows at all
	h := newTokenHookHandler(t, users, &fakeAudit{})

	w := postHook(t, h, "/iam/v1/hooks/token", "secret-hook-token",
		interactiveTokenHookBody("kratos-first-login-sub"))

	require.Equal(t, http.StatusOK, w.Code,
		"first login must still mint; refusing it would break the one case this branch "+
			"exists for. body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "kacho_external_id")
}

// ── Refresh hook ────────────────────────────────────────────────────────────

// The refresh hook already refused — but through the not-found branch, because
// the ACTIVE-only query had erased the distinction before the state was ever
// examined. Its audit therefore reported the wrong reason, and its own blocked
// branch was unreachable against the wired repository.
func TestRefreshHook_BlockedUser_RefusedWithTruthfulReason(t *testing.T) {
	users := &fakeUserLookup{users: []domain.User{blockedUserRow()}}
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	w := postHook(t, h, "/iam/v1/hooks/refresh", "secret",
		`{"subject":"`+blockedSubject+`","session":{},"request":{},"access_token_claims":{"jti":"A1"}}`)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "user_disabled")

	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.refresh.denied", events[0].EventType)
	assert.Equal(t, "user_blocked", events[0].Payload["reason"],
		"the audit must say why the subject was refused; reporting a blocked user as "+
			"'not found' describes a state the row does not have")
}

func TestRefreshHook_UnknownSubject_RefusedAsNotFound(t *testing.T) {
	users := &fakeUserLookup{} // no rows
	revs := newFakeRevocations()
	audit := &fakeAudit{}
	h := newRefreshHandler(t, users, revs, audit)

	w := postHook(t, h, "/iam/v1/hooks/refresh", "secret",
		`{"subject":"kratos-nobody","session":{},"request":{},"access_token_claims":{"jti":"A1"}}`)

	require.Equal(t, http.StatusForbidden, w.Code)
	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "user_not_found", events[0].Payload["reason"],
		"absent and blocked are different verdicts and must stay distinguishable")
}

// ── One verdict, both hooks ─────────────────────────────────────────────────

// The two hooks must not be able to disagree again: the decision is one
// predicate on the state, not a filter each caller re-derives.
func TestSubjectState_OneVerdictForBothHooks(t *testing.T) {
	assert.True(t, domain.InviteStatusActive.MayAuthenticate())
	assert.False(t, domain.InviteStatusBlocked.MayAuthenticate())
	assert.False(t, domain.InviteStatusPending.MayAuthenticate(),
		"an invitee has not confirmed an identity yet; the DB CHECK keeps such a row from "+
			"carrying an external id at all, so this is a floor, not a live path")
	assert.False(t, domain.InviteStatus("").MayAuthenticate(),
		"an unset state is not an authorisation")
}

// The service must be able to say WHY it refused, so the hook can answer a
// subject-state refusal differently from "no such subject". Collapsing the two
// is exactly how the issuing hook ended up minting for a blocked user.
func TestEnrichClaims_BlockedUser_IsNotNotFound(t *testing.T) {
	svc := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{users: []domain.User{blockedUserRow()}})

	_, _, err := svc.EnrichClaims(context.Background(), blockedSubject, service.TokenHookContext{})
	require.Error(t, err)
	require.ErrorIs(t, err, service.ErrSubjectNotActive)
	assert.NotContains(t, err.Error(), "not found",
		"a blocked subject is present and refused, not missing")
}

func TestEnrichClaims_ActiveUser_Unaffected(t *testing.T) {
	const sub = "kratos-active-sub"
	active := activeUserRow(sub)
	svc := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{users: []domain.User{active}})

	claims, _, err := svc.EnrichClaims(context.Background(), sub, service.TokenHookContext{})
	require.NoError(t, err)
	assert.Equal(t, string(active.ID), claims["kacho_user_id"])
	assert.Equal(t, string(active.AccountID), claims["kacho_account_id"])
}

// A membership set holding both an active and a blocked row must resolve to the
// active one: the blocked row must neither be chosen nor poison the lookup.
func TestEnrichClaims_MixedMembership_PicksTheActiveRow(t *testing.T) {
	const sub = "kratos-mixed-sub"
	blocked := blockedUserRow()
	blocked.ExternalID = sub
	active := activeUserRow(sub)

	svc := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{users: []domain.User{blocked, active}})

	claims, _, err := svc.EnrichClaims(context.Background(), sub, service.TokenHookContext{})
	require.NoError(t, err)
	assert.Equal(t, string(active.ID), claims["kacho_user_id"])
}

// ── Personal access token ───────────────────────────────────────────────────

// A blocked user holding a personal access token was worse off than the
// interactive one: that path resolves the owner BY ID, with no status filter at
// all, and stamped the FULL claim set — principal id and account included.
func TestTokenHook_BlockedUserPersonalToken_Refused(t *testing.T) {
	const clientID = "pat-client-of-blocked-user"
	owner := blockedUserRow()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{users: []domain.User{owner}},
	).WithUserTokenPort(&fakeBlockedOwnerTokens{clientID: clientID, owner: owner})
	audit := &fakeAudit{}
	h := iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{
			HookSharedSecret: "secret-hook-token",
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		}, enricher, newFakeRevocations(), audit, logger)

	w := postHook(t, h, "/iam/v1/hooks/token", "secret-hook-token",
		`{"session":{"client_id":"`+clientID+`"},
		  "request":{"client_id":"`+clientID+`","grant_types":["client_credentials"]}}`)

	require.Equal(t, http.StatusForbidden, w.Code,
		"a personal token whose owner may not authenticate must not mint. body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), string(owner.AccountID),
		"least of all the full claim set naming the owner's account")

	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	assert.Nil(t, body["session"], "no session claims are returned on a refusal")
}

// fakeBlockedOwnerTokens — a personal-access-token mapping whose owning user is
// blocked. Deliberately reports the owner as PRESENT: the defect is not a
// missing row, it is a present row nobody looked at.
type fakeBlockedOwnerTokens struct {
	clientID string
	owner    domain.User
}

func (f *fakeBlockedOwnerTokens) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	if string(id) != f.clientID {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such user-token client")
	}
	return domain.UserOAuthClient{ID: "uoc_01blockedblocked", UserID: f.owner.ID, OAuthClientID: id}, nil
}

func (f *fakeBlockedOwnerTokens) GetUser(_ context.Context, id domain.UserID) (domain.User, error) {
	if id != f.owner.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such user")
	}
	return f.owner, nil
}
