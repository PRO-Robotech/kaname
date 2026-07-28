// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

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

// TestTokenHook_ProviderBody_ClientCredentials_NoEndUser_MappedSAKey_StillMints
// — the machine grant in the same shape. It carries no end user at all, so the
// subject the provider states is empty and the client id is legitimately
// adopted in its place; a live mapping row mints.
func TestTokenHook_ProviderBody_ClientCredentials_NoEndUser_MappedSAKey_StillMints(t *testing.T) {
	h := newFullyWiredTokenHook(t, &fakeUserLookup{}, stubMappedSA{
		found: true,
		soc: domain.ServiceAccountOAuthClient{
			ID:            "soc_01abcdefghjkmnpqr",
			SvaID:         "sva_01abcdefghjkmnpqr",
			OAuthClientID: "soc_01abcdefghjkmnpqr",
		},
		sa: domain.ServiceAccount{
			ID:        "sva_01abcdefghjkmnpqr",
			AccountID: "acc_01abcdefghjkmnpqr",
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
