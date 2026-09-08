// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// disabled_sa_test.go — what the caller gets when a disabled service account
// asks for a token.
//
// These assert the answer on the wire: the status the provider reads as
// "refuse this token request", the absence of any claim set in the body, and
// the trail saying a token was DENIED rather than issued. Not that a function
// was called — a call proves nothing about what came back.
//
// The diagnostic is `invalid_client` and not the `user_disabled` a human gets.
// What failed on this path is client authentication (RFC 6749 §5.2), and the
// subject is not a user; answering with the human's code would send an operator
// looking through the wrong table. The audit reason is separated for the same
// reason: an operator responds to a disabled service account differently than
// to a blocked person.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	disabledSAClient  = "hydra-client-of-disabled-sa"
	disabledSAIDHook  = "sva_01disabledhook01"
	disabledSAAccount = "acc_01disabledhook01"
)

// fakeStateSAPort — an SA-key mapping whose owning account carries the state
// under test. The mapping and the account both RESOLVE: the defect was a row
// that was read and never consulted, not a row that was missing.
type fakeStateSAPort struct {
	clientID string
	sa       domain.ServiceAccount
}

func (f *fakeStateSAPort) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if string(id) != f.clientID {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such sa-key client")
	}
	return domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             "soc_01disabledhook01",
		SvaID:          f.sa.ID,
		OAuthClientID:  id,
	}, nil
}

func (f *fakeStateSAPort) GetServiceAccount(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if id != f.sa.ID {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "no such service account")
	}
	return f.sa, nil
}

func (f *fakeStateSAPort) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject")
}

func newStateSAHook(t *testing.T, enabled bool, audit *fakeAudit) *iamhooks.TokenHookHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		&fakeUserLookup{},
	).WithSAPort(&fakeStateSAPort{
		clientID: disabledSAClient,
		sa: domain.ServiceAccount{
			ID:        disabledSAIDHook,
			AccountID: disabledSAAccount,
			Enabled:   enabled,
		},
	})
	return iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{
			HookSharedSecret: "secret-hook-token",
			Domain:           "api.test.cloud",
			HydraIssuer:      "https://hydra.test.cloud",
		}, enricher, newFakeRevocations(), audit, logger)
}

func saClientCredentialsBody() string {
	return `{"session":{"client_id":"` + disabledSAClient + `"},
	          "request":{"client_id":"` + disabledSAClient + `","grant_types":["client_credentials"]}}`
}

func TestTokenHook_DisabledServiceAccount_Refused(t *testing.T) {
	audit := &fakeAudit{}
	h := newStateSAHook(t, false, audit)

	w := postHook(t, h, "/iam/v1/hooks/token", "secret-hook-token", saClientCredentialsBody())

	require.Equal(t, http.StatusForbidden, w.Code,
		"a disabled service account must be refused a token; 403 is the only status the "+
			"provider reads as 'refuse this token request'. body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid_client",
		"client authentication is what failed here, and the subject is not a user")

	// Nothing was minted: no claim set of any size reached the response.
	assert.NotContains(t, w.Body.String(), "ext_claims")
	assert.NotContains(t, w.Body.String(), "kaname_principal_id")
	assert.NotContains(t, w.Body.String(), disabledSAAccount,
		"least of all the claim set naming the account")

	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	assert.Nil(t, body["session"], "no session claims are returned on a refusal")

	events := audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "authn.token.denied", events[0].EventType,
		"a refused request must not be written down as an issuance")
	assert.Equal(t, "service_account_disabled", events[0].Payload["reason"],
		"the trail must say why: reporting a disabled service account as a blocked user "+
			"sends the operator to the wrong table")
}

// The control, and the reason step one had to come first. `Enabled` is false in
// every zero value, so a deny branch fed by a read that never loaded the column
// refuses EVERY service account — every machine flow in the platform — while
// looking indistinguishable from a working gate. This test is the one that
// fails when that happens.
func TestTokenHook_EnabledServiceAccount_StillMints(t *testing.T) {
	audit := &fakeAudit{}
	h := newStateSAHook(t, true, audit)

	w := postHook(t, h, "/iam/v1/hooks/token", "secret-hook-token", saClientCredentialsBody())

	require.Equal(t, http.StatusOK, w.Code,
		"an enabled service account must keep getting its token. body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "ext_claims")
	assert.Contains(t, w.Body.String(), disabledSAIDHook)
	assert.Contains(t, w.Body.String(), disabledSAAccount)
}
