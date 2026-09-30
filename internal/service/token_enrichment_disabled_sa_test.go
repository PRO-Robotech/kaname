// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_disabled_sa_test.go — a service account that may not
// authenticate mints nothing, whatever kind of key it presents.
//
// `service_accounts.enabled` states whether an account may authenticate, and
// the own issuance lane resolves the account row on its way to the claim set.
// The provider's token hook used to have two machine branches doing the same —
// `client_credentials` and `jwt-bearer` (federation-in); they are gone with the
// hooks (kaname#363), and both key kinds now reach the account through one
// branch of ClaimsForAssertionClient. The pairs below keep both kinds under the
// probe so a state that stops one kind and not the other stays visible.
//
// The refusal is its own sentinel rather than the user one: what fails here is
// client authentication, and a machine credential is owed a different
// diagnostic than a human. Absent is a third answer again — a key whose account
// cannot be read is not a disabled account, and the two must stay
// distinguishable.
//
// The enabled control is not decoration. The field arrives false by default in
// Go, so a deny branch reading it refuses every account in existence until the
// read underneath actually loads the column; that failure mode is silent on the
// deny tests and loud only here.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const (
	disabledSAID    = "sva01disabledsa001"
	disabledSocID   = "soc_01disabledsa001"
	disabledSAAccID = "acc01disabledsa001"
)

// saLaneWithState — the key row of the named kind resolves by OUR id; the
// account behind it carries the state under test. Deliberately reports the
// account as PRESENT: the defect was never a missing row, it was a present row
// nobody read.
func saLaneWithState(kind domain.CredentialKind, enabled bool) *TokenEnrichmentService {
	return NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "api.kacho.cloud"}).
		WithOwnClientPort(stubOwnClients{soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: kind,
			ID:             domain.SAOAuthClientID(disabledSocID),
			SvaID:          domain.ServiceAccountID(disabledSAID),
		}}).
		WithSAPort(stubSAPort{sa: domain.ServiceAccount{
			ID:        domain.ServiceAccountID(disabledSAID),
			AccountID: domain.AccountID(disabledSAAccID),
			Enabled:   enabled,
		}})
}

var disabledSAClient = domain.AssertionClient{
	ID: disabledSocID, Kind: domain.AssertionClientServiceAccount, OwnerID: disabledSAID,
}

// ── key pair ────────────────────────────────────────────────────────────────

func TestEnrichClaims_DisabledServiceAccount_Refused(t *testing.T) {
	svc := saLaneWithState(domain.CredentialKindKeypair, false)

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), disabledSAClient, TokenHookContext{})

	require.Error(t, err, "a service account that may not authenticate must not mint a token")
	assert.True(t, stderrors.Is(err, ErrServiceAccountDisabled),
		"the refusal must be the disabled-account sentinel so the lane answers invalid_client and "+
			"names what failed; got %v", err)
	assert.Nil(t, claims, "no claims may be produced for an account that may not authenticate")
	assert.NotContains(t, err.Error(), "not found",
		"a disabled account is present and refused, not missing — collapsing the two is how "+
			"the provider's interactive branch once minted for a blocked user")
}

// The control. `Enabled` is a bool: it is false in every zero value, so a deny
// branch reading a field the query never loaded refuses EVERY service account
// while looking exactly like a working gate. This test is what fails then.
func TestEnrichClaims_EnabledServiceAccount_StillMints(t *testing.T) {
	svc := saLaneWithState(domain.CredentialKindKeypair, true)

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), disabledSAClient, TokenHookContext{})

	require.NoError(t, err, "an enabled service account must keep minting; refusing it trades "+
		"one hole for an outage of every machine flow there is")
	require.NotNil(t, claims)
	assert.Equal(t, "service_account", claims["kaname_principal_type"])
	assert.Equal(t, disabledSAID, claims["kaname_principal_id"])
	assert.Equal(t, disabledSAAccID, claims["kaname_account_id"])
}

// ── federated key (federation-in) ───────────────────────────────────────────

func TestEnrichClaims_DisabledFederatedServiceAccount_Refused(t *testing.T) {
	svc := saLaneWithState(domain.CredentialKindFederated, false)

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), disabledSAClient, TokenHookContext{})

	require.Error(t, err, "federation-in resolves to the same account and owes the same answer; "+
		"a state that stops one kind and not the other is not a state at all")
	assert.True(t, stderrors.Is(err, ErrServiceAccountDisabled), "got %v", err)
	assert.Nil(t, claims)
}

func TestEnrichClaims_EnabledFederatedServiceAccount_StillMints(t *testing.T) {
	svc := saLaneWithState(domain.CredentialKindFederated, true)

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), disabledSAClient, TokenHookContext{})

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, disabledSAID, claims["kaname_principal_id"])
}

// ── the account is gone, which is not the same as disabled ──────────────────

// The mapping row references the account under an ON DELETE RESTRICT foreign
// key, so an account cannot be dropped from under a live mapping. Should that
// read miss anyway, the lane refuses — it mints nothing for an owner it could
// not judge — and the refusal is the read's, not a DISABLED account: that would
// name a state the row does not have, and the operator reading the trail would
// go looking for a toggle nobody flipped.
func TestEnrichClaims_ServiceAccountRowMissing_IsNotReportedAsDisabled(t *testing.T) {
	svc := NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "api.kacho.cloud"}).
		WithOwnClientPort(stubOwnClients{soc: domain.ServiceAccountOAuthClient{
			CredentialKind: domain.CredentialKindKeypair,
			ID:             domain.SAOAuthClientID(disabledSocID),
			SvaID:          domain.ServiceAccountID(disabledSAID),
		}}).
		// What the repository actually hands back on a miss: no row, and the error.
		WithSAPort(stubSAPort{saErr: iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", disabledSAID)})

	claims, _, err := svc.ClaimsForAssertionClient(context.Background(), disabledSAClient, TokenHookContext{})

	require.Error(t, err, "an unresolved account row is refused, not minted for")
	assert.Nil(t, claims)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "the refusal is the read's not-found; got %v", err)
	assert.False(t, stderrors.Is(err, ErrServiceAccountDisabled))
}
