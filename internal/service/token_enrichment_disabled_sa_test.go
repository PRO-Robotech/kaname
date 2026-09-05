// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_disabled_sa_test.go — a service account that may not
// authenticate mints nothing, on either machine branch.
//
// `service_accounts.enabled` states whether an account may authenticate, and
// both machine branches of the enricher resolve the account row on their way to
// the claim set: `client_credentials` (an SA key presented as a client
// assertion) and `jwt-bearer` (an external assertion matched against
// `trusted_subjects`). Neither consulted the field, so disabling an account
// took nothing away from it.
//
// The refusal is its own sentinel rather than the user one: what fails on these
// branches is client authentication, and the hook owes a machine credential a
// different diagnostic than it owes a human. Absent is a third answer again — a
// client id that maps to nothing is not a disabled account, and the two must
// stay distinguishable.
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

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

const (
	disabledSAClientID = "kacho-sak-disabled"
	disabledSAID       = "sva01disabledsa001"
	disabledSocID      = "soc_01disabledsa001"
	disabledSAAccID    = "acc01disabledsa001"
	disabledSAIssuer   = "https://idp.partner.example"
	disabledSAExtSub   = "partner-workload-1"
)

// saPortWithState — the SA mapping resolves; the account behind it carries the
// state under test. Deliberately reports the account as PRESENT: the defect was
// never a missing row, it was a present row nobody read.
func saPortWithState(enabled bool) stubSAPort {
	return stubSAPort{
		soc: domain.ServiceAccountOAuthClient{
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
			// словарь таблицы отвергает строку, вида не назвавшую.
			CredentialKind: domain.CredentialKindKeypair,
			ID:             domain.SAOAuthClientID(disabledSocID),
			SvaID:          domain.ServiceAccountID(disabledSAID),
			OAuthClientID:  domain.OAuthClientID(disabledSAClientID),
		},
		sa: domain.ServiceAccount{
			ID:        domain.ServiceAccountID(disabledSAID),
			AccountID: domain.AccountID(disabledSAAccID),
			Enabled:   enabled,
		},
	}
}

// fedSAPortWithState — same account, reached through the federated lookup so
// the jwt-bearer branch is the one exercised (the direct lookup misses).
type fedSAPortWithState struct{ inner stubSAPort }

func (p fedSAPortWithState) LookupByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

func (p fedSAPortWithState) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return p.inner.GetServiceAccount(ctx, id)
}

func (p fedSAPortWithState) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	return p.inner.soc, nil
}

func newSAEnricher(port TokenEnrichmentSAPort) *TokenEnrichmentService {
	return NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: "https://hydra.kacho.cloud"},
		stubUserPort{},
	).WithSAPort(port)
}

// ── client_credentials (SA key) ─────────────────────────────────────────────

func TestEnrichClaims_DisabledServiceAccount_Refused(t *testing.T) {
	svc := newSAEnricher(saPortWithState(false))

	claims, _, err := svc.EnrichClaims(context.Background(), disabledSAClientID,
		TokenHookContext{GrantType: "client_credentials", OAuthClientID: disabledSAClientID})

	require.Error(t, err, "a service account that may not authenticate must not mint a token")
	assert.True(t, stderrors.Is(err, ErrServiceAccountDisabled),
		"the refusal must be the disabled-account sentinel so the hook answers 403 and names "+
			"what failed; got %v", err)
	assert.Nil(t, claims, "no claims may be produced for an account that may not authenticate")
	assert.NotContains(t, err.Error(), "not found",
		"a disabled account is present and refused, not missing — collapsing the two is how "+
			"the interactive branch once minted for a blocked user")
}

// The control. `Enabled` is a bool: it is false in every zero value, so a deny
// branch reading a field the query never loaded refuses EVERY service account
// while looking exactly like a working gate. This test is what fails then.
func TestEnrichClaims_EnabledServiceAccount_StillMints(t *testing.T) {
	svc := newSAEnricher(saPortWithState(true))

	claims, _, err := svc.EnrichClaims(context.Background(), disabledSAClientID,
		TokenHookContext{GrantType: "client_credentials", OAuthClientID: disabledSAClientID})

	require.NoError(t, err, "an enabled service account must keep minting; refusing it trades "+
		"one hole for an outage of every machine flow there is")
	require.NotNil(t, claims)
	assert.Equal(t, "service_account", claims["kacho_principal_type"])
	assert.Equal(t, disabledSAID, claims["kacho_principal_id"])
	assert.Equal(t, disabledSAAccID, claims["kacho_account_id"])
}

// ── jwt-bearer (federated assertion) ────────────────────────────────────────

func TestEnrichClaims_DisabledFederatedServiceAccount_Refused(t *testing.T) {
	svc := newSAEnricher(fedSAPortWithState{inner: saPortWithState(false)})

	claims, _, err := svc.EnrichClaims(context.Background(), disabledSAExtSub, TokenHookContext{
		GrantType:      "urn:ietf:params:oauth:grant-type:jwt-bearer",
		ExternalIssuer: disabledSAIssuer,
		OAuthClientID:  disabledSAClientID,
	})

	require.Error(t, err, "federation-in resolves to the same account and owes the same answer; "+
		"a state that stops one branch and not the other is not a state at all")
	assert.True(t, stderrors.Is(err, ErrServiceAccountDisabled), "got %v", err)
	assert.Nil(t, claims)
}

func TestEnrichClaims_EnabledFederatedServiceAccount_StillMints(t *testing.T) {
	svc := newSAEnricher(fedSAPortWithState{inner: saPortWithState(true)})

	claims, _, err := svc.EnrichClaims(context.Background(), disabledSAExtSub, TokenHookContext{
		GrantType:      "urn:ietf:params:oauth:grant-type:jwt-bearer",
		ExternalIssuer: disabledSAIssuer,
		OAuthClientID:  disabledSAClientID,
	})

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, disabledSAID, claims["kacho_principal_id"])
}

// ── the account is gone, which is not the same as disabled ──────────────────

// The mapping row references the account under an ON DELETE RESTRICT foreign
// key, so an account cannot be dropped from under a live mapping. Should that
// read miss anyway, the answer stays what it was — an unresolved mapping is
// reported as such and the hook refuses the machine credential through its own
// branch. It must not be reported as a DISABLED account: that names a state the
// row does not have, and the operator reading the trail would go looking for a
// toggle nobody flipped.
func TestEnrichClaims_ServiceAccountRowMissing_IsNotReportedAsDisabled(t *testing.T) {
	port := saPortWithState(false)
	// What the repository actually hands back on a miss: no row, and the error.
	port.sa = domain.ServiceAccount{}
	port.saErr = iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", disabledSAID)
	svc := newSAEnricher(port)

	claims, _, err := svc.EnrichClaims(context.Background(), disabledSAClientID,
		TokenHookContext{GrantType: "client_credentials", OAuthClientID: disabledSAClientID})

	require.NoError(t, err, "an unresolved account row is the pre-existing not-found path, "+
		"answered by the caller, not a new refusal invented here")
	require.NotNil(t, claims)
	assert.False(t, stderrors.Is(err, ErrServiceAccountDisabled))
	assert.NotContains(t, claims, "kacho_account_id",
		"and it still omits the account it could not resolve")
}
