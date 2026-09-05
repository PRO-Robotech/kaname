// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_binding_test.go — the issuance half of machine-token binding.
//
// The gateway can require that a machine principal present a sender-constrained
// token (RFC 7800 `cnf`), but that requirement is unreachable unless the
// identity provider is ASKED to mint bound tokens in the first place. Binding is
// a property of the registered OAuth2 client: without
// `dpop_bound_access_tokens` (RFC 9449 §5.2) or
// `tls_client_certificate_bound_access_tokens` (RFC 8705 §3.4) the provider
// mints plain bearers, and enabling enforcement at the edge would simply reject
// every service account.
//
// So the two halves ship together, both default-off, and this file locks the
// issuance half: what the client registration actually carries.
package sa_keys

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// TestIssue_BindDPoP_RegistersBoundClient — with binding enabled, the OAuth2
// client registered for the key demands DPoP-bound access tokens.
func TestIssue_BindDPoP_RegistersBoundClient(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.BindDPoP = true

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if !h.hydra.gotReq.DPoPBoundAccessTokens {
		t.Error("the registered client must demand DPoP-bound access tokens — " +
			"without it the provider mints plain bearers and edge enforcement can only reject")
	}
}

// TestIssue_BindDPoPOff_RegistersUnboundClient — default-off. Flipping issuance
// on is what makes edge enforcement viable; until then nothing changes.
func TestIssue_BindDPoPOff_RegistersUnboundClient(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.BindDPoP = false

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if h.hydra.gotReq.DPoPBoundAccessTokens {
		t.Error("binding must be opt-in; an un-migrated deployment must be unchanged")
	}
}

// TestIssue_Federated_BindDPoP_RegistersBoundClient — the federated path mints
// tokens from its own client too. Leaving it unbound while the private_key_jwt
// path is bound would make federation the soft way in, which is exactly the
// shape an attacker looks for.
func TestIssue_Federated_BindDPoP_RegistersBoundClient(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.BindDPoP = true

	err := h.issue(t, IssueInput{
		TTLSeconds: 3600,
		TrustedSubjects: []domain.TrustedSubject{{
			Issuer:         "https://kube.cluster.local",
			SubjectPattern: "^system:serviceaccount:ci:deployer$",
			PublicKeyPEM:   testIssuerPublicKeyPEM,
			KeyAlgorithm:   "ES256",
		}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if !h.hydra.gotReq.DPoPBoundAccessTokens {
		t.Error("the federated client must be bound too — otherwise federation is the unbound path in")
	}
}

// TestIssue_BindDPoP_IndependentOfLifespan — binding and lifetime are separate
// controls; setting one must not silently carry the other.
func TestIssue_BindDPoP_IndependentOfLifespan(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.BindDPoP = true
	h.uc.AccessTokenLifespan = 15 * time.Minute

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if !h.hydra.gotReq.DPoPBoundAccessTokens {
		t.Error("binding must be set")
	}
	if got := h.hydra.gotReq.AccessTokenLifespan; got != (15 * time.Minute).String() {
		t.Errorf("access_token_lifespan = %q; want it preserved alongside binding", got)
	}
}
