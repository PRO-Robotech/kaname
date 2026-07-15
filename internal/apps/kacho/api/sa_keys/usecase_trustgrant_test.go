// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_trustgrant_test.go — federation IN: the federated Issue path registers
// an EXACT-subject jwt-bearer trust-grant in Hydra for each trusted subject, so
// Hydra accepts an external assertion only when its `sub` matches verbatim.
package sa_keys

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeTrustGrants — records the trust-grants the federated Issue registers.
type fakeTrustGrants struct {
	calls []clients.JWTBearerTrustGrant
	err   error
}

func (f *fakeTrustGrants) CreateJWTBearerTrustGrant(_ context.Context, g clients.JWTBearerTrustGrant) error {
	f.calls = append(f.calls, g)
	return f.err
}

// recordingHydra — an OAuthClientAdmin that records DeleteOAuthClient (rollback).
type recordingHydra struct {
	deleted bool
}

func (r *recordingHydra) CreateOAuthClient(_ context.Context, _ clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	return clients.HydraOAuthClient{ClientID: "hydra-cli-fake"}, nil
}
func (r *recordingHydra) DeleteOAuthClient(_ context.Context, _ string) error {
	r.deleted = true
	return nil
}

// TestIssue_Federated_RegistersExactSubjectTrustGrant — the literal-anchored
// subject_pattern is registered as an EXACT subject (unanchored) with
// allow_any_subject=false.
func TestIssue_Federated_RegistersExactSubjectTrustGrant(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	tg := &fakeTrustGrants{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithTrustGrantAdmin(tg)

	in := IssueInput{
		ServiceAccountID: "sva_test",
		CreatedByUserID:  "usr_admin",
		TrustedSubjects: []domain.TrustedSubject{
			{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"},
		},
	}
	if _, err := u.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if !repo.insertOK {
		t.Fatal("mapping must be persisted on success")
	}
	if len(tg.calls) != 1 {
		t.Fatalf("trust-grant calls = %d; want 1", len(tg.calls))
	}
	g := tg.calls[0]
	if g.Issuer != "https://kube.cluster.local" {
		t.Errorf("issuer = %q", g.Issuer)
	}
	if g.Subject != "system:serviceaccount:ci:deployer" {
		t.Errorf("subject = %q; want the EXACT unanchored literal", g.Subject)
	}
	if g.AllowAnySubject {
		t.Error("allow_any_subject must be false (no wildcard federation)")
	}
}

// TestIssue_Federated_TrustGrantFailure_RollsBackClient — a trust-grant failure
// fails the operation (no mapping persisted) and rolls back the Hydra client.
func TestIssue_Federated_TrustGrantFailure_RollsBackClient(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &recordingHydra{}
	tg := &fakeTrustGrants{err: errors.New("hydra trust-grant down")}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithTrustGrantAdmin(tg)

	in := IssueInput{
		ServiceAccountID: "sva_test",
		CreatedByUserID:  "usr_admin",
		TrustedSubjects: []domain.TrustedSubject{
			{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"},
		},
	}
	if _, err := u.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if repo.insertOK {
		t.Error("mapping must NOT be persisted when the trust-grant fails")
	}
	if !hydra.deleted {
		t.Error("the Hydra client must be rolled back when the trust-grant fails")
	}
}
