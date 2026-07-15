// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_federation_out_test.go — Phase 3c Federation OUT: end-to-end
// IssueSAKeyUseCase.Execute() coverage that asserts caller-supplied audience
// reaches Hydra in the CreateOAuthClient request and is echoed in the
// IssueSAKeyResponse for the operator to confirm without re-reading Hydra
// admin. Stubs are reused from usecase_federated_test.go (same package).
//
// Two paths exercised:
//   - Phase 3a (private_key_jwt, no TrustedSubjects) + Audience
//   - Phase 3b (federated, jwt-bearer) + Audience
//
// Backwards-compat: Audience empty falls back to AudiencePrefix-built
// internal audience (already covered by TestResolveAudience and
// TestIssue_FederatedPath_HydraRequestShape).
package sa_keys

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestIssue_PrivateKeyJWT_AudienceOverridesPrefix — Phase 3a + Phase 3c: when
// the caller supplies Audience the use-case MUST register the Hydra client
// with EXACTLY that audience list (overriding the configured AudiencePrefix)
// and echo it in IssueSAKeyResponse.Audiences.
func TestIssue_PrivateKeyJWT_AudienceOverridesPrefix(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)
	u.AudiencePrefix = "https://internal.example/iam"

	in := IssueInput{
		ServiceAccountID: "sva_ext",
		CreatedByUserID:  "usr_admin",
		Audience:         []string{"sts.example.com"},
	}

	_, err := u.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("Hydra CreateOAuthClient never called")
	}
	if len(hydra.gotReq.Audience) != 1 || hydra.gotReq.Audience[0] != "sts.example.com" {
		t.Fatalf("Hydra audience = %v, want [sts.example.com] (caller override, NOT %s/sa/sva_ext)",
			hydra.gotReq.Audience, u.AudiencePrefix)
	}

	if ops.lastResp == nil {
		t.Fatal("MarkDone response nil")
	}
	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audiences) != 1 || resp.Audiences[0] != "sts.example.com" {
		t.Fatalf("Response.Audiences = %v, want [sts.example.com]", resp.Audiences)
	}
	if resp.PrivateKeyPem == "" {
		t.Error("Phase 3a private_key_pem must still be returned with caller audience")
	}
}

// TestIssue_Federated_AudienceOverridesPrefix — Phase 3b + Phase 3c: federated
// path also accepts caller-supplied audience and lands it both on Hydra and
// in the response.
func TestIssue_Federated_AudienceOverridesPrefix(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)
	u.AudiencePrefix = "https://internal.example/iam"

	in := IssueInput{
		ServiceAccountID: "sva_ext2",
		CreatedByUserID:  "usr_admin",
		TrustedSubjects: []domain.TrustedSubject{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				SubjectPattern: "^repo:acme/infra:ref:refs/heads/main$",
			},
		},
		Audience: []string{
			"//idp.example.com/pools/p/providers/x",
		},
	}

	_, err := u.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("Hydra CreateOAuthClient never called")
	}
	want := "//idp.example.com/pools/p/providers/x"
	if len(hydra.gotReq.Audience) != 1 || hydra.gotReq.Audience[0] != want {
		t.Fatalf("Hydra audience = %v, want [%s]", hydra.gotReq.Audience, want)
	}

	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audiences) != 1 || resp.Audiences[0] != want {
		t.Fatalf("Response.Audiences = %v, want [%s]", resp.Audiences, want)
	}
	if resp.PrivateKeyPem != "" || resp.PublicKeyPem != "" {
		t.Error("federated response must omit key material even with caller audience")
	}
}

// TestIssue_AudienceDedupAndEmptyDrop — caller-supplied audience with
// duplicates + empty entries is sanitized before reaching Hydra.
func TestIssue_AudienceDedupAndEmptyDrop(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_abc",
		CreatedByUserID:  "usr_admin",
		Audience:         []string{"a.example", "", "a.example", "b.example", ""},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	got := hydra.gotReq.Audience
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("audience not sanitized: %v", got)
	}
}
