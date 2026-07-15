// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_name_labels_test.go — unit-тесты create-only name + labels на
// user-token Issue (маппинг проходит в persisted row + proto-response) и
// стемпинг account_id на IssueUserTokenMetadata / RevokeUserTokenMetadata
// (иначе /iam/operations, scoped по account_id, не показывает token-операции).
package user_tokens

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestIssue_NameLabels_MapThrough — name + labels из IssueInput попадают в
// persisted row (Insert) и в proto-response (userTokenToProto).
func TestIssue_NameLabels_MapThrough(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		Name:            "laptop-token",
		Labels:          domain.Labels{"device": "macbook", "purpose": "cli"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}

	if repo.inserted.Name != "laptop-token" {
		t.Errorf("inserted.Name = %q, want laptop-token", repo.inserted.Name)
	}
	if repo.inserted.Labels["device"] != "macbook" || repo.inserted.Labels["purpose"] != "cli" {
		t.Errorf("inserted.Labels = %v, want {device:macbook purpose:cli}", repo.inserted.Labels)
	}

	var resp iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	tok := resp.GetToken()
	if tok == nil {
		t.Fatal("response.token nil")
	}
	if tok.GetName() != "laptop-token" {
		t.Errorf("response.token.name = %q, want laptop-token", tok.GetName())
	}
	if tok.GetLabels()["device"] != "macbook" || tok.GetLabels()["purpose"] != "cli" {
		t.Errorf("response.token.labels = %v, want {device:macbook purpose:cli}", tok.GetLabels())
	}
}

// TestIssue_AccountIDStampedOnMetadata — account_id владельца User стемпится на
// IssueUserTokenMetadata (иначе /iam/operations account-scoped исключает операцию).
func TestIssue_AccountIDStampedOnMetadata(t *testing.T) {
	repo := &stubUserClientRepo{accountID: "acc00000000000000042"}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil || op.Metadata == nil {
		t.Fatal("operation / metadata nil")
	}
	var meta iamv1.IssueUserTokenMetadata
	if err := op.Metadata.UnmarshalTo(&meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.GetAccountId() != "acc00000000000000042" {
		t.Errorf("IssueUserTokenMetadata.account_id = %q, want acc00000000000000042", meta.GetAccountId())
	}
	if meta.GetUserId() != "usr00000000000000001" {
		t.Errorf("IssueUserTokenMetadata.user_id = %q", meta.GetUserId())
	}
}

// TestRevoke_AccountIDStampedOnMetadata — account_id владельца User стемпится на
// RevokeUserTokenMetadata тем же образом.
func TestRevoke_AccountIDStampedOnMetadata(t *testing.T) {
	repo := &stubUserClientRepo{
		accountID: "acc00000000000000042",
		getRow: domain.UserOAuthClient{
			ID:            "uoc00000000000000009",
			UserID:        "usr00000000000000001",
			OAuthClientID: "hydra-uoc-9",
		},
	}
	ops := &stubOpsRepo{}
	uc := NewRevokeUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), RevokeInput{
		UserID:  "usr00000000000000001",
		TokenID: "uoc00000000000000009",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil || op.Metadata == nil {
		t.Fatal("operation / metadata nil")
	}
	var meta iamv1.RevokeUserTokenMetadata
	if err := op.Metadata.UnmarshalTo(&meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.GetAccountId() != "acc00000000000000042" {
		t.Errorf("RevokeUserTokenMetadata.account_id = %q, want acc00000000000000042", meta.GetAccountId())
	}
}
