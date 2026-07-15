// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_name_labels_test.go — unit-тесты create-only name + labels на SA-key
// Issue (маппинг проходит в persisted row + proto-response) и стемпинг account_id
// на IssueSAKeyMetadata / RevokeSAKeyMetadata (иначе /iam/operations, scoped по
// account_id, не показывает token-операции).
package sa_keys

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// AccountForServiceAccount — резолвер account'а SA (порт SAClientRepo). Дефолт —
// фиксированный account; тесты account_id-стемпинга подставляют свой.
func (s *stubSAClientRepo) AccountForServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.AccountID, error) {
	if s.accountID != "" {
		return s.accountID, nil
	}
	return "acc00000000000000001", nil
}

// TestIssue_NameLabels_MapThrough — name + labels из IssueInput попадают в
// persisted row (Insert) и в proto-response (saClientToProto).
func TestIssue_NameLabels_MapThrough(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000001",
		CreatedByUserID:  "usr00000000000000001",
		Name:             "prod-ci-key",
		Labels:           domain.Labels{"env": "prod", "team": "platform"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}

	// name + labels persisted on the row.
	if repo.inserted.Name != "prod-ci-key" {
		t.Errorf("inserted.Name = %q, want prod-ci-key", repo.inserted.Name)
	}
	if repo.inserted.Labels["env"] != "prod" || repo.inserted.Labels["team"] != "platform" {
		t.Errorf("inserted.Labels = %v, want {env:prod team:platform}", repo.inserted.Labels)
	}

	// name + labels echoed in proto response.
	var resp iamv1.IssueSAKeyResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	key := resp.GetKey()
	if key == nil {
		t.Fatal("response.key nil")
	}
	if key.GetName() != "prod-ci-key" {
		t.Errorf("response.key.name = %q, want prod-ci-key", key.GetName())
	}
	if key.GetLabels()["env"] != "prod" || key.GetLabels()["team"] != "platform" {
		t.Errorf("response.key.labels = %v, want {env:prod team:platform}", key.GetLabels())
	}
}

// TestIssue_AccountIDStampedOnMetadata — account_id владельца SA стемпится на
// IssueSAKeyMetadata (иначе /iam/operations account-scoped исключает операцию).
func TestIssue_AccountIDStampedOnMetadata(t *testing.T) {
	repo := &stubSAClientRepo{accountID: "acc00000000000000042"}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000001",
		CreatedByUserID:  "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil || op.Metadata == nil {
		t.Fatal("operation / metadata nil")
	}
	var meta iamv1.IssueSAKeyMetadata
	if err := op.Metadata.UnmarshalTo(&meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.GetAccountId() != "acc00000000000000042" {
		t.Errorf("IssueSAKeyMetadata.account_id = %q, want acc00000000000000042", meta.GetAccountId())
	}
	if meta.GetServiceAccountId() != "sva00000000000000001" {
		t.Errorf("IssueSAKeyMetadata.service_account_id = %q", meta.GetServiceAccountId())
	}
}

// TestRevoke_AccountIDStampedOnMetadata — account_id владельца SA стемпится на
// RevokeSAKeyMetadata тем же образом.
func TestRevoke_AccountIDStampedOnMetadata(t *testing.T) {
	repo := &stubSAClientRepo{
		accountID: "acc00000000000000042",
		getRow: domain.ServiceAccountOAuthClient{
			ID:            "soc00000000000000009",
			SvaID:         "sva00000000000000001",
			OAuthClientID: "hydra-soc-9",
		},
	}
	ops := &stubOpsRepo{}
	uc := NewRevokeSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), RevokeInput{
		ServiceAccountID: "sva00000000000000001",
		KeyID:            "soc00000000000000009",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil || op.Metadata == nil {
		t.Fatal("operation / metadata nil")
	}
	var meta iamv1.RevokeSAKeyMetadata
	if err := op.Metadata.UnmarshalTo(&meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.GetAccountId() != "acc00000000000000042" {
		t.Errorf("RevokeSAKeyMetadata.account_id = %q, want acc00000000000000042", meta.GetAccountId())
	}
}
