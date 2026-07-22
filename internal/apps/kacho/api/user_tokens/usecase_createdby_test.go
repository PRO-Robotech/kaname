// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_createdby_test.go — DEFECT (b) regression (#60 / UTM-12): Issue must
// SYNC-reject an invalid `created_by_user_id` BEFORE creating the async
// Operation, so an SA-caller (`sva…`, not a users(id) row) fails fast with a
// clear INVALID_ARGUMENT instead of the opaque async `user_oauth_clients`
// created_by FK code-9. A nonexistent well-formed user → FAILED_PRECONDITION.
package user_tokens

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// createdByStubRepo lets a test drive AccountForUser to model an absent
// created_by user (well-formed usr… id that does not exist).
type createdByStubRepo struct {
	stubUserClientRepo
	// missing — user ids for which AccountForUser returns ErrNotFound.
	missing map[string]bool
}

func (s *createdByStubRepo) AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, error) {
	if s.missing[string(id)] {
		return "", iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return "acc00000000000000001", nil
}

// TestIssue_SACallerRejectedSync (UTM-12): an SA created_by (`sva…`) →
// sync INVALID_ARGUMENT, and NO async Operation is started.
func TestIssue_SACallerRejectedSync(t *testing.T) {
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "sva00000000000000009", // an SA principal — not a users(id) row
	})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (SA created_by must fail SYNC, not async FK code-9)", grpcstatus.Code(err))
	}
	if op != nil {
		t.Fatal("no async Operation must be created when created_by is invalid")
	}
	// No leak of the raw pgx/FK text.
	if msg := grpcstatus.Convert(err).Message(); msg == "" {
		t.Fatal("expected a clear message")
	}
}

// TestIssue_NonexistentCreatedByRejectedSync (UTM-12): a well-formed but unknown
// `usr…` created_by → sync FAILED_PRECONDITION, no async Operation.
func TestIssue_NonexistentCreatedByRejectedSync(t *testing.T) {
	repo := &createdByStubRepo{missing: map[string]bool{"usr00000000000000404": true}}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000404", // well-formed usr… but not a known user
	})
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (unknown created_by user)", grpcstatus.Code(err))
	}
	if op != nil {
		t.Fatal("no async Operation must be created when created_by does not exist")
	}
}
