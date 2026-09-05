// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_blocked_user_test.go — no fresh personal token for a user who may not
// authenticate.
//
// The hooks already refuse to MINT a token for such a user. Issuing them a new
// personal access token is a separate act with a separate consequence: the
// secret is handed over and kept, and it begins working the day the account is
// unblocked — a credential granted while nobody was allowed to grant it.
//
// The path resolves the owner to stamp the operation's account, through a query
// that selected the account and nothing else. Same shape as every other
// instance of this class: the state was one column away from a decision that
// never asked for it.
package user_tokens

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestIssue_BlockedUser_Refused(t *testing.T) {
	repo := &stubUserClientRepo{blocked: true}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		Name:            "token-for-a-blocked-user",
	})

	if err == nil {
		t.Fatalf("a user who may not authenticate must not be issued a personal token; got op=%v", op)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition (well-formed request, the subject's "+
			"state is what does not permit it): %v", got, err)
	}
	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.created {
		t.Errorf("no Operation may be started for a request refused synchronously")
	}
}

// The control: the ordinary case must survive the fix.
func TestIssue_ActiveUser_StillIssues(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	if _, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		Name:            "token-for-a-live-user",
	}); err != nil {
		t.Fatalf("an active user must still be issued a personal token: %v", err)
	}
}

// A token issued to someone acting on behalf of a blocked user is the same
// credential by another route, so the same answer is owed — otherwise the
// refusal above is a speed bump with a documented detour.
func TestIssue_BlockedTargetNamedByAnotherCaller_Refused(t *testing.T) {
	repo := &stubUserClientRepo{blocked: true, blockedIDs: map[domain.UserID]bool{
		"usr00000000000000002": true,
	}}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000002",
		CreatedByUserID: "usr00000000000000001",
		Name:            "token-minted-for-someone-else",
	})
	if err == nil {
		t.Fatal("the state of the token's OWNER decides, not the state of whoever asked")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition: %v", got, err)
	}
}
