// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_disabled_sa_test.go — no fresh credential for a service account that
// may not authenticate.
//
// Refusing the TOKEN is not the whole answer. Issue mints a NEW key and
// registers a client with the provider, and both outlive this call: the key is
// handed to whoever asked, and it starts working the moment the account is
// enabled again — a credential nobody decided to grant then. The account
// component documents this refusal as existing; until now the Issue path never
// read the field, so it did not.
//
// The refusal is synchronous. A well-formed request whose precondition does not
// hold owes the caller an answer now, not an Operation that fails later with a
// code they have to go and interpret.
package sa_keys

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestIssue_DisabledServiceAccount_Refused(t *testing.T) {
	repo := &stubSAClientRepo{disabled: true}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000001",
		CreatedByUserID:  "usr00000000000000001",
		Name:             "key-for-a-disabled-account",
	})

	if err == nil {
		t.Fatalf("a disabled service account must not be issued a new key; got op=%v", op)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition (the request is well-formed; the "+
			"account's state is what does not permit it): %v", got, err)
	}
	if repo.insertOK {
		t.Errorf("no key row may be written for an account that may not authenticate")
	}
	if ops.created {
		t.Errorf("no Operation may be started for a request refused synchronously")
	}
}

// The control. `enabled` arrives false in every zero value, so a check on a
// field the query does not load refuses every service account there is. This
// test is what fails then — and issuing keys is how machine access is
// bootstrapped, so that failure would be the whole platform.
func TestIssue_EnabledServiceAccount_StillIssues(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	if _, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000001",
		CreatedByUserID:  "usr00000000000000001",
		Name:             "key-for-a-live-account",
	}); err != nil {
		t.Fatalf("an enabled service account must still be issued a key: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}
	if !repo.insertOK {
		t.Errorf("the key row must be written")
	}
}

// Revoking and listing the keys of a disabled account must keep working. The
// state says the account may not AUTHENTICATE; taking away the ability to clean
// up after it would make disabling an account something an operator cannot
// finish, and would strand live keys precisely where they most want removing.
func TestRevoke_DisabledServiceAccount_StillRevokes(t *testing.T) {
	repo := &stubSAClientRepo{disabled: true}
	repo.getRow = domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             "soc00000000000000001",
		SvaID:          "sva00000000000000001",
	}
	ops := &stubOpsRepo{}
	uc := NewRevokeSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	if _, err := uc.Execute(context.Background(), RevokeInput{
		ServiceAccountID: "sva00000000000000001",
		KeyID:            repo.getRow.ID,
	}); err != nil {
		t.Fatalf("the keys of a disabled account must remain revocable: %v", err)
	}
	// The synchronous return says only that the verb ACCEPTED the request; the
	// removal happens in the worker. Without the two assertions below this test
	// stayed green on a revoke that removed nothing at all — and with revoke now
	// answering success on a barren outcome (#1216), "no error" is exactly what
	// a broken removal would also look like.
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("the revoke of a disabled account's key failed in the worker: %+v", ops.lastErr)
	}
	if !repo.deleted {
		t.Error("the row was not removed — the key of a disabled account stayed live")
	}
}
