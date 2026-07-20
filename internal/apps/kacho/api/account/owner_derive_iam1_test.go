// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// owner_derive_iam1_test.go — redesign-2026 F1 (IAM-1-01/02/03):
// Account.ownerUserId° is OUTPUT-ONLY, derived-from-caller.
//
//   - IAM-1-01 (positive): Create WITHOUT ownerUserId → the authenticated caller
//     becomes owner° automatically (owner AccessBinding subject == principal.id).
//   - IAM-1-02 (negative): ownerUserId in Create-body → sync INVALID_ARGUMENT
//     "Illegal argument ownerUserId (derived from caller)", first statement,
//     before the Operation is minted. Even ownerUserId == principal.id is
//     rejected (output-only by construction — removes both the AS-IS
//     required-branch and the anti-hijack branch).
//   - IAM-1-03 (edge): Update(update_mask=["ownerUserId"]) → sync INVALID_ARGUMENT
//     "ownerUserId is immutable after Account.Create" (immutable-switch before
//     corevalidate.UpdateMask).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

const iam1Principal = "usr00000000000000abcd"

// IAM-1-01: owner derived from the authenticated caller when absent from body.
func TestAccount_IAM_1_01_OwnerDerivedFromCaller(t *testing.T) {
	repo := newFakeRepo()
	uc := NewCreateAccountUseCase(repo, newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: iam1Principal})

	op, err := uc.Execute(ctx, domain.Account{Name: "acme-prod"}) // NO OwnerUserID in body
	require.NoError(t, err)
	require.NotNil(t, op)

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	// Owner° is the caller — observable through the co-committed owner binding.
	bindings := repo.ownerBindingsSnapshot()
	require.Len(t, bindings, 1)
	assert.Equal(t, domain.SubjectID(iam1Principal), bindings[0].SubjectID,
		"owner binding subject must be the authenticated caller (derived owner)")
}

// IAM-1-02: ownerUserId supplied in the Create body → sync reject, no Operation.
func TestAccount_IAM_1_02_OwnerInBody_Reject(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: iam1Principal})

	// Both an attacker id AND the caller's own id are rejected: the field is
	// output-only by construction, not merely anti-hijack.
	for _, owner := range []string{"usr-attacker000000000", iam1Principal} {
		uc := NewCreateAccountUseCase(newFakeRepo(), newFakeOpsRepo())
		op, err := uc.Execute(ctx, domain.Account{
			Name:        "acme-prod",
			OwnerUserID: domain.UserID(owner),
		})
		require.Error(t, err, "owner=%q must reject", owner)
		assert.Nil(t, op, "no Operation minted on sync reject")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Equal(t, "Illegal argument ownerUserId (derived from caller)", st.Message(),
			"owner=%q contract text", owner)
	}
}

// IAM-1-03: ownerUserId is immutable in Update.
func TestAccount_IAM_1_03_OwnerImmutable_Update(t *testing.T) {
	uc := NewUpdateAccountUseCase(newFakeRepo(), newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: iam1Principal})

	for _, field := range []string{"ownerUserId", "owner_user_id"} {
		op, err := uc.Execute(ctx, UpdateAccountInput{
			ID:         "acc0000000000000abcd",
			UpdateMask: []string{field},
		})
		require.Error(t, err, "mask=[%q]", field)
		assert.Nil(t, op)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code(), "mask=[%q]", field)
		assert.Equal(t, "ownerUserId is immutable after Account.Create", st.Message(),
			"mask=[%q] contract text", field)
	}
}
