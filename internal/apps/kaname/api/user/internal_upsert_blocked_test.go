// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// internal_upsert_blocked_test.go — a blocked identity does not get provisioned
// back in by signing in again.
//
// The provisioning hook fires on LOGIN as well as registration, and it decided
// whether an identity was new by asking for its ACTIVE rows. A blocked user has
// none, which is indistinguishable from never having been seen — so the hook
// took the new-identity branch and wrote a fresh ACTIVE row, plus a personal
// account, a project and self-admin grants over them. The next token request
// then found an ACTIVE row and minted.
//
// That is the same shape as the refusal added to the hooks, in the one path
// that could undo it: blocking a user was reversible by the blocked user, at
// will, by logging in. The uniqueness index does not stand in the way either —
// it covers ACTIVE rows only, so a blocked row leaves the slot free.
//
// First login must keep working: it is the case the new-identity branch exists
// for, and an identity nobody has ever seen is genuinely new.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const blockedExternalID = domain.ExternalSubject("krt-blocked-identity")

func blockedIdentityRow() domain.User {
	return domain.User{
		ID:           "usr0000000000blockd1",
		AccountID:    "acc0000000000blockd1",
		ExternalID:   blockedExternalID,
		Email:        "blocked@example.com",
		DisplayName:  "Blocked",
		InviteStatus: domain.InviteStatusBlocked,
	}
}

func TestUpsertFromIdentity_BlockedIdentity_NotReprovisioned(t *testing.T) {
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{blockedIdentityRow()}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  blockedExternalID,
		Email:       "blocked@example.com",
		DisplayName: "Blocked",
	})

	require.Error(t, err, "a blocked identity signing in again must not be provisioned; "+
		"got op=%v", op)
	assert.Nil(t, op, "and no Operation may be started for it")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code(),
		"the request is well-formed; the identity's state is what does not permit it")

	assert.Equal(t, 0, repo.upsertCalls(),
		"no user row may be written — writing one hands the blocked identity a fresh "+
			"ACTIVE row, and with it an account, a project and admin over both")
}

// First login: no row of any state. This is the case the new-identity branch
// exists for, and refusing it would break every genuine signup.
func TestUpsertFromIdentity_UnknownIdentity_StillProvisioned(t *testing.T) {
	repo := newFakeUserRepo() // no rows at all
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  "krt-first-login",
		Email:       "first@example.com",
		DisplayName: "First",
	})

	require.NoError(t, err, "first login must still provision")
	require.NotNil(t, op)
}

// Blocking lives on the MEMBERSHIP row, so it belongs to one account. An
// invitation to a different account is a membership that account issued itself,
// and it must still be acceptable — otherwise one account blocking a person
// locks them out everywhere, including places that never heard of them.
func TestUpsertFromIdentity_BlockedElsewhereWithPendingInvite_StillProvisioned(t *testing.T) {
	pending := domain.User{
		ID:        "usr0000000000pendng1",
		AccountID: "acc0000000000invitr1",
		// A pending invitee carries no external id — the DB CHECK forbids it —
		// which is why it is found by email and not by the identity above.
		ExternalID:   "",
		Email:        "blocked@example.com",
		InviteStatus: domain.InviteStatusPending,
	}
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{blockedIdentityRow(), pending}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  blockedExternalID,
		Email:       "blocked@example.com",
		DisplayName: "Blocked",
	})

	require.NoError(t, err, "a pending invitation from another account must still be "+
		"acceptable; a block belongs to the account that issued it")
	require.NotNil(t, op)
}

// An identity that is blocked in one account and active in another may still
// sign in: the active membership is a real one, and refusing it would let a
// single blocked membership lock a person out of accounts that never blocked
// them.
func TestUpsertFromIdentity_BlockedInOneAccountActiveInAnother_StillProvisioned(t *testing.T) {
	blocked := blockedIdentityRow()
	active := domain.User{
		ID:           "usr0000000000active1",
		AccountID:    "acc0000000000active1",
		ExternalID:   blockedExternalID,
		Email:        "blocked@example.com",
		InviteStatus: domain.InviteStatusActive,
	}
	repo := newFakeUserRepo()
	repo.existingActive = []domain.User{blocked, active}
	uc := NewUpsertFromIdentityUseCase(repo, newFakeOpsRepoUser())

	op, err := uc.Execute(context.Background(), UpsertFromIdentityInput{
		ExternalID:  blockedExternalID,
		Email:       "blocked@example.com",
		DisplayName: "Blocked",
	})

	require.NoError(t, err, "one blocked membership must not lock the person out of the "+
		"accounts that did not block them")
	require.NotNil(t, op)
}
