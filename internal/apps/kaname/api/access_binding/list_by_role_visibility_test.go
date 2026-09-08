// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_role_visibility_test.go — what a STRANGER receives from the "who holds
// role R" audit read.
//
// The catalog entry for this RPC asks `viewer` on the cluster singleton, and the
// cluster bootstrap grants that relation to `user:*` so the global reference
// catalog stays readable — so every authenticated subject passes the front door
// and the per-row scope filter in this use-case is the only narrowing there is.
// The suite pinned the positive arm (an account owner sees the binding) but never
// the negative one, and a filter with no red test for the case it exists to
// prevent is a filter that can be dropped in silence.
//
// Asserted at the level of the observable: the rows handed back, not the status
// code — a stranger must learn neither that the binding exists, nor who its
// subject is, nor which scope it sits on.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// TestListByRole_StrangerSeesNothing — an authenticated caller who neither owns
// the binding's scope, nor administers it, nor is its subject, gets an empty page.
func TestListByRole_StrangerSeesNothing(t *testing.T) {
	const (
		roleID    = "rol000000000sysadmin"
		ownerID   = "usr_owner"
		accountID = "acc_lbr_account"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_member",
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	// denyingFGA: no delegated admin anywhere, and the caller is not the owner.
	uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	got, _, err := uc.Execute(foreignCtx(), roleID, repoab.ListByRoleFilter{PageSize: 50})

	require.NoError(t, err, "a stranger gets an empty page, not an error")
	require.Empty(t, got,
		"a stranger must learn neither that the binding exists nor who holds the role")
}

// TestListByRole_SubjectOfBindingSeesOwnRow — the deliberate exception: the
// person the grant is ABOUT sees their own row even without scope authority. Pins
// that the narrowing above is a scope filter and not a blanket denial.
func TestListByRole_SubjectOfBindingSeesOwnRow(t *testing.T) {
	const (
		roleID    = "rol000000000sysadmin"
		ownerID   = "usr_owner"
		accountID = "acc_lbr_account"
		memberID  = "usr_member"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    memberID,
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	got, _, err := uc.Execute(newOwnerContext(memberID), roleID, repoab.ListByRoleFilter{PageSize: 50})

	require.NoError(t, err)
	require.Len(t, got, 1, "the subject of the grant sees the grant that names them")
	require.Equal(t, domain.SubjectID(memberID), got[0].SubjectID)
}
