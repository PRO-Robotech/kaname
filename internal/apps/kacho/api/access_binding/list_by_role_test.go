// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_by_role_test.go — RBAC rules-model 2026 unit tests for
// the ListByRole audit read-RPC. The repo lister is exercised by the pg
// integration test; here we assert the use-case authz floor + the read flow over
// the fake repo.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

func TestListByRole_E33_AnonymousRejected(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_a", "acc_a", "rol_r", "viewer", domain.Permissions{"iam.access_bindings.get"})
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	_, _, err := uc.Execute(context.Background(), "rol_r", repoab.ListByRoleFilter{})
	require.Error(t, err, "anonymous caller must be rejected")
}

func TestListByRole_E33_MalformedRoleID(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_a", "acc_a", "rol_r", "viewer", domain.Permissions{"iam.access_bindings.get"})
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := newOwnerContext("usr_owner")
	_, _, err := uc.Execute(ctx, "not-a-role-id!!", repoab.ListByRoleFilter{})
	require.Error(t, err, "malformed role id → INVALID_ARGUMENT")
}

func TestListByRole_E33_OwnerSeesBinding(t *testing.T) {
	const (
		roleID    = "rol000000000sysadmin"
		ownerID   = "usr_owner"
		accountID = "acc_lbr_account"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer", domain.Permissions{"iam.access_bindings.get"})
	// Seed a binding carrying the role (the fake's single-binding store).
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_member",
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := newOwnerContext(ownerID) // account owner → grant authority

	got, _, err := uc.Execute(ctx, roleID, repoab.ListByRoleFilter{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, got, 1, "account owner sees the binding carrying the role")
	require.Equal(t, domain.RoleID(roleID), got[0].RoleID)
}

var _ = authzguard.PermissionDenied // keep import referenced
