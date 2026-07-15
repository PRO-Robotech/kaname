// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// deletion_protection_test.go — unit-тесты RBAC explicit-model 2026 P6
// (C-02 / C-03): deletion_protection sync pre-check на Delete + update_mask
// дисциплина на Update. Через in-memory abFakeRepo (без БД); CAS-backstop и
// concurrent-race — в integration (pg/access_binding_deletion_protection_integration_test.go).

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

// seedAccountBinding seeds an ACTIVE account-scoped binding on the fake repo so the
// owner (newOwnerContext) passes requireGrantAuthority (owner-of-account path).
func seedAccountBinding(repo *abFakeRepo, accountID, roleID string, protected bool) domain.AccessBindingID {
	id := domain.AccessBindingID("acb000000000000pr6ab")
	repo.mu.Lock()
	repo.ab = &domain.AccessBinding{
		ID:                 id,
		SubjectType:        domain.SubjectTypeUser,
		SubjectID:          "usr_some_subject01",
		RoleID:             domain.RoleID(roleID),
		ResourceType:       "account",
		ResourceID:         accountID,
		Scope:              domain.ScopeAccount,
		Status:             domain.AccessBindingStatusActive,
		DeletionProtection: protected,
	}
	repo.mu.Unlock()
	return id
}

// C-02: Delete on a protected binding → sync FAILED_PRECONDITION (before Operation).
func TestAccessBinding_Delete_Protected_SyncFailedPrecondition(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_p6_del", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id)
	require.Error(t, err)
	assert.Nil(t, op, "no Operation on a sync FAILED_PRECONDITION")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "deletion_protection enabled")
}

// #4/#6: Delete on a PROTECTED binding by an UNAUTHORIZED caller must return
// PERMISSION_DENIED — NOT the deletion_protection FAILED_PRECONDITION text. The
// grant-authority gate must run BEFORE the deletion_protection pre-check, otherwise
// an authenticated non-owner learns (a) the binding exists and (b) it is protected,
// regressing the uniform-403 existence-leak protection the not-found branch enforces.
func TestAccessBinding_Delete_Protected_Unauthorized_NoLeak(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_p6_leak", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true) // protected

	// Caller is NOT the owner and the FGA grants no admin → no grant-authority.
	rs := &scopedFGA{allow: map[string]bool{}}
	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(rs, nil)

	op, err := uc.Execute(clusterAdminCtx("usr_intruder"), id)
	require.Error(t, err)
	assert.Nil(t, op, "no Operation for an unauthorized caller")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"unauthorized caller on a protected binding → PERMISSION_DENIED (not FAILED_PRECONDITION)")
	assert.NotContains(t, st.Message(), "deletion_protection",
		"must NOT leak deletion_protection state to an unauthorized caller")
}

// C-02 negative-control: Delete on an unprotected binding passes the sync gate
// (returns an Operation).
func TestAccessBinding_Delete_Unprotected_NoSyncBlock(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_p6_del2", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, false)

	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id)
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))
}

// C-03: Update(update_mask=["deletion_protection"], false) clears the flag.
func TestAccessBinding_Update_ClearsDeletionProtection(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_p6_upd", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id, []string{"deletion_protection"}, false, nil)
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	repo.mu.Lock()
	got := repo.ab.DeletionProtection
	repo.mu.Unlock()
	assert.False(t, got, "Update cleared deletion_protection")
}

// C-03 update_mask discipline: an unknown / immutable field in the mask → sync
// INVALID_ARGUMENT.
func TestAccessBinding_Update_RejectsUnknownMaskField(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_p6_mask", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id, []string{"role_id"}, false, nil)
	require.Error(t, err)
	assert.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}
