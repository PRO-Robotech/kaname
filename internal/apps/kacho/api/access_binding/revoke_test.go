// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// revoke_test.go — unit-тесты soft-revoke (redesign-2026 F10 IAM-1-28). Через
// in-memory abFakeRepo (без БД); atomic CAS-backstop + concurrent-race — в
// integration (pg/access_binding_revoke_integration_test.go).
//
// Покрытие sync-path (thin transport → use-case):
//   - malformed id → sync INVALID_ARGUMENT первым стейтментом (до repo).
//   - protected binding → sync FAILED_PRECONDITION ("...before revoke") до Operation.
//   - unauthorized caller на protected → PERMISSION_DENIED (grant-authority ДО
//     deletion_protection pre-check — не течёт protection-state, anti-leak).
//   - unprotected → Operation; после done fake-binding RETAINED со status=REVOKED
//     (контраст с Delete=hard, где row исчезает).

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

// IAM-1-28 sync-gate: malformed AB id → INVALID_ARGUMENT first statement (before repo).
func TestAccessBinding_Revoke_MalformedID_SyncInvalidArgument(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_rev_bad", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)

	uc := NewRevokeAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), domain.AccessBindingID("not-an-acb-id"))
	require.Error(t, err)
	assert.Nil(t, op, "no Operation on a sync INVALID_ARGUMENT")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// IAM-1-28 edge (delete-parity): Revoke on a protected binding → sync FAILED_PRECONDITION.
func TestAccessBinding_Revoke_Protected_SyncFailedPrecondition(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_rev_prot", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true) // protected

	uc := NewRevokeAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id)
	require.Error(t, err)
	assert.Nil(t, op, "no Operation on a sync FAILED_PRECONDITION")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "deletion_protection enabled")
	assert.Contains(t, st.Message(), "before revoke")
}

// IAM-1-28 anti-leak: unauthorized caller on a protected binding → PERMISSION_DENIED
// (grant-authority runs BEFORE the deletion_protection pre-check; protection-state
// must not leak to a non-owner). Exact mirror of the Delete anti-leak invariant.
func TestAccessBinding_Revoke_Protected_Unauthorized_NoLeak(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_rev_leak", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true) // protected

	rs := &scopedFGA{allow: map[string]bool{}} // no admin → no grant-authority
	uc := NewRevokeAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(rs, nil)

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

// IAM-1-28 positive: Revoke on an unprotected binding → Operation; after done the
// row is RETAINED with status=REVOKED (soft), contrast with Delete=hard.
func TestAccessBinding_Revoke_Unprotected_SoftRevoke_OpDone(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_rev_ok", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, false) // unprotected

	uc := NewRevokeAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id)
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	// Soft: the fake binding is RETAINED and transitioned to REVOKED (not deleted).
	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.NotNil(t, repo.ab, "soft-revoke retains the row (contrast with Delete=hard)")
	assert.Equal(t, id, repo.ab.ID)
	assert.Equal(t, domain.AccessBindingStatusRevoked, repo.ab.Status)
	require.NotNil(t, repo.ab.RevokedAt, "revoked_at stamped")
	require.NotNil(t, repo.ab.RevokedByUserID, "revoked_by retained (audit)")
}
