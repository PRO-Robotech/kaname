// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// get_error_mapping_test.go — RED→GREEN regression lock for the audit r5
// finding: Update/Delete collapsed EVERY error from AccessBindings().Get to
// PermissionDenied, though the comment ("Existence-leak parity ... a
// non-existent binding → PermissionDenied") only justifies that mapping for a
// genuinely non-existent binding (iamerr.ErrNotFound). A transient Reader
// failure (statement-timeout, conn reset — surfaced here as ErrUnavailable /
// ErrInternal) was mis-mapped to the terminal, non-retriable PERMISSION_DENIED
// instead of a retriable code, so a well-behaved client would never retry a
// transient outage.
//
// Fix: only errors.Is(err, iamerr.ErrNotFound) maps to PermissionDenied
// (existence-hiding, intentional); every other error goes through
// shared.MapRepoErr like the Reader-acquisition error just above it.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Well-formed AccessBinding ids (prefix "acb" + domain.ShortIDLen==20 total)
// that do not correspond to any seeded binding, used to exercise the
// Get-not-found / Get-transient-error branches without tripping the sync
// malformed-id precheck (shared.ValidateResourceID) before reaching the Get.
const (
	nonexistentABID1 domain.AccessBindingID = "acb0000000000000abc1"
	nonexistentABID2 domain.AccessBindingID = "acb0000000000000abc2"
	nonexistentABID3 domain.AccessBindingID = "acb0000000000000abc3"
	nonexistentABID4 domain.AccessBindingID = "acb0000000000000abc4"
)

// ── Update ──────────────────────────────────────────────────────────────────

// Not-found stays PermissionDenied (existence-hiding is intentional).
func TestAccessBinding_Update_GetNotFound_MapsToPermissionDenied(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_upd_nf", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	// No binding seeded ⇒ fakeABRdr.Get returns iamerr.ErrNotFound.
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID1,
		[]string{"labels"}, false, domain.Labels{"stage": "prod"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"non-existent binding must still 403 (existence-leak protection)")
}

// A transient (non-not-found) Reader failure on the existence-check Get must
// map to a retriable code (via shared.MapRepoErr), NOT the terminal
// PermissionDenied — a client must be able to tell "retry me" from "you are
// forbidden, forever".
func TestAccessBinding_Update_GetTransientError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_upd_tr", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrUnavailable, "access_bindings: statement timeout")
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID2,
		[]string{"labels"}, false, domain.Labels{"stage": "prod"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"a transient Reader.Get failure must map to a retriable code, not PermissionDenied")
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

// ── Delete ──────────────────────────────────────────────────────────────────

func TestAccessBinding_Delete_GetNotFound_MapsToPermissionDenied(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_del_nf", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID3)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"non-existent binding must still 403 (existence-leak protection)")
}

func TestAccessBinding_Delete_GetTransientError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_del_tr", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrInternal, "access_bindings: conn reset")
	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID4)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err),
		"a transient Reader.Get failure must map to a retriable/internal code, not PermissionDenied")
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}
