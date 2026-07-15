// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// delete_w1_6_test.go — Delete uses requireGrantAuthority (mirror Create's
// authority rule — admin on resource can both grant and revoke). A self-only
// IsSelf check would reject legitimate admin-revokes (the account/project
// admin who granted a binding to another user could not revoke it).
package access_binding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Project-admin (owner) can revoke a binding for ANY subject on a
// resource they own.
func TestAccessBinding_Delete_OwnerCanRevokeAnyBindingOnOwnResource(t *testing.T) {
	const (
		ownerID   = "usr_acct_owner"
		accountID = "acc_test_account"
		projectID = "prj_test_project"
		roleID    = "rol_viewer_test_001"
		roleName  = "kacho.view"
		subjectID = "usr_strang_subject"
	)

	repo := newABFakeRepo(ownerID, accountID, projectID, roleID, roleName, nil)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctxOwner := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   projectID,
	}
	_, err := createUC.Execute(ctxOwner, binding)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	// owner (NOT the subject) attempts delete — must succeed
	// via requireGrantAuthority (was 403 pre-fix because of IsSelf-only).
	_, err = deleteUC.Execute(ctxOwner, abID)
	if err != nil {
		t.Fatalf("account-owner deleting stranger's binding on own project must succeed, got %v", err)
	}
}

// Stranger (neither owner nor subject nor FGA admin) is denied.
func TestAccessBinding_Delete_StrangerDenied(t *testing.T) {
	const (
		ownerID   = "usr_acct_owner"
		accountID = "acc_test_account"
		projectID = "prj_test_project"
		roleID    = "rol_viewer_test_001"
		roleName  = "kacho.view"
		subjectID = "usr_strang_subject"
	)

	repo := newABFakeRepo(ownerID, accountID, projectID, roleID, roleName, nil)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctxOwner := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   projectID,
	}
	_, err := createUC.Execute(ctxOwner, binding)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	// Outsider attempts delete: not owner, not subject, no FGA admin.
	// Use a recordingFGA but for outsider — actually our fake recordingFGA
	// always returns true; so substitute a denying FGA. The simplest is to
	// build a new use-case with a denying FGA hook for the authority check.
	denyingFGA := &denyingFGA{}
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(denyingFGA, nil)

	ctxStranger := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_random_outsider"})

	_, err = deleteUC.Execute(ctxStranger, abID)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stranger Delete must 403, got %v", err)
	}
}

// Self-binding (subject == principal) still works because owner path
// applies (when subject equals owner) — or via FGA admin path. Regression
// test that self-deleting hasn't broken.
func TestAccessBinding_Delete_SubjectIsOwner_Allowed(t *testing.T) {
	const (
		ownerID   = "usr_owner_and_subject"
		accountID = "acc_test_account"
		projectID = "prj_test_project"
		roleID    = "rol_viewer_test_001"
		roleName  = "kacho.view"
	)
	// owner of the account IS the subject.
	repo := newABFakeRepo(ownerID, accountID, projectID, roleID, roleName, nil)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctxOwner := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(ownerID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   projectID,
	}
	_, err := createUC.Execute(ctxOwner, binding)
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	abID := repo.lastInsertedID()
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	_, err = deleteUC.Execute(ctxOwner, abID)
	if err != nil {
		t.Fatalf("owner deleting own binding must succeed, got %v", err)
	}
}

// denyingFGA — Check always returns false (no admin), Write/Delete no-op.
type denyingFGA struct{ recordingFGA }

func (*denyingFGA) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
