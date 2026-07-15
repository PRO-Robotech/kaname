// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// create_subjects_test.go — unit tests for the multi-subject Create path:
// per-subject independent tuple-set + per-subject child rows + the legacy
// single = subjects[0] projection.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// TestCreate_E30_MultiSubject_IndependentTupleSets — a Create with two subjects
// (a user and a group) emits an INDEPENDENT tuple-set per subject and persists
// both subject child rows; the binding row keeps subjects[0] as the legacy single.
func TestCreate_E30_MultiSubject_IndependentTupleSets(t *testing.T) {
	const (
		roleID     = "rol_e30_test"
		roleName   = "viewer"
		userID     = "usr_e30_user"
		groupID    = "grp_e30_group"
		resourceID = "acc_e30_account"
		ownerID    = "usr_e30_owner"
		accountID  = "acc_e30_account"
	)
	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	ctx := newOwnerContext(ownerID)

	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	binding := domain.AccessBinding{
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   resourceID,
		Subjects: []domain.Subject{
			{Type: domain.SubjectTypeUser, ID: userID},
			{Type: domain.SubjectTypeGroup, ID: groupID},
		},
	}
	op, err := uc.Execute(ctx, binding)
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	written := repo.drainFGAWritten()
	// Per-subject role-relation tuple: one for the user, one for the group#member.
	assert.Contains(t, written, ab_repo.RelationTuple{User: "user:" + userID, Relation: "viewer", Object: "account:" + resourceID},
		"user subject must get its own role-relation tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{User: "group:" + groupID + "#member", Relation: "viewer", Object: "account:" + resourceID},
		"group subject must get its OWN independent role-relation tuple (E-30)")

	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	// Both subjects persisted in the child table.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	subs, err := rd.AccessBindings().ListSubjects(ctx, abID)
	require.NoError(t, err)
	require.Len(t, subs, 2, "both subjects persisted in access_binding_subjects")
}

// TestCreate_E34_LegacySingle_ProjectsToSubjects — a legacy single-subject Create
// (no Subjects[]) still persists a one-element subjects[] (reverse projection).
func TestCreate_E34_LegacySingle_ProjectsToSubjects(t *testing.T) {
	const (
		roleID     = "rol_e34_test"
		roleName   = "viewer"
		userID     = "usr_e34_user"
		resourceID = "acc_e34_account"
		ownerID    = "usr_e34_owner"
		accountID  = "acc_e34_account"
	)
	perms := domain.Permissions{"iam.access_bindings.get"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	ctx := newOwnerContext(ownerID)

	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	binding := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(userID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   resourceID,
	}
	op, err := uc.Execute(ctx, binding)
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	abID := repo.lastInsertedID()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	subs, err := rd.AccessBindings().ListSubjects(ctx, abID)
	require.NoError(t, err)
	require.Len(t, subs, 1, "legacy single subject projects to a one-element subjects[]")
	assert.Equal(t, domain.SubjectTypeUser, subs[0].Type)
	assert.Equal(t, domain.SubjectID(userID), subs[0].ID)
}

// TestCreate_E32b_GroupSubject_NoGrantAuthority_Denied — the group-amplification
// guard NEGATIVE branch (Q#4 / E-32b): an admin/editor-tier binding with a GROUP
// subject grants the role to every member, so it MUST be authored by a
// grant-authority holder on the scope. A caller who is NOT the owner AND holds no
// FGA admin on the scope is DENIED (PERMISSION_DENIED) before any tuple is emitted.
// (E-32a above only covers the subjects[]-conflict branch; this covers the
// amplification guard itself.)
func TestCreate_E32b_GroupSubject_NoGrantAuthority_Denied(t *testing.T) {
	const (
		roleID     = "rol_e32b_test"
		groupID    = "grp_e32b"
		resourceID = "acc_e32b_account"
		ownerID    = "usr_e32b_owner"
		accountID  = "acc_e32b_account"
	)
	// editor-tier role (write verb) granted to a GROUP — the amplifying case.
	perms := domain.Permissions{"iam.access_bindings.create"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, "editor", perms)
	opsRepo := newFakeOpsRepo()

	// Caller is a NON-owner, NON-admin authenticated principal; denyingFGA → no
	// delegated-admin path → requireGrantAuthority must deny.
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{ID: "usr_e32b_attacker", Type: "user"})

	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(&denyingFGA{}, nil)
	binding := domain.AccessBinding{
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   resourceID,
		Subjects:     []domain.Subject{{Type: domain.SubjectTypeGroup, ID: groupID}},
	}
	_, err := uc.Execute(ctx, binding)
	require.Error(t, err, "group-amplifying binding without grant-authority must be denied (E-32b)")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"no grant-authority on scope → PERMISSION_DENIED")

	// No FGA grant tuple may have been emitted (denied before doCreate).
	assert.Empty(t, repo.drainFGAWritten(), "no tuple emitted when the guard denies")
}

// TestCreate_E32_SubjectsConflict_Rejected — subjects[] set AND a legacy single
// that disagrees with subjects[0] → sync INVALID_ARGUMENT before any Operation.
func TestCreate_E32_SubjectsConflict_Rejected(t *testing.T) {
	const (
		roleID     = "rol_e32_test"
		resourceID = "acc_e32_account"
		ownerID    = "usr_e32_owner"
		accountID  = "acc_e32_account"
	)
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, "viewer", domain.Permissions{"iam.access_bindings.get"})
	opsRepo := newFakeOpsRepo()
	ctx := newOwnerContext(ownerID)

	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	binding := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser, // legacy single = usr_x
		SubjectID:    "usr_x",
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   resourceID,
		Subjects:     []domain.Subject{{Type: domain.SubjectTypeGroup, ID: "grp_other"}}, // disagrees
	}
	_, err := uc.Execute(ctx, binding)
	require.Error(t, err, "conflicting legacy single vs subjects[0] → INVALID_ARGUMENT")
}
