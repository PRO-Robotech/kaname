// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// audit_emit_test.go — unit test asserting the AccessBinding grant/revoke
// use-cases emit a durable audit_outbox compliance event inside the writer-tx.
//
// P0 compliance: "who granted which role to whom on which resource, and when"
// must be durably recorded. This test wires the in-memory fake repo (no
// Postgres) and asserts:
//
//  1. Create emits exactly one audit event `iam.access_binding.granted` whose
//     actor = granted_by, subject/resource/role_id/binding_id match the binding.
//  2. Delete emits exactly one audit event `iam.access_binding.revoked`.
//
// The audit emit is part of the same Writer-tx as the binding mutation (atomic
// emit-in-tx is enforced at the repo/integration level); here we assert the
// use-case actually calls EmitAuditEvent with the right payload.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

func TestAuditEmit_CreateEmitsGranted_DeleteEmitsRevoked(t *testing.T) {
	const (
		roleID    = "rol_admin_test_aud"
		roleName  = "admin"
		subjectID = "usr_audit_subject"
		resID     = "acc_audit_target"
		ownerID   = "usr_audit_owner"
		accountID = "acc_audit_account"
	)

	perms := domain.Permissions{"iam.access_bindings.admin"}
	repo := newABFakeRepo(ownerID, accountID, resID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()

	ctx := newOwnerContext(ownerID)

	// ── Create ──────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	binding := domain.AccessBinding{
		SubjectType:     "user",
		SubjectID:       domain.SubjectID(subjectID),
		RoleID:          domain.RoleID(roleID),
		ResourceType:    "account",
		ResourceID:      resID,
		GrantedByUserID: domain.UserID(ownerID),
	}
	_, err := createUC.Execute(ctx, binding)
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	grantEvents := repo.drainAuditEvents()
	require.Len(t, grantEvents, 1, "Create must emit exactly one audit_outbox compliance event")
	g := grantEvents[0]
	assert.Equal(t, ab_repo.AuditEventTypeGranted, g.EventType, "grant event_type")
	assert.Equal(t, ownerID, g.Actor, "actor = granted_by")
	assert.Equal(t, "user", g.SubjectType)
	assert.Equal(t, subjectID, g.SubjectID)
	assert.Equal(t, "account", g.ResourceType)
	assert.Equal(t, resID, g.ResourceID)
	assert.Equal(t, roleID, g.RoleID)
	assert.Equal(t, string(repo.lastInsertedID()), g.BindingID, "binding_id ties the event to the row")

	// ── Delete ──────────────────────────────────────────────────────────────
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	subjectCtx := newOwnerContext(subjectID)
	abID := repo.lastInsertedID()
	_, err = deleteUC.Execute(subjectCtx, abID)
	require.NoError(t, err)
	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2))

	revokeEvents := repo.drainAuditEvents()
	require.Len(t, revokeEvents, 1, "Delete must emit exactly one audit_outbox compliance event")
	r := revokeEvents[0]
	assert.Equal(t, ab_repo.AuditEventTypeRevoked, r.EventType, "revoke event_type")
	assert.Equal(t, "account", r.ResourceType)
	assert.Equal(t, resID, r.ResourceID)
	assert.Equal(t, roleID, r.RoleID)
	assert.Equal(t, string(abID), r.BindingID)
}
