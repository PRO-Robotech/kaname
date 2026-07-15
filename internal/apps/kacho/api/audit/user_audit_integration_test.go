// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package audit_test

// user_audit_integration_test.go — User audit slice.
// UpsertFromIdentity insert-branch → iam.user.created;
// activate-invite update-branch → iam.user.updated; Delete → iam.user.deleted.
//
// UpsertFromIdentity is the InternalUserService bootstrap/provision path (Kratos
// hook + admin-tooling). When no caller principal is present (Kratos provision)
// the actor is the system/bootstrap identity — recorded, never fabricated.
// Delete runs through the public UserService.Delete (self-delete).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestUserAudit_5_2_14_UpsertInsertEmitsCreated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// No caller principal → Kratos-provision bootstrap path. actor = system/bootstrap.
	bootstrapCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kacho-iam-bootstrap"})

	uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
	_, err := uc.Execute(bootstrapCtx, user.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject("ext-sub-5214-insert"),
		Email:       domain.Email("u-5214-insert@example.com"),
		DisplayName: domain.DisplayName("Upsert Insert"),
	})
	require.NoError(t, err)
	awaitWorkers(t)

	usrID := singleID(t, ctx, env, `SELECT id FROM kacho_iam.users WHERE external_id = $1 AND email = $2`,
		"ext-sub-5214-insert", "u-5214-insert@example.com")

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.created", usrID)
	require.Equal(t, "user", r.payload["resource_type"])
	require.Equal(t, usrID, r.payload["resource_id"])
	require.Equal(t, "u-5214-insert@example.com", r.payload["email"])
	require.Equal(t, "Upsert Insert", r.payload["display_name"])
	// Kratos-provision has no user principal → IsAnonymous(bootstrap)=true →
	// PrincipalUserID="" → the use-case records the non-fabricated system
	// identity "system" (never an invented user id). 5.2-14.
	require.Equal(t, "system", r.payload["actor"],
		"Kratos-provision actor is the system identity, never fabricated")
	require.Regexp(t, evtIDFormat, r.id)
}

func TestUserAudit_5_2_14_UpsertActivateEmitsUpdated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed a PENDING invite row by email (no external_id yet).
	owner, accID := seedUserAccount(t, ctx, env.pool, "usr14upd")
	_ = owner
	pendingID := domain.UserID("usr0000000000005214pp")
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, $4, 'PENDING')`,
		string(pendingID), string(accID), "u-5214-activate@example.com", "Pending Invitee")
	require.NoError(t, err)

	bootstrapCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kacho-iam-bootstrap"})

	uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
	_, err = uc.Execute(bootstrapCtx, user.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject("ext-sub-5214-activate"),
		Email:       domain.Email("u-5214-activate@example.com"),
		DisplayName: domain.DisplayName("Now Active"),
	})
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.updated", string(pendingID))
	require.Equal(t, string(pendingID), r.payload["resource_id"])
	require.Equal(t, "system", r.payload["actor"])
	require.Regexp(t, evtIDFormat, r.id)
}

func TestUserAudit_5_2_14_DeleteEmitsDeleted(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// A standalone user (owns no account) can self-delete.
	owner, accID := seedUserAccount(t, ctx, env.pool, "usr14del")
	_ = owner
	target := seedExtraUser(t, ctx, env.pool, accID, "del14")

	uc := user.NewDeleteUserUseCase(env.repo, env.opsRepo)
	// self-delete: principal == target.
	_, err := uc.Execute(withPrincipal(target), target)
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.deleted", string(target))
	require.Equal(t, string(target), r.payload["resource_id"])
	require.Equal(t, string(target), r.payload["actor"])
}
