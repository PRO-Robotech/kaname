// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// upsert_invite_grant_fga_integration_test.go — RC-2 + RC-5 integration
// (testcontainers Postgres), driving the real InternalUserService.UpsertFromIdentity
// use-case (operations LRO) against a real DB and probing the transactional
// outbox rows + DB state.
//
// Scenarios:
//   T-I3 — invite-activation co-commits the member hierarchy tuple
//          (account:<A>#account@iam_user:<id>) IN THE SAME Step-1 writer-tx as the
//          iam.user.updated audit-event + the ActivateInvite UPDATE (ban #10 atomic
//          co-commit through w.EmitFGARelationWrite, NOT post-commit relationhook).
//   T-I5 — an invitee that owns ZERO accounts gets a personal default Account +
//          "default" Project bootstrapped (RC-5 gate), WITHOUT a 2nd InsertActive
//          (the invitee user-row already exists → a re-INSERT would 23505 on
//          UNIQUE(external_id)); the RC-2 inviter member-tuple co-exists.
//   T-E4(int) — re-activation is idempotent: still exactly ONE owned personal
//          account, no duplicate member-tuple intent shape mismatch.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// seedInviterAndPendingInvite creates an ACTIVE inviter + its owned account, then
// a PENDING-invite-row for inviteeEmail under that account (the invitee user-row
// already exists; it owns no account). Returns inviter uid, account id, invitee
// pending user-id.
func seedInviterAndPendingInvite(t *testing.T, ctx context.Context, repo *kachopg.Repository, suffix, inviteeEmail string) (domain.UserID, domain.AccountID, domain.UserID) {
	t.Helper()
	inviterID, accID := bootstrapAdmin(t, ctx, repo, suffix)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inviteeID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, _, err = w.UsersW().InsertPending(ctx, domain.User{
		ID:           inviteeID,
		AccountID:    accID,
		Email:        domain.Email(inviteeEmail),
		DisplayName:  domain.DisplayName("Invitee"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    inviterID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return inviterID, accID, inviteeID
}

func fgaOutboxCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user, relation, object string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.fga_outbox
		 WHERE event_type = 'fga.tuple.write'
		   AND payload->>'user' = $1
		   AND payload->>'relation' = $2
		   AND payload->>'object' = $3`, user, relation, object).Scan(&n))
	return n
}

func auditUpdatedCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user.updated'
		   AND event_payload->>'resource_id' = $1`, userID).Scan(&n))
	return n
}

func ownedAccountCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerUserID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.accounts WHERE owner_user_id = $1`, ownerUserID).Scan(&n))
	return n
}

// activeRowCountByExternalID — number of ACTIVE user-rows for an external_id
// (must stay 1 — a 2nd InsertActive would 23505 on UNIQUE(external_id)).
func activeRowCountByExternalID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.users WHERE external_id = $1 AND invite_status = 'ACTIVE'`, ext).Scan(&n))
	return n
}

// ── T-I3 — RC-2 member-tuple co-committed with audit in Step-1 writer-tx ──────
func TestUpsertInviteGrant_TI3_RC2_MemberTupleCoCommitWithAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const ext = "ext_INV_ti3"
	const email = "invitee-ti3@example.com"
	_, accID, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti3", email)

	uc := userapp.NewUpsertFromIdentityUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(ext),
		Email:       domain.Email(email),
		DisplayName: domain.DisplayName("Invitee Real"),
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "UpsertFromIdentity must succeed: %v", done.Error)

	// PENDING → ACTIVE, id preserved.
	var status, gotExt string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status, external_id FROM kacho_iam.users WHERE id = $1`, string(inviteeID)).
		Scan(&status, &gotExt))
	assert.Equal(t, "ACTIVE", status, "invite activated")
	assert.Equal(t, ext, gotExt, "external_id set on the SAME row (id preserved)")

	// iam.user.updated audit-event present for the activated row.
	assert.GreaterOrEqual(t, auditUpdatedCount(t, ctx, pool, string(inviteeID)), 1,
		"iam.user.updated audit-event emitted on activation")

	// RC-2: member hierarchy-tuple intent co-committed (account:<A>#account@iam_user:<id>).
	memberTuples := fgaOutboxCount(t, ctx, pool,
		"account:"+string(accID), "account", "iam_user:"+string(inviteeID))
	assert.Equal(t, 1, memberTuples,
		"exactly one RC-2 member hierarchy-tuple intent must be co-committed with activation")
}

// T-I3 atomicity — a rolled-back Step-1 tx leaves NEITHER the audit row NOR the
// fga member-tuple intent. We assert the co-commit invariant directly on the
// writer-tx (the only way both rows can appear/disappear atomically is via the
// SAME w.EmitFGARelationWrite + w.EmitAuditEvent on one pgx.Tx).
func TestUpsertInviteGrant_TI3_RC2_RollbackDiscardsBoth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	const email = "invitee-ti3rb@example.com"
	_, accID, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti3rb", email)

	// Replicate the Step-1 writer-tx shape, then ROLLBACK: activate + audit + fga
	// member-tuple, all on one tx, abandoned.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.UsersW().ActivateInvite(ctx, inviteeID,
		domain.ExternalSubject("ext_INV_ti3rb"), domain.DisplayName("Rolled Back"))
	require.NoError(t, err)
	memberTuple := fmt.Sprintf("iam_user:%s", inviteeID)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
		User: "account:" + string(accID), Relation: "account", Object: memberTuple,
	}}))
	require.NoError(t, w.Rollback(ctx))

	// Neither outbox row visible (atomic discard).
	assert.Equal(t, 0, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accID), "account", memberTuple),
		"rolled-back fga member-tuple intent must not be visible")
	// Still PENDING.
	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM kacho_iam.users WHERE id = $1`, string(inviteeID)).Scan(&status))
	assert.Equal(t, "PENDING", status, "rolled-back activation leaves row PENDING")
}

// ── T-I5 — RC-5 bootstrap fires for invitee owning zero accounts, no 2nd InsertActive ──
func TestUpsertInviteGrant_TI5_RC5_BootstrapFiresOwnsZero_NoSecondInsertActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const ext = "ext_INV_ti5"
	const email = "invitee-ti5@example.com"
	_, accA, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti5", email)

	// Pre-condition: invitee owns ZERO accounts.
	require.Equal(t, 0, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"pre-state: invitee owns no account")

	uc := userapp.NewUpsertFromIdentityUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(ext),
		Email:       domain.Email(email),
		DisplayName: domain.DisplayName("Invitee Real"),
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "UpsertFromIdentity must succeed (no 23505 from a 2nd InsertActive): %v", done.Error)

	// ActivateInvite ran, id preserved, exactly one ACTIVE row (no 2nd InsertActive).
	assert.Equal(t, 1, activeRowCountByExternalID(t, ctx, pool, ext),
		"exactly one ACTIVE user-row (no duplicate InsertActive → no 23505)")
	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM kacho_iam.users WHERE id = $1`, string(inviteeID)).Scan(&status))
	assert.Equal(t, "ACTIVE", status, "invitee activated on the existing row")

	// RC-5: bootstrap fired → exactly ONE personal account owned by the invitee.
	assert.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"RC-5: invitee now owns exactly one personal account")

	// the personal account has a "default" project.
	var personalAcc string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.accounts WHERE owner_user_id = $1`, string(inviteeID)).Scan(&personalAcc))
	var defaultPrjCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.projects WHERE account_id = $1 AND name = 'default'`, personalAcc).
		Scan(&defaultPrjCount))
	assert.Equal(t, 1, defaultPrjCount, `RC-5: personal account has a "default" project`)

	// 2 self-admin AccessBindings (account + project) for the invitee on personal scope.
	var abCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings ab
		   WHERE ab.subject_id = $1 AND ab.revoked_at IS NULL
		     AND ( (ab.resource_type='account' AND ab.resource_id=$2)
			OR (ab.resource_type='project' AND ab.resource_id IN
			      (SELECT id FROM kacho_iam.projects WHERE account_id=$2)) )`,
		string(inviteeID), personalAcc).Scan(&abCount))
	assert.Equal(t, 2, abCount, "RC-5: 2 self-admin AccessBindings on personal scope")

	// bootstrapTuples intents present for the personal graph (owner + member hierarchy).
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"user:"+string(inviteeID), "owner", "account:"+personalAcc),
		"RC-5: owner grant on personal account")
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"account:"+personalAcc, "account", "iam_user:"+string(inviteeID)),
		"RC-5: user→personal-account hierarchy")

	// RC-2 inviter member-tuple ALSO emitted (membership in inviter's account A).
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accA), "account", "iam_user:"+string(inviteeID)),
		"RC-2: inviter member-tuple co-exists with RC-5 personal bootstrap")

	// metadata.created stays false (existing activated id reused, not a new identity).
	meta, err := operations.MetadataFor[*iamv1.UpsertFromIdentityMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(inviteeID), meta.GetUserId(), "metadata.user_id = activated id")
	assert.False(t, meta.GetCreated(), "metadata.created=false (user-row reused)")
}

// ── T-E4 (integration) — idempotent re-activation: still exactly one owned account ──
func TestUpsertInviteGrant_TE4_RC5_ReActivateIdempotent_SingleOwnedAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const ext = "ext_INV_te4"
	const email = "invitee-te4@example.com"
	_, accA, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "te4", email)

	uc := userapp.NewUpsertFromIdentityUseCase(repo, opsRepo)
	in := userapp.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(ext),
		Email:       domain.Email(email),
		DisplayName: domain.DisplayName("Invitee Real"),
	}

	// First activation.
	op1, err := uc.Execute(ctx, in)
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, op1.ID).Error)
	require.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"first activation → one owned account")

	// Re-activation (re-login). Already-ACTIVE → owns-zero == false → no 2nd bootstrap.
	op2, err := uc.Execute(ctx, in)
	require.NoError(t, err)
	done2 := awaitOp(t, ctx, opsRepo, op2.ID)
	require.Nil(t, done2.Error)

	assert.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"RC-5 idempotent: still exactly one owned personal account after re-activation")
	assert.Equal(t, 1, activeRowCountByExternalID(t, ctx, pool, ext),
		"still exactly one ACTIVE row")
	// member tuple in inviter account still present.
	assert.GreaterOrEqual(t, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accA), "account", "iam_user:"+string(inviteeID)), 1,
		"inviter member-tuple intent present (at-least-once, idempotent drain)")

	meta2, err := operations.MetadataFor[*iamv1.UpsertFromIdentityMetadata](done2)
	require.NoError(t, err)
	assert.Equal(t, string(inviteeID), meta2.GetUserId())
	assert.False(t, meta2.GetCreated())
}
