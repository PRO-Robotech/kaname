// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// bootstrap_owner_mat_integration_test.go — rbac-contract-a-flat-fallout
// (signup/bootstrap parity with Account.Create owner-path under the FLAT model).
//
// ROOT prod-hole: bootstrapPersonalResources (the live signup / Kratos-provision
// path AND the activated-invitee owns-zero-accounts path) was OUT OF SYNC with the
// Account.Create owner-path:
//   - it created the account-scoped self-binding with the ADMIN role, not the OWNER
//     role (so ownerBindingFor / the owner `*.*` forward-mat engine never saw it);
//   - it emitted only the hard-coded bootstrapTuples (tier owner/admin@account +
//     hierarchy pointers) — ZERO per-object content tuples;
//   - it NEVER called ReconcileBinding / emitted a reconcile event.
//
// Under the flat OpenFGA model the hierarchy parent-pointers grant NO access
// (`<rel> from account` cascade removed), so the bootstrap user got 403 on the
// content of their OWN account: their project, their access_bindings, their
// iam-native content, cross-service content. This is the ~90% root of the flat
// 403 fallout (diagnosis classes 1/2/4/5/6/9).
//
// The fix makes bootstrap mirror Account.Create doCreate: create an OWNER-binding
// (OwnerRoleID, scope=ACCOUNT, deletion_protection, subjects, ledger) and call
// ReconcileBinding(ownerBindingID) post-commit — reusing the proven owner
// forward-mat engine (the `*.*` ARM_ANCHOR over the account's content +
// scope-self verbs on account:<A>). Plus a SECOND prod-hole (diagnosis class 3,
// D-4 — not reconstructible by the reconciler): the iam_user self-tuple
// `iam_user:<U> # subject @ user:<U>` (model: `iam_user.viewer = subject or
// editor`) must be EMITTED at user bootstrap so the user can GET themselves.
//
// RED before the fix (admin-binding, no owner-binding row, no content tuples, no
// self-tuple), GREEN after.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// bootstrapNewIdentity drives the REAL UpsertFromIdentity use-case for a
// genuinely-new identity (no PENDING, no ACTIVE) wired with the reconciler, then
// returns the bootstrapped user-id + personal account-id.
func bootstrapNewIdentity(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kachopg.Repository, ext, email string) (domain.UserID, domain.AccountID) {
	t.Helper()
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec, _ := newReconciler(pool)
	uc := userapp.NewUpsertFromIdentityUseCase(repo, opsRepo).
		WithReconciler(rec)
	op, err := uc.Execute(ctx, userapp.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(ext),
		Email:       domain.Email(email),
		DisplayName: domain.DisplayName("Bootstrap User"),
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "UpsertFromIdentity bootstrap must succeed: %v", done.Error)

	var uid, accID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.users WHERE external_id = $1 AND invite_status='ACTIVE'`, ext).Scan(&uid))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.accounts WHERE owner_user_id = $1`, uid).Scan(&accID))
	return domain.UserID(uid), domain.AccountID(accID)
}

// TestBootstrapOwnerMat_AccountIsOwnerBinding — the bootstrap account-scoped
// self-binding MUST be an OWNER-role binding (parity with Account.Create), not the
// admin-role binding. RED before the fix (admin role id), GREEN after.
func TestBootstrapOwnerMat_AccountIsOwnerBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid, accID := bootstrapNewIdentity(t, ctx, pool, repo, "ext_BOOT_owner", "boot-owner@example.com")

	// The account-scoped binding for the bootstrap user must carry OwnerRoleID,
	// scope=ACCOUNT, deletion_protection=true (so ownerBindingFor resolves it and
	// the owner forward-mat engine drives it).
	var roleID string
	var dp bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT role_id, deletion_protection
		  FROM kacho_iam.access_bindings
		 WHERE subject_id = $1 AND resource_type = 'account' AND resource_id = $2
		   AND revoked_at IS NULL`,
		string(uid), string(accID)).Scan(&roleID, &dp))
	assert.Equal(t, domain.OwnerRoleID, roleID,
		"bootstrap account binding must be the OWNER role (not admin) — drives owner forward-mat")
	assert.True(t, dp, "bootstrap owner-binding must be deletion-protected (parity with Account.Create)")

	// ownerBindingFor must now resolve it (it filters on OwnerRoleID).
	ownerBID := ownerBindingFor(t, ctx, pool, accID)
	assert.NotEmpty(t, ownerBID, "ownerBindingFor must resolve the bootstrap owner-binding")
}

// TestBootstrapOwnerMat_ProjectContentMaterialized — the bootstrap user's "default"
// project (iam-native content of their account, created in the SAME bootstrap flow)
// must FORWARD-materialize the owner's per-object content tuple, so a Get on the
// project authorizes. RED before the fix (no owner-binding + no reconcile → 0
// content tuples), GREEN after.
func TestBootstrapOwnerMat_ProjectContentMaterialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid, accID := bootstrapNewIdentity(t, ctx, pool, repo, "ext_BOOT_prj", "boot-prj@example.com")
	ownerBID := ownerBindingFor(t, ctx, pool, accID)

	var prjID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.projects WHERE account_id = $1 AND name = 'default'`,
		string(accID)).Scan(&prjID))

	// iam.project content collapses to the bare `project:<id>` FGA object
	// (authzmap.FGAObjectType "iam.project" → "project"); the owner `*.*` materializes
	// the admin tier + v_* there.
	ownerUser := "user:" + string(uid)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "project:"+prjID),
		"bootstrap owner must FORWARD-materialize admin on their default project (flat-model per-object)")
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "v_get", "project:"+prjID),
		"bootstrap owner must FORWARD-materialize v_get on their default project (verb-bearing)")
}

// TestBootstrapOwnerMat_OwnAccessBindingMaterialized — the bootstrap user's OWN
// owner-binding object (iam.accessBinding content of their account) must be
// per-object materialized so a Get on the binding authorizes (diagnosis class 2).
func TestBootstrapOwnerMat_OwnAccessBindingMaterialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid, accID := bootstrapNewIdentity(t, ctx, pool, repo, "ext_BOOT_ab", "boot-ab@example.com")
	ownerBID := ownerBindingFor(t, ctx, pool, accID)
	ownerUser := "user:" + string(uid)

	// The project-scoped self-binding row created in bootstrap is iam.accessBinding
	// content of the account; the owner `*.*` ARM_ANCHOR over iam.accessBinding must
	// materialize admin on it.
	var prjBID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM kacho_iam.access_bindings
		 WHERE subject_id = $1 AND resource_type = 'project' AND revoked_at IS NULL`,
		string(uid)).Scan(&prjBID))

	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_access_binding:"+prjBID),
		"bootstrap owner must materialize admin on the project-scoped access_binding object (class 2)")
}

// TestBootstrapOwnerMat_CrossServiceContentForward — a vpc_network created in the
// bootstrap user's account AFTER bootstrap (the C-01b forward path, e.g. via the
// vpc→iam RegisterResource edge → ReconcileObject) materializes the owner's
// per-object editor/v_* tuple, so the bootstrap user has access on cross-service
// content of their account (diagnosis class 5, label-revoke-vpc). RED before the
// fix (no owner-binding → forward path finds nothing), GREEN after.
func TestBootstrapOwnerMat_CrossServiceContentForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid, accID := bootstrapNewIdentity(t, ctx, pool, repo, "ext_BOOT_vpc", "boot-vpc@example.com")
	ownerBID := ownerBindingFor(t, ctx, pool, accID)
	ownerUser := "user:" + string(uid)

	// A vpc_network lands in the account mirror (RegisterResource) AFTER bootstrap.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nBootVpc", "", string(accID), nil, time.Now())
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nBootVpc"))

	// The owner must hold a per-object verb tuple on the network (v_get etc.) — the
	// forward path picked it up because the bootstrap owner-binding now exists.
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "v_get", "vpc_network:nBootVpc"),
		"bootstrap owner must forward-materialize v_get on a cross-service network in their account (class 5)")
}

// TestBootstrapOwnerMat_SelfUserTupleEmitted — the bootstrap user must be able to
// GET themselves: the flat iam_user model is `viewer: subject or editor`, so an
// explicit self-tuple `iam_user:<U> # subject @ user:<U>` must be emitted at
// bootstrap (D-4 class — NOT reconstructible by the reconciler). RED before the fix
// (no such tuple), GREEN after.
func TestBootstrapOwnerMat_SelfUserTupleEmitted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid, _ := bootstrapNewIdentity(t, ctx, pool, repo, "ext_BOOT_self", "boot-self@example.com")

	// The self subject-tuple intent must be co-committed to fga_outbox in the
	// bootstrap writer-tx.
	selfTuples := fgaOutboxCount(t, ctx, pool,
		"user:"+string(uid), "subject", "iam_user:"+string(uid))
	assert.Equal(t, 1, selfTuples,
		"bootstrap must emit the iam_user self-tuple (iam_user:<U>#subject@user:<U>) for get-self")
}
