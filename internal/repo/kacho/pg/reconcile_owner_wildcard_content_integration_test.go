// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_owner_wildcard_content_integration_test.go — RBAC explicit-model 2026 /
// issue #224 (contract-blocker): the OWNER `*.*.*` role bound at a BOUNDED scope
// (ACCOUNT) MUST forward-materialize per-object CONTENT.
//
// Before the fix domain.dottedTypes dropped wildcard module/resource for ALL scopes,
// so the owner binding's ARM_ANCHOR selector projected to ZERO object types →
// 0 content tuples; owner content was held ONLY by the FGA derivation cascade. This
// blocks the contract phase (the cascade cannot be removed without losing owner
// access). After the fix the wildcard expands to the full materializable type set
// and the reconciler emits per-object v_* + tier on EVERY object inside the account.
//
// Coverage (acceptance D-8a / C-01b / D-3):
//   - backfill: a resource that EXISTS at owner-binding time → ReconcileBinding
//     materializes its content tuple.
//   - forward (C-01b): a resource created AFTER the owner-binding → ReconcileObject
//     (the RegisterResource event path, D-4) materializes its content tuple.
//   - scope-boundary (D-3): owner of account A is NOT materialized on objects of
//     account B (IsContainedIn narrows; the wildcard does not become a cluster anchor).
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
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// ownerBindingFor returns the ACTIVE owner-binding id for an account (created by the
// idempotent owner-binding backfill).
func ownerBindingFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) domain.AccessBindingID {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.access_bindings
		  WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		    AND status = 'ACTIVE' AND revoked_at IS NULL`,
		domain.OwnerRoleID, string(accID)).Scan(&id))
	return domain.AccessBindingID(id)
}

// Test224_OwnerWildcard_BackfillMaterializesContent — D-8a backfill: an object that
// already exists in the account when the owner-binding is reconciled gets a per-object
// content tuple. RED before #224 fix (0 content tuples), GREEN after.
func Test224_OwnerWildcard_BackfillMaterializesContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "o224bf")
	acc := seedAccount(t, ctx, repo, "acc-224-bf", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)

	// A vpc_network that EXISTS in the account before reconcile (backfill path).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "n224bf", "", string(acc.ID), nil, now)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBID))

	// The owner is now an explicit per-object admin on the network (D-8a true per-
	// object, NOT cascade): the content tuple is recorded in the emitted-tuple ledger.
	ownerUser := "user:" + string(owner)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "vpc_network:n224bf"),
		"owner must materialize per-object content tuple on an existing account resource (#224 D-8a)")
}

// Test224_OwnerWildcard_ForwardMaterializesContent — C-01b forward: a resource
// created AFTER the owner-binding (the RegisterResource → ReconcileObject path, D-4)
// gets its content tuple. RED before fix, GREEN after.
func Test224_OwnerWildcard_ForwardMaterializesContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "o224fwd")
	acc := seedAccount(t, ctx, repo, "acc-224-fwd", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)

	rec, _ := newReconciler(pool)
	// Owner-binding reconciled while the account is EMPTY (no content yet).
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBID))
	require.Equal(t, 0,
		countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i224late"),
		"no content tuple before the resource exists")

	// LATER a resource is created in the account (consumer RegisterResource lands a
	// mirror row, then drives the forward path).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "i224late", "", string(acc.ID), nil, now)
	require.NoError(t, rec.ReconcileObject(ctx, "compute.instance", "i224late"))

	ownerUser := "user:" + string(owner)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "compute_instance:i224late"),
		"owner must FORWARD-materialize content tuple on a resource created after the binding (#224 C-01b)")
}

// Test224_OwnerWildcard_ScopeBoundary — D-3: the owner of account A is NOT
// materialized on objects of account B. The wildcard expansion stays bounded to the
// binding's scope (IsContainedIn), it does NOT become a cluster-wide anchor.
func Test224_OwnerWildcard_ScopeBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "o224a")
	ownerB := mustSeedUser(t, ctx, pool, "o224b")
	accA := seedAccount(t, ctx, repo, "acc-224-aa", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-224-bb", ownerB)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)

	// A network that lives in account B.
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nB224", "", string(accB.ID), nil, now)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBIDA))

	// Owner A must NOT have any content tuple on account B's network (scope boundary).
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), "admin", "vpc_network:nB224"),
		"owner of account A must NOT materialize on account B's resource (#224 D-3 scope boundary)")
}

// Test224_OwnerWildcard_ForwardWithoutBootBackfill — review КФ-1: the forward path
// must NOT depend on the best-effort Go boot-backfill (BackfillOwnerBindings) having
// run. Migration 0038 seeds the owner role_rule_selectors row at `goose up`, so a
// fresh account's owner binding (created via the Account.Create flow, here emulated by
// inserting the binding directly) fast-path-matches a brand-new object WITHOUT ever
// calling BackfillOwnerBindings. RED if the owner selector row were only seeded by the
// boot-task; GREEN with the migration seed.
func Test224_OwnerWildcard_ForwardWithoutBootBackfill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "o224nbb")
	acc := seedAccount(t, ctx, repo, "acc-224-nbb", owner)

	// Owner binding inserted directly (the Account.Create co-commit), WITHOUT running
	// BackfillOwnerBindings — so the only source of the owner role_rule_selectors row
	// is migration 0038 (applied by setupTestDB's goose.Up).
	ownerBID := insertThinBindingScope(t, ctx, repo, owner, domain.OwnerRoleID,
		"account", string(acc.ID), domain.ScopeAccount)

	// A brand-new object registered in the account → forward path (ReconcileObject).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nNbb224", "", string(acc.ID), nil, now)
	require.NoError(t, rec224ReconcileObject(t, ctx, pool, "vpc.network", "nNbb224"))

	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, "user:"+string(owner), "admin", "vpc_network:nNbb224"),
		"owner forward path must work from the migration-seeded selector, not the boot-backfill (#224 КФ-1)")
}

// rec224ReconcileObject drives the forward fast-path (ReconcileObject) for the owner
// content tests.
func rec224ReconcileObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) error {
	t.Helper()
	rec, _ := newReconciler(pool)
	return rec.ReconcileObject(ctx, objType, objID)
}

// Test224_VerifyGate_OwnerContentForwardSmoke — КФ-4 verify-gate EXTENSION (item 2):
// a POSITIVE owner-content no-access-loss check. Drives the verify-gate forward-smoke
// against the OWNER binding (not a regular selector binding): a fresh resource in the
// account must materialize the owner's per-object content tuple BEFORE contract. This
// is the assertion the old gate could NOT make (КФ-БАГ-1 — owner content never
// materialized, and the active_members-derived Verify always passed it as 0-expected).
// RED before #224, GREEN after.
func Test224_VerifyGate_OwnerContentForwardSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "o224vg")
	acc := seedAccount(t, ctx, repo, "acc-224-vg", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)

	_, gate := newBackfill(pool)

	// Forward-smoke against the OWNER binding: a fresh vpc.network in the account must
	// get the owner's content tuple via the forward path (D-4). The owner rule is
	// ARM_ANCHOR(all) wildcard → no labels (empty Labels matches the anchor selector).
	fresh := ids.NewID("net")
	smoke, err := gate.ForwardSmoke(ctx, seed.ForwardSmokeSpec{
		ExpectBinding: ownerBID,
		ObjectType:    "vpc.network",
		ObjectID:      fresh,
		ParentAccount: string(acc.ID),
	})
	require.NoError(t, err)
	assert.True(t, smoke,
		"verify-gate forward-smoke on the OWNER binding must materialize owner content on a fresh resource (#224 КФ-4)")
}
