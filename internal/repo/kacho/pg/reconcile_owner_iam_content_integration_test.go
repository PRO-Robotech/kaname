// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_owner_iam_content_integration_test.go — rbac-contract-a-fix
// (forward-materialization of iam-NATIVE content under the owner `*.*` binding).
//
// Regression: the flat OpenFGA model (Contract-A) removed all `<rel> from account`
// ACCESS cascades on iam leaf types (iam_role / iam_group / iam_service_account /
// iam_user / iam_access_binding). The inert hierarchy parent-pointer tuple each iam
// Create still emitted (`account:<acc>#account@iam_role:<id>`) grants nobody anything
// under the flat model. So a Role/Group/SA/User created inside an account that already
// has an owner `*.*` binding got NO admin/viewer/v_* tuple → owner (and creator) gets
// 403 on GET right after Create. The 11 e2e suites (iam-role/group/user/sa/...) were red
// on exactly this `get-confirms → expected 403 to deeply equal 200` class.
//
// The forward fix (design-aligned, per-object materialization engine extended to iam
// content):
//   1. iam content Create emits a reconcile event (writer-tx co-commit, ban #10).
//   2. AllMaterializableTypes includes iam.role/group/serviceAccount/user/accessBinding.
//   3. iam-direct pg scans (iamDirectQuery / IAMDirectSelectorBindingsMatchingObject)
//      cover the new native tables, respecting account/project containment.
//
// Coverage:
//   (a) forward (C-01b): a Role/Group/SA/User created AFTER the owner-binding →
//       ReconcileObject materializes the owner's admin (+ v_* tier) tuple on the object.
//   (b) backfill: a native row existing at owner-binding-reconcile time → ReconcileBinding
//       materializes its content tuple.
//   (c) scope boundary: owner of account A is NOT materialized on account B's role.
//   (d) iam-direct scan returns the new iam content types within scope.
//
// RED before the fix (0 content tuples / scan returns nothing), GREEN after.
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedNativeRole inserts a custom (account-scoped) role row directly. Returns id.
func seedNativeRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	rid := ids.NewID(domain.PrefixRole)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, account_id, name, permissions, is_system)
		VALUES ($1, $2, $3, '["compute.instance.*.get"]'::jsonb, false)`,
		rid, string(acc), name)
	require.NoError(t, err, "seed native role")
	return rid
}

// seedNativeGroup inserts an account-scoped group row directly. Returns id.
func seedNativeGroup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	gid := ids.NewID(domain.PrefixGroup)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.groups (id, account_id, name)
		VALUES ($1, $2, $3)`, gid, string(acc), name)
	require.NoError(t, err, "seed native group")
	return gid
}

// seedNativeSA inserts an account-scoped service_account row directly. Returns id.
func seedNativeSA(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	sid := ids.NewID(domain.PrefixServiceAccount)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		VALUES ($1, $2, $3)`, sid, string(acc), name)
	require.NoError(t, err, "seed native service_account")
	return sid
}

// seedNativeUser inserts a user row in an account directly. Returns id.
func seedNativeUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, suffix string) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, string(acc), "ext-"+suffix+"-"+uid, "u-"+suffix+"@example.com", "U "+suffix)
	require.NoError(t, err, "seed native user")
	return uid
}

// TestOwnerIamContent_ForwardMaterializes — (a) C-01b forward: a Role/Group/SA/User
// created AFTER the owner-binding gets the owner's per-object admin tuple via
// ReconcileObject (the Create reconcile-event → drain → ReconcileObject path, here a
// direct ReconcileObject call). RED before the fix (iam-direct scan + materializable
// set + selector-match all excluded these types → 0 tuples), GREEN after.
func TestOwnerIamContent_ForwardMaterializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "oic-fwd")
	acc := seedAccount(t, ctx, repo, "acc-oic-fwd", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	rec, _ := newReconciler(pool)
	ownerUser := "user:" + string(owner)

	cases := []struct {
		name    string
		seedFn  func() string
		objType string
		fgaType string
	}{
		{"role", func() string { return seedNativeRole(t, ctx, pool, acc.ID, "fwdrole") }, "iam.role", "iam_role"},
		{"group", func() string { return seedNativeGroup(t, ctx, pool, acc.ID, "fwd-grp") }, "iam.group", "iam_group"},
		{"service_account", func() string { return seedNativeSA(t, ctx, pool, acc.ID, "fwd-sa") }, "iam.serviceAccount", "iam_service_account"},
		{"user", func() string { return seedNativeUser(t, ctx, pool, acc.ID, "fwdu") }, "iam.user", "iam_user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objID := tc.seedFn()
			require.NoError(t, rec.ReconcileObject(ctx, tc.objType, objID))
			assert.True(t,
				ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", tc.fgaType+":"+objID),
				"owner must FORWARD-materialize admin tuple on a %s created after the binding (C-01b)", tc.name)
		})
	}
}

// TestOwnerIamContent_BackfillMaterializes — (b) backfill: a native iam content row
// that EXISTS in the account when the owner-binding is reconciled gets a per-object
// content tuple. RED before the fix (iamDirectQuery did not scan roles/groups/etc).
func TestOwnerIamContent_BackfillMaterializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "oic-bf")
	acc := seedAccount(t, ctx, repo, "acc-oic-bf", owner)
	roleID := seedNativeRole(t, ctx, pool, acc.ID, "bfrole")
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBID))

	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, "user:"+string(owner), "admin", "iam_role:"+roleID),
		"owner must materialize admin tuple on an existing account role (backfill)")
}

// TestOwnerIamContent_ScopeBoundary — (c): owner of account A is NOT materialized on
// account B's role (containment narrows; the wildcard does not become cluster-wide).
func TestOwnerIamContent_ScopeBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "oic-a")
	ownerB := mustSeedUser(t, ctx, pool, "oic-b")
	accA := seedAccount(t, ctx, repo, "acc-oic-aa", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-oic-bb", ownerB)
	roleB := seedNativeRole(t, ctx, pool, accB.ID, "brole")
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)

	rec, _ := newReconciler(pool)
	// Forward path on account B's role MUST NOT grant owner A anything.
	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", roleB))
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), "admin", "iam_role:"+roleB),
		"owner of account A must NOT materialize on account B's role (scope boundary)")
}

// TestOwnerIamContent_AccessBindingForward — (a') C-01b for iam.accessBinding: a grant
// (access_binding) created in the owner's account materializes the owner's admin tuple
// on iam_access_binding:<id>, so the owner can GET the binding object.
func TestOwnerIamContent_AccessBindingForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "oic-ab")
	acc := seedAccount(t, ctx, repo, "acc-oic-ab", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)

	// A second (account-scoped) binding created in the account — emulate via the
	// thin-binding helper (subject = a member, scope = account A).
	member := mustSeedUser(t, ctx, pool, "oic-abm")
	roleID := seedNativeRole(t, ctx, pool, acc.ID, "abrole")
	grantBID := insertThinBindingScope(t, ctx, repo, member, domain.RoleID(roleID),
		"account", string(acc.ID), domain.ScopeAccount)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "iam.accessBinding", string(grantBID)))

	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, "user:"+string(owner), "admin", "iam_access_binding:"+string(grantBID)),
		"owner must FORWARD-materialize admin tuple on an access_binding created in the account (so GET works)")
}
