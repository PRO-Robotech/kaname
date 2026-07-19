// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_materialization_matrix_integration_test.go — the per-verb / per-object
// MATERIALIZATION MATRIX regression, guarding two owner-tuple defects and the class
// they belong to (testcontainers Postgres 16; asserts on the emitted-tuple ledger,
// the same observable the fga_outbox drainer applies to OpenFGA).
//
// The matrix pins, for the two canonical creator/owner subjects, the FULL per-object
// relation set the reconciler must materialize:
//
//   (1) `edit`@PROJECT creator — a project editor's freshly-created object must carry
//       the COMPLETE object-CRUD verb set {v_get, v_list, v_update, v_delete} + the
//       editor tier. BUG #1: migration 0040 extended the edit roles from ["update"] to
//       ["get","list","update"] (read verbs) but omitted `delete`, so the reconciler —
//       which materialises EXACTLY the role's authored verbs — never emitted v_delete →
//       every delete/cleanup of the creator's OWN resource 403s "lacks v_delete".
//       The editor tier must NOT escalate to admin (a project editor is not an admin).
//
//   (2) `owner`@ACCOUNT subject — an account owner must materialise per-object access on
//       the PROJECT object itself (iam.project, the direct child of the account) AND on
//       the iam-native content of the account (iam.serviceAccount), not only on the
//       vpc/compute content nested inside its projects (that leg was fixed by 8d44019).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestMatrix_EditProjectCreator_FullObjectCRUD (BUG #1) — a subject bound to the
// system `edit` role at PROJECT scope must materialise the FULL object-CRUD verb set
// on a project-nested resource: v_get + v_list + v_update + v_delete + the editor tier.
//
// RED before the fix: the edit role's verbs are ["get","list","update"] (migration
// 0040 added the read verbs but forgot delete), so ruleObjectTuples emits only
// v_get/v_list/v_update + editor — v_delete is MISSING → the creator 403s on delete
// of its own object. The editor tier must stay `editor` (not `admin`): the fix adds
// v_delete WITHOUT escalating the back-compat tier.
func TestMatrix_EditProjectCreator_FullObjectCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mx1o")
	editor := mustSeedUser(t, ctx, pool, "mx1e") // the project-editor creator
	acc := seedAccount(t, ctx, repo, "acc-mx1", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-mx1")

	// Editor bound to the SYSTEM `edit` role at PROJECT scope.
	bID := insertThinBindingScope(t, ctx, repo, editor, systemRoleID("edit"),
		"project", string(prj.ID), domain.ScopeProject)

	// A vpc.network registered under the project (the creator's own resource).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nMX1", string(prj.ID), "", nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nMX1"))

	u := "user:" + string(editor)
	obj := "vpc_network:nMX1"
	// Read verbs + update materialise today (migration 0040) — the baseline.
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_get", obj), "editor must have v_get")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_list", obj), "editor must have v_list")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", obj), "editor must have v_update")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "editor", obj), "editor must carry the editor tier")
	// BUG #1: v_delete is co-materialised with v_update (create.go:435 invariant) — a
	// CRUD editor deletes what it edits. RED before the fix.
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_delete", obj),
		"BUG #1: edit@project creator must materialise v_delete on its own resource "+
			"(co-materialised with v_update)")
	// No over-grant: an editor must NOT be materialised at the admin tier.
	assert.False(t, ledgerHasTuple(t, ctx, pool, bID, u, "admin", obj),
		"editor tier must not escalate to admin")
}

// TestMatrix_EditTier_NoDeleteOnHierarchyScope (BUG #1 anti-over-grant lock) — the
// v_update⟹v_delete co-materialization is LEAF-only: an edit-tier grant must gain
// v_delete on leaf content (a vpc.network) but must NOT gain v_delete on the
// hierarchy scope objects project/account (ProjectService/AccountService.Delete gate
// v_delete on the scope — an editor is not an owner). Guards a future regression that
// naively adds `delete` to the edit role verbs and lets a project-editor delete the
// project itself.
func TestMatrix_EditTier_NoDeleteOnHierarchyScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mx5o")
	editor := mustSeedUser(t, ctx, pool, "mx5e")
	acc := seedAccount(t, ctx, repo, "acc-mx5", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-mx5")

	// ACCOUNT-scoped edit binding — its content covers the project object + leaf content.
	bID := insertThinBindingScope(t, ctx, repo, editor, systemRoleID("edit"),
		"account", string(acc.ID), domain.ScopeAccount)
	rec, _ := newReconciler(pool)

	// (a) the PROJECT object itself (hierarchy scope) — v_update yes, v_delete NO.
	require.NoError(t, rec.ReconcileObject(ctx, "iam.project", string(prj.ID)))
	u := "user:" + string(editor)
	pObj := "project:" + string(prj.ID)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", pObj), "editor updates the project")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_delete", pObj),
		"anti over-grant: edit-tier must NOT gain v_delete on the project (scope deletion is owner/admin)")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bID, u, "admin", pObj), "editor is not admin on the project")

	// (b) a LEAF resource in the project — v_update AND v_delete (co-materialized).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nMX5", string(prj.ID), "", nil, now)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nMX5"))
	nObj := "vpc_network:nMX5"
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", nObj), "editor updates leaf content")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_delete", nObj),
		"editor deletes leaf content it can update (v_update⟹v_delete, leaf)")
}

// TestMatrix_AccountOwner_MaterializesOnProjectObject (BUG #2a) — owner@account:A must
// materialise per-object access on the PROJECT object itself (iam.project → fga type
// `project`), the direct child of the account. RED before the fix: the account owner
// materialises on vpc/compute content nested in its projects (8d44019) but NOT on the
// project object nor on the account's iam-native content.
func TestMatrix_AccountOwner_MaterializesOnProjectObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mx2o")
	subject := mustSeedUser(t, ctx, pool, "mx2s") // account-owner grantee
	acc := seedAccount(t, ctx, repo, "acc-mx2", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-mx2")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "iam.project", string(prj.ID)))

	u := "user:" + string(subject)
	obj := "project:" + string(prj.ID)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", obj),
		"BUG #2a: account-owner must materialise v_update on the project object itself")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_delete", obj),
		"BUG #2a: account-owner must materialise v_delete on the project object itself")
	// owner role is `*.*.*` → admin tier on content.
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "admin", obj),
		"BUG #2a: account-owner must carry the admin tier on the project object")
}

// TestMatrix_AccountOwner_MaterializesOnServiceAccount (BUG #2b) — owner@account:A must
// materialise per-object access on an iam.serviceAccount of the account (fga type
// `iam_service_account`). RED before the fix: issue-sakey 403s "lacks v_update on
// iam_service_account".
func TestMatrix_AccountOwner_MaterializesOnServiceAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mx3o")
	subject := mustSeedUser(t, ctx, pool, "mx3s")
	acc := seedAccount(t, ctx, repo, "acc-mx3", owner)
	said := seedSAID(t, ctx, pool, string(acc.ID), "mx3")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "iam.serviceAccount", said))

	u := "user:" + string(subject)
	obj := "iam_service_account:" + said
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", obj),
		"BUG #2b: account-owner must materialise v_update on the account's service_account")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "admin", obj),
		"BUG #2b: account-owner must carry the admin tier on the account's service_account")
}

// TestMatrix_AccountOwner_ChildResource_Unaffected (regression guard) — the 8d44019 leg
// (account-owner on vpc content nested in a project of its account) must stay GREEN.
func TestMatrix_AccountOwner_ChildResource_Unaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "mx4o")
	subject := mustSeedUser(t, ctx, pool, "mx4s")
	acc := seedAccount(t, ctx, repo, "acc-mx4", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-mx4")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nMX4", string(prj.ID), "", nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nMX4"))

	u := "user:" + string(subject)
	obj := "vpc_network:nMX4"
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_update", obj),
		"account-owner keeps v_update on project-nested vpc content (8d44019)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, u, "v_delete", obj),
		"account-owner keeps v_delete on project-nested vpc content")
}
