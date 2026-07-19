// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_account_owner_transitive_integration_test.go — regression: an
// ACCOUNT-scoped binding (owner@account:A) must TRANSITIVELY materialize per-object
// v_* on a mirror-fed object that lives in a PROJECT of that account, EVEN WHEN the
// mirror row carries only parent_project_id (parent_account_id empty — the common
// production shape: vpc/compute register with the owning project, and iam resolves the
// account same-DB, but an unresolved/legacy row leaves parent_account_id='').
//
// Root cause (verified, keystone commit e195632): both containment gates for a
// mirror-fed object resolve account-containment ONLY via the DIRECT parent_account_id
// column — the scope-narrowing JOIN in SelectorBindingsMatchingObject (fast-path
// discovery) AND the reconciler's IsContainedIn re-verify (fed by the resource_mirror
// reads). A project-nested object whose parent_account_id is empty is therefore
// EXCLUDED from an account-scoped binding → the account owner never materializes
// per-object v_* on resources in projects of its OWN account → 403 on create/mutate.
//
// Coverage (RED → GREEN):
//   01 — account-owner forward-materializes v_* (+ admin tier) on a project-nested
//        vpc.network whose mirror row has EMPTY parent_account_id (only parent_project).
//   02 — a PROJECT-scoped edit binding is UNAFFECTED (project branch never used
//        parent_account_id) — guard that the transitive fix does not regress it.
//   03 — NO over-grant across the account boundary: owner@account:A must NOT
//        materialize on a vpc.network in a project of account:B (transitivity is
//        account-bounded, resolved through the project→account hierarchy).
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

// Test 01 (RED-1, main) — account-owner materializes per-object v_* on a project-nested
// vpc.network whose mirror row carries ONLY parent_project_id (parent_account_id=”).
//
// RED before the fix: SelectorBindingsMatchingObject's anchor account-branch checks
// `m.parent_account_id = b.resource_id`, which is ” ≠ A → the owner binding is not
// discovered on the object-change event, AND IsContainedIn(account:A) (parent_account_id
// == A) rejects it on the sweep → 0 tuples → 403 on the owner's own resource.
func TestAcctOwnerTransitive_01_ForwardMaterializes_ProjectNestedObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "aot1o")
	subject := mustSeedUser(t, ctx, pool, "aot1s") // S — account-owner grantee
	acc := seedAccount(t, ctx, repo, "acc-aot1", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-aot1")

	// S bound to the SYSTEM `owner` role at ACCOUNT scope.
	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	// A vpc.network registered under the project — mirror row carries parent_project
	// but EMPTY parent_account (the unresolved/legacy production shape).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nAOT1", string(prj.ID), "", nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nAOT1"))

	subjUser := "user:" + string(subject)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "v_update", "vpc_network:nAOT1"),
		"account-owner must transitively materialize v_update on a project-nested resource "+
			"of its own account (parent_account_id empty → resolved via project→account)")
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "admin", "vpc_network:nAOT1"),
		"account-owner must carry the admin tier on the project-nested resource")
}

// Test 02 (RED-2 guard) — a PROJECT-scoped edit binding still materializes v_update on a
// project-nested object even when the mirror row has EMPTY parent_account_id. The
// project containment branch (parent_project_id = scope.ID) never used
// parent_account_id, so it must be GREEN before AND after the transitive fix (no
// regression to project-scoped materialization / keystone test-1).
func TestAcctOwnerTransitive_02_ProjectScoped_Unaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "aot2o")
	member := mustSeedUser(t, ctx, pool, "aot2m") // project editor
	acc := seedAccount(t, ctx, repo, "acc-aot2", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-aot2")

	bID := insertThinBindingScope(t, ctx, repo, member, systemRoleID("edit"),
		"project", string(prj.ID), domain.ScopeProject)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nAOT2", string(prj.ID), "", nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nAOT2"))

	memberUser := "user:" + string(member)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, memberUser, "v_update", "vpc_network:nAOT2"),
		"project-scoped editor materializes v_update on its own project's resource "+
			"(project branch unaffected by parent_account_id)")
}

// Test 03 (RED-3, containment) — NO over-grant across the account boundary. owner@account:A
// must NOT materialize on a vpc.network in a project of a DIFFERENT account:B. The
// transitive resolution is account-bounded: the object's project resolves to account:B,
// which is not account:A → REJECTED, never a tuple.
func TestAcctOwnerTransitive_03_NoOverGrant_AcrossAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "aot3oa")
	ownerB := mustSeedUser(t, ctx, pool, "aot3ob")
	subject := mustSeedUser(t, ctx, pool, "aot3s") // S — owner of account A ONLY
	accA := seedAccount(t, ctx, repo, "acc-aot3a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-aot3b", ownerB)
	prjB := seedProject(t, ctx, repo, accB.ID, "prj-aot3b") // project in the OTHER account

	// S owns account A.
	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(accA.ID), domain.ScopeAccount)

	// A vpc.network in account B's project — mirror row carries only parent_project (of B).
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nAOT3b", string(prjB.ID), "", nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nAOT3b"))

	subjUser := "user:" + string(subject)
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "v_update", "vpc_network:nAOT3b"),
		"owner@account:A must NOT over-grant onto a resource in account:B's project "+
			"(transitive containment is account-bounded)")
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "admin", "vpc_network:nAOT3b"),
		"owner@account:A must NOT carry any tier on account:B's resource")
}
