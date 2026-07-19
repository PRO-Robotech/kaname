// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_scope_predicate_integration_test.go — scope-predicate push-down for the
// ARM_ANCHOR (`all`) reconcile arm.
//
// Root cause (perf, diagnosed file:line): ReconcileObject(one new object) fans out to
// every account/project binding whose selector matches, and reconcileBinding then does a
// FULL desired-set recompute. For the ARM_ANCHOR arm that recompute called
// MatchAllInScope → resource_mirror.AllByTypes, which read the WHOLE resource_mirror of
// the cluster (`WHERE object_type = ANY($1)` only) and narrowed to the binding's scope
// in Go. That is O(cluster mirror) per create → O(N²) per suite → grant-materialization
// lag → newman busy-wait 403 inflation across vpc/compute/nlb.
//
// Fix: push the binding's containment scope into the SQL as a PROVEN SUPERSET of the
// domain IsContainedIn re-verify, so Go receives O(scope) rows, not O(cluster):
//   - project scope  → parent_project_id = $scope                                  (exactly the IsContainedIn project branch)
//   - account scope  → COALESCE(NULLIF(parent_account_id,''), pj.account_id,'') = $scope
//                      (exactly the IsContainedIn account branch — SAME resolution the SELECT projects)
//   - cluster scope  → no narrowing (cluster contains everything; IsContainedIn cluster=true)
//
// The Go-side IsContainedIn (reconcile.go desiredRuleMembers) STAYS authoritative — the
// SQL predicate only PRE-filters. The predicate is an EXACT mirror of the projected
// ParentAccountID/ParentProjectID, so it is a guaranteed superset: it can never DROP a row
// IsContainedIn would accept (no under-grant), and any residual over-return is narrowed by
// Go (safe).
//
// Coverage (RED → GREEN):
//   01 — SYNC-VISIBLE: account-owner materializes v_update on a fresh project-nested object
//        (scoped recompute still materializes — no regression on the happy path).
//   02 — NO UNDER-GRANT: the object's mirror row carries EMPTY parent_account_id (only
//        parent_project) — the account-scope predicate MUST still include it via the
//        project→account join (guards that the pushed-down predicate is a true superset;
//        a naive `parent_account_id = $account` predicate would DROP it → under-grant).
//   03 — NO OVER-GRANT: object in a DIFFERENT account is NOT materialized (Go IsContainedIn
//        rejects; the account-scope predicate is account-bounded).
//   04 — PERF / SCAN-SCOPE: resource_mirror.AllByTypes with an account/project scope returns
//        ONLY the in-scope rows even when foreign-account rows of the SAME type exist in the
//        mirror — the observable proxy for "reconcile of an account-A object does not scan
//        account-B rows". Cluster scope still returns everything (unchanged).
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
)

// Test 01 — SYNC-VISIBLE: account-owner forward-materializes v_update (+ admin tier) on a
// project-nested object via the SCOPED anchor recompute. Correctness guard: the scope
// push-down must not lose the happy-path materialization.
func TestReconcileScopePredicate_01_SyncVisible_AccountOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rsp1o")
	subject := mustSeedUser(t, ctx, pool, "rsp1s")
	acc := seedAccount(t, ctx, repo, "acc-rsp1", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-rsp1")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	// parent_account NON-empty here (the resolved shape) — object clearly under account:A.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nRSP1", string(prj.ID), string(acc.ID), nil, time.Now())
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nRSP1"))

	subjUser := "user:" + string(subject)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "v_update", "vpc_network:nRSP1"),
		"account-owner must materialize v_update on its own account's object via the scoped anchor recompute")
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "admin", "vpc_network:nRSP1"),
		"account-owner must carry the admin tier on its own object")
}

// Test 02 — NO UNDER-GRANT: the mirror row carries ONLY parent_project_id (parent_account
// EMPTY — the common production/legacy shape). The account-scope predicate MUST resolve the
// account through the project→account join and STILL include the object. A naive
// `parent_account_id = $account` push-down would DROP this row → the account owner never
// materializes → under-grant (more 403). This pins the predicate as a true superset.
func TestReconcileScopePredicate_02_NoUnderGrant_EmptyParentAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rsp2o")
	subject := mustSeedUser(t, ctx, pool, "rsp2s")
	acc := seedAccount(t, ctx, repo, "acc-rsp2", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-rsp2")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(acc.ID), domain.ScopeAccount)

	// EMPTY parent_account — account must be resolved via the projects join.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nRSP2", string(prj.ID), "", nil, time.Now())
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nRSP2"))

	subjUser := "user:" + string(subject)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "v_update", "vpc_network:nRSP2"),
		"account-owner must materialize even when parent_account_id is empty "+
			"(scope predicate resolves account via project→account join — superset holds, no under-grant)")
}

// Test 03 — NO OVER-GRANT: owner@account:A must NOT materialize on an object in account:B's
// project. The account-scope predicate is account-bounded and Go IsContainedIn rejects it.
func TestReconcileScopePredicate_03_NoOverGrant_ForeignAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "rsp3oa")
	ownerB := mustSeedUser(t, ctx, pool, "rsp3ob")
	subject := mustSeedUser(t, ctx, pool, "rsp3s")
	accA := seedAccount(t, ctx, repo, "acc-rsp3a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-rsp3b", ownerB)
	prjB := seedProject(t, ctx, repo, accB.ID, "prj-rsp3b")

	bID := insertThinBindingScope(t, ctx, repo, subject, systemRoleID("owner"),
		"account", string(accA.ID), domain.ScopeAccount)

	seedMirrorRow(t, ctx, pool, "vpc.network", "nRSP3b", string(prjB.ID), "", nil, time.Now())
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nRSP3b"))

	subjUser := "user:" + string(subject)
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, bID, subjUser, "v_update", "vpc_network:nRSP3b"),
		"owner@account:A must NOT over-grant onto account:B's resource (account-bounded predicate + Go re-verify)")
}

// Test 04 — PERF / SCAN-SCOPE: the pushed-down scope predicate makes AllByTypes return ONLY
// the in-scope rows, so a reconcile of an account-A object never has to deserialize/scan the
// foreign account-B mirror rows in Go. This is the observable proxy for the O(scope) fix.
//
// RED before the fix: AllByTypes has NO scope parameter — the package fails to compile
// (scoped capability absent). Behavioral RED after the signature exists but with a wrong
// (cluster-wide) predicate: the account-scope call would return BOTH A and B rows.
func TestReconcileScopePredicate_04_ScanScope_ReturnsOnlyInScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "rsp4oa")
	ownerB := mustSeedUser(t, ctx, pool, "rsp4ob")
	accA := seedAccount(t, ctx, repo, "acc-rsp4a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-rsp4b", ownerB)
	prjA := seedProject(t, ctx, repo, accA.ID, "prj-rsp4a")
	prjA2 := seedProject(t, ctx, repo, accA.ID, "prj-rsp4a2")
	prjB := seedProject(t, ctx, repo, accB.ID, "prj-rsp4b")

	now := time.Now()
	// account A: two objects across two projects — parent_account EMPTY (resolve via join).
	seedMirrorRow(t, ctx, pool, "vpc.network", "nA1", string(prjA.ID), "", nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "nA2", string(prjA2.ID), "", nil, now)
	// account B: one object of the SAME type — must be EXCLUDED from an account-A scan.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nB1", string(prjB.ID), "", nil, now)

	types := []string{"vpc.network"}

	// account:A scope → ONLY A's two rows, never B's (proves the scan is account-bounded).
	accARows, err := resource_mirror.AllByTypes(ctx, pool, types, "account", string(accA.ID))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nA1", "nA2"}, mirrorIDs(accARows),
		"account:A scan returns ONLY account:A rows (foreign account:B row must not be scanned/returned)")

	// project:A scope → ONLY the single object in that project.
	prjARows, err := resource_mirror.AllByTypes(ctx, pool, types, "project", string(prjA.ID))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nA1"}, mirrorIDs(prjARows),
		"project:A scan returns ONLY that project's rows")

	// cluster scope → EVERYTHING (unchanged — cluster contains all).
	clusterRows, err := resource_mirror.AllByTypes(ctx, pool, types, "cluster", "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nA1", "nA2", "nB1"}, mirrorIDs(clusterRows),
		"cluster scope returns every row of the type (no narrowing)")
}

// mirrorIDs extracts the object ids from a mirror-row slice for order-insensitive assertions.
func mirrorIDs(rows []resource_mirror.MirrorRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ObjectID)
	}
	return out
}
