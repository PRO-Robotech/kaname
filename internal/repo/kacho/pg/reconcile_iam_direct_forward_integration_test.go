// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_iam_direct_forward_integration_test.go — the ADDITIVE forward fast-path
// extended to the IAM-DIRECT feed (sub-phase IAM-FMB: throughput fix for the
// iam.accessBinding / iam.project owner-tuple materialization on the create-path),
// driven through the pg ReconcileAdapter + testcontainers Postgres 16.
//
// Before this, ReconcileObjectForward delegated EVERY iam-direct type straight to the
// FULL EXCLUSIVE ReconcileObject, whose per-binding advisory lock + O(scope) recompute
// serialized on the SINGLE owner/account binding every access_binding / project of an
// account shares → the owner-tuple materialization lagged past the client
// read-your-writes retry budget (transient 403 on GET of the resource one just created)
// under a parallel create burst. The forward path now materializes ONLY the freshly-
// created iam-direct object's per-object tuples for each matching binding, reading the
// object from its OWN table (GetIAMDirectObject) + the iam-direct fan-out
// (IAMDirectSelectorBindingsMatchingObject), under a SHARE advisory lock — so N
// concurrent creates in one account do NOT serialize.
//
// Coverage (RED → GREEN):
//   01 ACCESSBINDING-FWD — forward materializes the owner's admin tuple on a NEW
//                          iam.accessBinding immediately, and ONLY that object (a sibling
//                          binding-object is NOT materialized → single-object, not O(scope)).
//   02 PROJECT-FWD ≡ FULL — forward's emitted relation-set on a NEW iam.project is
//                          BYTE-IDENTICAL to the FULL path's on a twin project (no drift).
//   03 THROUGHPUT         — N concurrent forwards for N distinct iam.project objects
//                          sharing ONE owner binding all materialize (idempotently, exactly
//                          once), no deadlock/serialization error (the SHARE-lock property).
//   04 SCOPE-BOUNDARY     — owner of account A is NOT materialized on account B's project.
//   05 BACKSTOP           — FULL then forward → no duplicate (idempotent convergence).
//   06 DELETE-STALE GUARD — a label-selector iam.project grant, then the label removed on
//                          re-materialize → routes to the FULL path → revoke STICKS.
//   07 ROLE-FWD ≡ FULL    — the four sibling create-paths (role/group/service_account/user)
//                          are now ROUTED to the forward fast-path too (they emit their own
//                          reconcile event on Create). 07 pins iam.role BYTE-IDENTITY on BOTH
//                          scopes — the account-scoped role AND the PROJECT-scoped role whose
//                          containment resolves the account through the COALESCE(o.account_id,
//                          p.account_id) join (the complex-containment case the reviewers
//                          flagged): forward ≡ full owner relation-set, no drift.
//   08 SA-FWD ≡ FULL      — iam.serviceAccount BYTE-IDENTITY on the account-scoped SA AND a
//                          project-scoped SA (parentProject = COALESCE(o.project_id,'')
//                          projection) — forward ≡ full owner relation-set.
//   09 USER/GROUP ≡ FULL  — iam.user + iam.group (the simpler account-scoped siblings)
//                          forward ≡ full owner relation-set (table-driven).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"fmt"
	"sort"
	"sync"
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

// countLedgerTuple counts emitted-tuple ledger rows for a (binding, object, relation).
func countLedgerTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, object, relation string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object=$2 AND relation=$3`,
		string(bID), object, relation).Scan(&n))
	return n
}

// ledgerRelationsForObject returns the SORTED set of relations recorded for a
// (binding, object) in the emitted-tuple ledger — the "what was materialized" set used
// to prove the forward path and the FULL path derive an IDENTICAL tuple-set.
func ledgerRelationsForObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, object string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT relation FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object=$2 ORDER BY relation ASC`,
		string(bID), object)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var rel string
		require.NoError(t, rows.Scan(&rel))
		out = append(out, rel)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// Test 01 — ACCESSBINDING-FWD: a grant (access_binding) created in the owner's account is
// forward-materialized (owner's admin tuple on iam_access_binding:<id>) immediately, AND a
// SIBLING binding-object is left un-materialized (proving the path is single-object, not a
// full O(scope) recompute of the owner binding).
func TestIAMDirectForward_01_AccessBinding_MaterializesOwnerAdmin_SingleObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf1-o")
	acc := seedAccount(t, ctx, repo, "acc-idf1", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	// Two account-scoped grant bindings (A + a sibling), created directly (no reconcile).
	memberA := mustSeedUser(t, ctx, pool, "idf1-ma")
	memberB := mustSeedUser(t, ctx, pool, "idf1-mb")
	roleA := seedNativeRole(t, ctx, pool, acc.ID, "idf1rolea")
	roleB := seedNativeRole(t, ctx, pool, acc.ID, "idf1roleb")
	grantA := insertThinBindingScope(t, ctx, repo, memberA, domain.RoleID(roleA), "account", string(acc.ID), domain.ScopeAccount)
	grantB := insertThinBindingScope(t, ctx, repo, memberB, domain.RoleID(roleB), "account", string(acc.ID), domain.ScopeAccount)

	// Forward ONLY grantA (as the create-path would for the just-created binding).
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.accessBinding", string(grantA)))

	// grantA: owner's admin tuple materialized on iam_access_binding:<grantA>.
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_access_binding:"+string(grantA)),
		"forward materializes the owner's admin tuple on the new access_binding")
	assert.Equal(t, 1, countLedgerTuple(t, ctx, pool, ownerBID, "iam_access_binding:"+string(grantA), "admin"),
		"exactly one admin ledger row (idempotent)")

	// grantB (the sibling) is NOT materialized — forward is single-object, not O(scope).
	assert.False(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_access_binding:"+string(grantB)),
		"forward must NOT recompute the whole scope (sibling binding-object untouched)")
}

// Test 02 — PROJECT-FWD ≡ FULL: the forward path's emitted relation-set on a brand-new
// iam.project is BYTE-IDENTICAL to the FULL path's on a twin project in the same account
// under the same owner binding — the shared per-object tuple derivation guarantees the two
// paths never drift (no over-/under-grant).
func TestIAMDirectForward_02_Project_ForwardEqualsFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf2-o")
	acc := seedAccount(t, ctx, repo, "acc-idf2", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	// Twin brand-new projects: one materialized via FORWARD, one via the FULL object path.
	prjFwd := seedProject(t, ctx, repo, acc.ID, "idf2-fwd")
	prjFull := seedProject(t, ctx, repo, acc.ID, "idf2-full")

	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.project", string(prjFwd.ID)))
	require.NoError(t, rec.ReconcileObject(ctx, "iam.project", string(prjFull.ID)))

	relFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, "project:"+string(prjFwd.ID))
	relFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, "project:"+string(prjFull.ID))

	require.NotEmpty(t, relFwd, "forward materialized SOME owner tuples on the new project")
	assert.Equal(t, relFull, relFwd,
		"forward and full derive a BYTE-IDENTICAL owner relation-set on an identical project (no drift)")
	// The owner tier is admin (owner `*.*` role — delete ⇒ admin).
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "project:"+string(prjFwd.ID)),
		"forward materializes the owner admin tuple on the new project")
}

// Test 03 — THROUGHPUT: N concurrent forwards for N DISTINCT iam.project objects sharing
// ONE owner binding all materialize the owner's admin tuple, idempotently (exactly one
// admin ledger row each) and WITHOUT deadlock / serialization error. This is the
// advisory-lock-free property under the iam-direct feed: with the per-binding EXCLUSIVE
// advisory lock (the old FULL delegation) every pass would serialize on the ONE owner
// binding; the additive SHARE-lock forward lets them proceed concurrently.
func TestIAMDirectForward_03_ConcurrentThroughput_NoDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf3-o")
	acc := seedAccount(t, ctx, repo, "acc-idf3", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	const n = 12
	prjIDs := make([]string, n)
	for i := 0; i < n; i++ {
		p := seedProject(t, ctx, repo, acc.ID, fmt.Sprintf("idf3-p%02d", i))
		prjIDs[i] = string(p.ID)
	}

	// N distinct projects × 2 concurrent forwards each (idempotent double-fire) = 2N
	// goroutines all hitting the SAME owner binding via SHARE locks.
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		for dup := 0; dup < 2; dup++ {
			wg.Add(1)
			go func(pid string) {
				defer wg.Done()
				errs <- rec.ReconcileObjectForward(ctx, "iam.project", pid)
			}(prjIDs[i])
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "no iam-direct forward pass may error/deadlock under concurrency")
	}

	for _, pid := range prjIDs {
		assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "project:"+pid),
			"project %s materialized under concurrency", pid)
		assert.Equal(t, 1, countLedgerTuple(t, ctx, pool, ownerBID, "project:"+pid, "admin"),
			"exactly one admin ledger row per project (idempotent, no dupes) for %s", pid)
	}
}

// Test 04 — SCOPE-BOUNDARY: the owner of account A must NOT be materialized on account B's
// project by a forward pass (containment narrows: the iam-direct fan-out is scope-aware and
// IsContainedIn re-verifies — the wildcard does not become cluster-wide).
func TestIAMDirectForward_04_ScopeBoundary_NoCrossAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "idf4-a")
	ownerB := mustSeedUser(t, ctx, pool, "idf4-b")
	accA := seedAccount(t, ctx, repo, "acc-idf4a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-idf4b", ownerB)
	prjB := seedProject(t, ctx, repo, accB.ID, "idf4-pb")
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)
	rec, _ := newReconciler(pool)

	// Forward account B's project MUST NOT grant owner A anything.
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.project", string(prjB.ID)))
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), "admin", "project:"+string(prjB.ID)),
		"owner of account A must NOT materialize on account B's project (scope boundary)")
}

// Test 05 — BACKSTOP: with the forward pass SKIPPED, the async FULL ReconcileObject
// materializes the project (at-least-once backstop). A subsequent forward pass does NOT
// duplicate — the two paths converge idempotently (exactly one admin ledger row).
func TestIAMDirectForward_05_Backstop_FullThenForward_NoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf5-o")
	acc := seedAccount(t, ctx, repo, "acc-idf5", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	rec, _ := newReconciler(pool)

	prj := seedProject(t, ctx, repo, acc.ID, "idf5-p")

	// Forward SKIPPED — the async FULL ReconcileObject is the backstop.
	require.NoError(t, rec.ReconcileObject(ctx, "iam.project", string(prj.ID)))
	require.Equal(t, 1, countLedgerTuple(t, ctx, pool, ownerBID, "project:"+string(prj.ID), "admin"),
		"async full backstop materializes the owner admin tuple forward skipped")

	// A late forward pass must be an idempotent no-op (no duplicate ledger row).
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.project", string(prj.ID)))
	assert.Equal(t, 1, countLedgerTuple(t, ctx, pool, ownerBID, "project:"+string(prj.ID), "admin"),
		"forward after full does not duplicate the owner tuple (idempotent convergence)")
}

// Test 06 — DELETE-STALE GUARD (iam-direct): a label-selector binding grants v_get on
// iam.project labeled team=a. A project labeled team=a is forward-materialized (create
// hot-path). Then the project label is REMOVED and the object is re-materialized — the
// grant MUST be REVOKED. The additive forward cannot delete-stale, so a re-materialize
// (object already has members) routes to the FULL ReconcileObject.
//
// RED (had the guard been dropped for iam-direct): the second forward would stay additive
// and never revoke → the stale grant survives. GREEN: the re-materialize revokes it.
func TestIAMDirectForward_06_DeleteStaleGuard_ProjectLabelFlip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf6-o")
	member := mustSeedUser(t, ctx, pool, "idf6-m")
	acc := seedAccount(t, ctx, repo, "acc-idf6", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	rec, _ := newReconciler(pool)

	// Account-scoped ARM_LABELS rule: v_get on iam.project labeled team=a.
	rule := domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, repo, acc.ID, "idf6role", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, repo, member, roleID, "account", string(acc.ID), domain.ScopeAccount)
	subj := "user:" + string(member)

	// CREATE: project labeled team=a → forward materializes the grant (no prior members).
	prj := seedProject(t, ctx, repo, acc.ID, "idf6-p")
	setProjectLabels(t, ctx, pool, prj.ID, map[string]string{"team": "a"})
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.project", string(prj.ID)))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.project", string(prj.ID))
	require.True(t, ok, "labeled project is granted on create")
	require.Equal(t, domain.VerificationActive, st)
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "project:"+string(prj.ID)),
		"create materializes v_get on the labeled project")

	// RE-MATERIALIZE (label removed): the object now has members → routes to the FULL path →
	// delete-stale → the grant is REVOKED.
	setProjectLabels(t, ctx, pool, prj.ID, map[string]string{})
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.project", string(prj.ID)))

	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "iam.project", string(prj.ID))
	assert.False(t, stillMember, "label-removed project is no longer a member (delete-stale)")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "project:"+string(prj.ID)),
		"REVOKE STICKS: the stale grant's ledger tuple is gone after the re-materialize")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "project:"+string(prj.ID)), 1,
		"the label-removal re-materialize eager-revokes the per-object tuple (post-revoke Check must DENY)")
}

// Test 07 — ROLE-FWD ≡ FULL: iam.role is one of the four sibling create-paths now ROUTED
// to the additive forward fast-path (sub-phase IAM-FMB extension). Role carries the most
// complex iam-direct containment: a PROJECT-scoped role has account_id NULL and resolves
// its account through the COALESCE(o.account_id, p.account_id) LEFT JOIN on projects
// (iamDirectScanSpecs["iam.role"]). This test pins that the forward path derives a
// BYTE-IDENTICAL owner relation-set to the FULL ReconcileObject on a twin object for BOTH
// scopes — the account-scoped role (direct account_id) AND the project-scoped role (the
// COALESCE-through-project join) — so routing the create-path to forward cannot over-/
// under-grant vs the full recompute.
//
// The account-owner (`*.*`, delete ⇒ admin tier) materializes on the project-scoped role
// too: the COALESCE join resolves the project's account, IsContainedIn(account) accepts it.
func TestIAMDirectForward_07_Role_ForwardEqualsFull_AccountAndProjectScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf7-o")
	acc := seedAccount(t, ctx, repo, "acc-idf7", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	// --- account-scoped role twins: forward vs full, byte-identical owner relation-set ---
	roleAccFwd := seedNativeRole(t, ctx, pool, acc.ID, "idf7accfwd")
	roleAccFull := seedNativeRole(t, ctx, pool, acc.ID, "idf7accfull")
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.role", roleAccFwd))
	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", roleAccFull))

	relAccFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_role:"+roleAccFwd)
	relAccFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_role:"+roleAccFull)
	require.NotEmpty(t, relAccFwd, "forward materialized owner tuples on the account-scoped role")
	assert.Equal(t, relAccFull, relAccFwd,
		"account-scoped iam.role: forward ≡ full owner relation-set (no drift)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_role:"+roleAccFwd),
		"forward materializes the owner admin tuple on the account-scoped role")

	// --- project-scoped role twins: COALESCE(o.account_id, p.account_id) join containment ---
	prj := seedProject(t, ctx, repo, acc.ID, "idf7prj")
	roleProjFwd := seedProjectRole(t, ctx, pool, prj.ID, "idf7prjfwd")
	roleProjFull := seedProjectRole(t, ctx, pool, prj.ID, "idf7prjfull")
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.role", string(roleProjFwd)))
	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", string(roleProjFull)))

	relProjFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_role:"+string(roleProjFwd))
	relProjFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_role:"+string(roleProjFull))
	require.NotEmpty(t, relProjFwd,
		"forward materialized owner tuples on the PROJECT-scoped role (COALESCE join resolves account via project)")
	assert.Equal(t, relProjFull, relProjFwd,
		"project-scoped iam.role: forward ≡ full owner relation-set (COALESCE(account_id,p.account_id) join byte-identical)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_role:"+string(roleProjFwd)),
		"account-owner materializes admin on the project-scoped role via COALESCE-through-project containment")
}

// Test 08 — SA-FWD ≡ FULL: iam.serviceAccount forward path derives a BYTE-IDENTICAL owner
// relation-set to the FULL ReconcileObject on a twin, for BOTH an account-scoped SA and a
// PROJECT-scoped SA (account_id set + project_id set → parentProject = COALESCE(o.project_id,
// ”) projection in iamDirectScanSpecs["iam.serviceAccount"]). The account-owner contains
// the SA through parentAccount = o.account_id in both cases; the project_id projection must
// not perturb the derived owner tuple-set (no drift) — the containment risk the reviewers
// flagged for the SA feed.
func TestIAMDirectForward_08_ServiceAccount_ForwardEqualsFull_AccountAndProjectScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf8-o")
	acc := seedAccount(t, ctx, repo, "acc-idf8", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	// seedProjectScopedSA inserts an SA carrying BOTH account_id and project_id (there is no
	// account/project XOR on service_accounts) so parentProject is a non-empty projection.
	seedProjectScopedSA := func(suffix string, prjID domain.ProjectID) string {
		sid := ids.NewID(domain.PrefixServiceAccount)
		_, e := pool.Exec(ctx,
			`INSERT INTO kacho_iam.service_accounts (id, account_id, project_id, name)
			 VALUES ($1, $2, $3, $4)`,
			sid, string(acc.ID), string(prjID), "sa-"+suffix)
		require.NoError(t, e, "seed project-scoped service_account")
		return sid
	}

	// --- account-scoped SA twins ---
	saAccFwd := seedNativeSA(t, ctx, pool, acc.ID, "idf8accfwd")
	saAccFull := seedNativeSA(t, ctx, pool, acc.ID, "idf8accfull")
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.serviceAccount", saAccFwd))
	require.NoError(t, rec.ReconcileObject(ctx, "iam.serviceAccount", saAccFull))

	relAccFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_service_account:"+saAccFwd)
	relAccFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_service_account:"+saAccFull)
	require.NotEmpty(t, relAccFwd, "forward materialized owner tuples on the account-scoped SA")
	assert.Equal(t, relAccFull, relAccFwd,
		"account-scoped iam.serviceAccount: forward ≡ full owner relation-set (no drift)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_service_account:"+saAccFwd),
		"forward materializes the owner admin tuple on the account-scoped SA")

	// --- project-scoped SA twins (project_id projection) ---
	prj := seedProject(t, ctx, repo, acc.ID, "idf8prj")
	saProjFwd := seedProjectScopedSA("idf8prjfwd", prj.ID)
	saProjFull := seedProjectScopedSA("idf8prjfull", prj.ID)
	require.NoError(t, rec.ReconcileObjectForward(ctx, "iam.serviceAccount", saProjFwd))
	require.NoError(t, rec.ReconcileObject(ctx, "iam.serviceAccount", saProjFull))

	relProjFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_service_account:"+saProjFwd)
	relProjFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, "iam_service_account:"+saProjFull)
	require.NotEmpty(t, relProjFwd,
		"forward materialized owner tuples on the project-scoped SA (parentProject = COALESCE(project_id,''))")
	assert.Equal(t, relProjFull, relProjFwd,
		"project-scoped iam.serviceAccount: forward ≡ full owner relation-set (project_id projection byte-identical)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_service_account:"+saProjFwd),
		"account-owner materializes admin on the project-scoped SA (contained via account_id)")
}

// Test 09 — USER/GROUP ≡ FULL: the two simpler account-scoped siblings. iam.user and
// iam.group both project parentAccount = o.account_id, parentProject = ” (account-scoped
// only). This pins forward ≡ full owner relation-set on a twin for each, closing the
// per-type byte-identity matrix for all four newly-routed sibling create-paths
// (role/service_account covered by 07/08).
func TestIAMDirectForward_09_UserGroup_ForwardEqualsFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "idf9-o")
	acc := seedAccount(t, ctx, repo, "acc-idf9", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)
	rec, _ := newReconciler(pool)

	cases := []struct {
		name    string
		objType string
		fgaType string
		seedFn  func(suffix string) string
	}{
		{"user", "iam.user", "iam_user", func(s string) string { return seedNativeUser(t, ctx, pool, acc.ID, s) }},
		{"group", "iam.group", "iam_group", func(s string) string { return seedNativeGroup(t, ctx, pool, acc.ID, s) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fwdID := tc.seedFn(tc.name + "fwd")
			fullID := tc.seedFn(tc.name + "full")
			require.NoError(t, rec.ReconcileObjectForward(ctx, tc.objType, fwdID))
			require.NoError(t, rec.ReconcileObject(ctx, tc.objType, fullID))

			relFwd := ledgerRelationsForObject(t, ctx, pool, ownerBID, tc.fgaType+":"+fwdID)
			relFull := ledgerRelationsForObject(t, ctx, pool, ownerBID, tc.fgaType+":"+fullID)
			require.NotEmpty(t, relFwd, "forward materialized owner tuples on the new %s", tc.name)
			assert.Equal(t, relFull, relFwd,
				"%s: forward ≡ full owner relation-set (no drift)", tc.name)
			assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", tc.fgaType+":"+fwdID),
				"forward materializes the owner admin tuple on the new %s", tc.name)
		})
	}
}
