// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_forward_integration_test.go — the ADDITIVE forward fast-path
// (reconcile.ReconcileObjectForward) driven through the pg ReconcileAdapter +
// testcontainers Postgres 16.
//
// The forward path materializes ONLY the freshly-registered object's per-object tuples
// for each matching binding, WITHOUT the per-binding advisory lock / FOR UPDATE row-lock
// and WITHOUT the full O(scope) desired recompute — so N concurrent registrations in one
// project/account (all sharing ONE editor/owner binding) do NOT serialize on that
// binding's advisory lock (the throughput fix). The FULL ReconcileObject remains the
// async at-least-once backstop (delete-stale / audit / sweep).
//
// Coverage (RED → GREEN):
//   01 FORWARD-FAST     — forward materializes the registered object immediately, and
//                         ONLY that object (a sibling in-scope object is NOT touched →
//                         proves single-object, not a full-scope recompute).
//   02 THROUGHPUT       — N concurrent forwards for N distinct objects sharing ONE
//                         binding all materialize (idempotently, exactly once each), with
//                         no deadlock/serialization error — the advisory-lock-free path.
//   03 NO-OVER-GRANT    — a foreign-account binding is NOT a candidate / not materialized.
//   04 BACKSTOP         — forward skipped → the async FULL ReconcileObject converges;
//                         a later forward does NOT duplicate (idempotent overlap).
//   05 RACE FWD-vs-FULL — concurrent forward(add R) + full ReconcileObject(sibling O of
//                         the same binding) → R's tuples SURVIVE (full does not strip the
//                         just-added, in-mirror object as stale), no deadlock.
//   06 REVOKE-ON-UPDATE — a RE-REGISTER that REMOVES a grant-matching label REVOKES the
//                         now-stale grant (delete-stale). The additive forward cannot do
//                         this, so a re-register (object already has members) must route to
//                         the FULL path. Regression guard: T31 label-revoke `post-revoke-deny`.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// forwardAnchorRule — a project-scoped ARM_ANCHOR rule over compute.instance (get,
// update). ANCHOR → every compute.instance under scope; the reconciler re-verifies
// containment. update ⟹ v_delete co-materialization (leaf editor).
func forwardAnchorRule() domain.Rule {
	return domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}
}

// countTargetMembers counts materialized member rows for (binding, rule_fp, object).
func countTargetMembers(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, ruleFP, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members
		  WHERE binding_id=$1 AND rule_fp=$2 AND object_type=$3 AND object_id=$4`,
		string(bID), ruleFP, objType, objID).Scan(&n))
	return n
}

// Test 01 — FORWARD-FAST: a single forward pass materializes the registered object's
// per-object grant immediately AND touches ONLY that object (a sibling in-scope object is
// left un-materialized), proving the path is single-object, not a full-scope recompute.
func TestReconcileForward_01_FastMaterialize_SingleObjectOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd1")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd1role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	// Two objects in the SAME project (both would be in a full recompute's desired set).
	seedMirrorRow(t, ctx, pool, "compute.instance", "iFwd", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iSibling", string(fx.prj), string(fx.accID), nil, now)

	// Forward ONLY iFwd (as the register create-path would for the just-created object).
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iFwd"))

	subj := "user:" + string(fx.member)
	// iFwd is fully materialized (v_get/v_update/v_delete + editor tier).
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:iFwd"), "forward materializes v_update on the registered object")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_delete", "compute_instance:iFwd"), "update⟹v_delete co-materialized")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "editor", "compute_instance:iFwd"), "back-compat tier materialized")
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iFwd")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationActive, st)

	// The SIBLING object is NOT materialized — forward is single-object, not O(scope).
	_, okSib := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iSibling")
	assert.False(t, okSib, "forward must NOT recompute the whole scope (sibling untouched)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:iSibling"),
		"sibling object gets no tuple from a single-object forward pass")
}

// Test 02 — THROUGHPUT: N concurrent forwards for N DISTINCT objects sharing ONE binding
// all materialize, idempotently (exactly one member row each) and without deadlock /
// serialization error. This is the advisory-lock-free property: with the per-binding
// advisory lock every pass would serialize on that ONE binding; the additive forward path
// removes that lock so the passes proceed concurrently (each touches disjoint rows).
func TestReconcileForward_02_ConcurrentThroughput_NoSerializationDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd2")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd2role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	const n = 20
	now := time.Now()
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("iC%02d", i)
		seedMirrorRow(t, ctx, pool, "compute.instance", ids[i], string(fx.prj), string(fx.accID), nil, now)
	}

	// N distinct objects × 2 concurrent forwards each (idempotent double-fire) = 2N
	// goroutines all hitting the SAME editor@project binding. With the advisory lock this
	// would serialize; the forward path must let them run concurrently AND stay correct.
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		for dup := 0; dup < 2; dup++ {
			wg.Add(1)
			go func(objID string) {
				defer wg.Done()
				errs <- rec.ReconcileObjectForward(ctx, "compute.instance", objID)
			}(ids[i])
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "no forward pass may error/deadlock under concurrency")
	}

	subj := "user:" + string(fx.member)
	for _, id := range ids {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", id)
		require.True(t, ok, "object %s materialized under concurrency", id)
		assert.Equal(t, domain.VerificationActive, st)
		// Exactly ONE member row despite 2 concurrent forwards of the same object (additive
		// UPSERT idempotency — no duplicate materialization).
		assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", id),
			"exactly one member row per object (idempotent, no dupes) for %s", id)
		assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:"+id),
			"object %s carries its per-object grant", id)
	}
}

// Test 03 — NO-OVER-GRANT: a binding scoped to a DIFFERENT account is not a fast-path
// candidate for an object under account A, so forward never materializes it for the
// foreign binding (scope-narrowed source + IsContainedIn re-verify).
func TestReconcileForward_03_NoOverGrant_ForeignAccountBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd3") // account A + prj (fx.prj) + member
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()

	// Binding A: member gets compute.instance anchor on account A's project (own scope).
	roleA := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd3role_a", domain.Rules{rule})
	bidA := insertThinBinding(t, ctx, fx.repo, fx.member, roleA, fx.prj)

	// Foreign account B with its OWN account-scoped anchor binding for a foreign subject.
	ownerB := mustSeedUser(t, ctx, pool, "fwd3ob")
	subjB := mustSeedUser(t, ctx, pool, "fwd3sb")
	accB := seedAccount(t, ctx, fx.repo, "acc-fwd3b", ownerB)
	roleB := seedAccountRulesRole(t, ctx, pool, fx.repo, accB.ID, "fwd3role_b", domain.Rules{rule})
	bidB := insertThinBindingScope(t, ctx, fx.repo, subjB, roleB, "account", string(accB.ID), domain.ScopeAccount)

	// Object registered under account A.
	seedMirrorRow(t, ctx, pool, "compute.instance", "iA", string(fx.prj), string(fx.accID), nil, time.Now())
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iA"))

	// Binding A (own account) materialized; binding B (foreign account) NOT.
	stA, okA := memberStatusByRule(t, ctx, pool, bidA, fp, "compute.instance", "iA")
	require.True(t, okA, "own-scope binding materializes the object")
	assert.Equal(t, domain.VerificationActive, stA)
	_, okB := memberStatusByRule(t, ctx, pool, bidB, fp, "compute.instance", "iA")
	assert.False(t, okB, "foreign-account binding must NOT be materialized (no over-grant)")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bidB, "user:"+string(subjB), "v_update", "compute_instance:iA"),
		"foreign subject gets no tuple on account A's object")
}

// Test 04 — BACKSTOP: with the forward pass SKIPPED, the async FULL ReconcileObject
// materializes the object (at-least-once backstop). A subsequent forward pass does NOT
// duplicate — the two paths converge idempotently (exactly one member row, ledger PK
// dedup).
func TestReconcileForward_04_Backstop_FullConverges_NoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd4")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd4role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iBk", string(fx.prj), string(fx.accID), nil, time.Now())

	// Forward SKIPPED — the async FULL ReconcileObject is the backstop.
	require.NoError(t, rec.ReconcileObject(ctx, "compute.instance", "iBk"))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iBk")
	require.True(t, ok, "async full backstop materializes the object forward skipped")
	require.Equal(t, domain.VerificationActive, st)
	assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", "iBk"))

	// A late forward pass must be an idempotent no-op (no duplicate member, no ledger dup).
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iBk"))
	assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", "iBk"),
		"forward after full does not duplicate the member (idempotent convergence)")
	var ledgerRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object=$2 AND relation='v_update'`,
		string(bid), "compute_instance:iBk").Scan(&ledgerRows))
	assert.Equal(t, 1, ledgerRows, "ledger holds exactly one v_update row (PK dedup — forward+full overlap idempotent)")
}

// Test 05 — RACE FORWARD vs FULL: a concurrent forward(add R) and full ReconcileObject
// (triggered by a sibling object O of the SAME binding, which does a full recompute of B)
// must leave R's tuples PRESENT — the full recompute must NOT strip the just-added, in-
// mirror object R as stale. Both R and O end ACTIVE; no deadlock.
func TestReconcileForward_05_Race_ForwardVsFull_RSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd5")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd5role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	subj := "user:" + string(fx.member)
	now := time.Now()
	// Repeat a few times to shake out interleavings.
	for iter := 0; iter < 5; iter++ {
		rID := fmt.Sprintf("iR%02d", iter)
		oID := fmt.Sprintf("iO%02d", iter)
		// BOTH objects are committed to the mirror BEFORE the race, so the full recompute's
		// desired set includes R (in-mirror) → R must not be revoked as stale.
		seedMirrorRow(t, ctx, pool, "compute.instance", rID, string(fx.prj), string(fx.accID), nil, now)
		seedMirrorRow(t, ctx, pool, "compute.instance", oID, string(fx.prj), string(fx.accID), nil, now)

		var wg sync.WaitGroup
		errCh := make(chan error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errCh <- rec.ReconcileObjectForward(ctx, "compute.instance", rID) }()
		go func() { defer wg.Done(); errCh <- rec.ReconcileObject(ctx, "compute.instance", oID) }()
		wg.Wait()
		close(errCh)
		for e := range errCh {
			require.NoError(t, e, "no deadlock/error in forward|full race (iter %d)", iter)
		}
		// Converge (a late full/forward pass) then assert the final consistent state.
		require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", rID))

		stR, okR := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", rID)
		require.True(t, okR, "R materialized (iter %d)", iter)
		assert.Equal(t, domain.VerificationActive, stR, "R stays ACTIVE — full recompute must not strip the in-mirror object (iter %d)", iter)
		assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:"+rID),
			"R's tuple survives the concurrent full recompute (iter %d)", iter)
		assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", rID),
			"exactly one R member row (iter %d)", iter)
	}
}

// Test 06 — REVOKE-ON-UPDATE (regression guard for T31 label-revoke `post-revoke-deny`).
// A label-selector binding grants v_get on resources labeled team=a. A resource created
// with team=a is forward-materialized (create hot-path). Then the resource is RE-
// REGISTERED with the label REMOVED (the owning service's Update → RegisterResource with
// new labels) — the grant MUST be REVOKED. The additive forward path cannot delete-stale,
// so a re-register (object already has members) routes to the FULL ReconcileObject.
//
// RED before the delete-stale guard: the second ReconcileObjectForward stays additive and
// never revokes → the stale grant survives (Check would still allow → the e2e
// `post-revoke-deny {allowed:true}` failure). GREEN: the re-register revokes it.
func TestReconcileForward_06_ReRegisterLabelRemoved_RevokeSticks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd6")
	rec, _ := newReconciler(pool)

	// ARM_LABELS rule: v_get on compute.instance labeled team=a.
	rule := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd6role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	subj := "user:" + string(fx.member)

	now := time.Now()
	// CREATE: resource labeled team=a → forward materializes the grant (create hot-path,
	// no prior members → additive forward).
	seedMirrorRow(t, ctx, pool, "compute.instance", "iLbl", string(fx.prj), string(fx.accID), map[string]string{"team": "a"}, now)
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iLbl"))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iLbl")
	require.True(t, ok, "labeled resource is granted on create")
	require.Equal(t, domain.VerificationActive, st)
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "compute_instance:iLbl"),
		"create materializes v_get")

	// RE-REGISTER (label UPDATE): the label is REMOVED. RegisterResource is called again
	// → ReconcileObjectForward. The object now has members → routes to the FULL path →
	// delete-stale → the grant is REVOKED.
	seedMirrorRow(t, ctx, pool, "compute.instance", "iLbl", string(fx.prj), string(fx.accID), map[string]string{}, now.Add(time.Second))
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iLbl"))

	// The grant is gone: member removed AND the per-object tuple eager-revoked.
	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iLbl")
	assert.False(t, stillMember, "label-removed resource is no longer a member (delete-stale)")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "compute_instance:iLbl"),
		"REVOKE STICKS: the stale grant's ledger tuple is gone after the re-register")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "compute_instance:iLbl"), 1,
		"the label-removal re-register eager-revokes the per-object tuple (post-revoke Check must DENY)")
}
