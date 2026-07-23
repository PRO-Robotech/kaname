// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_binding_forward_integration_test.go — the ADDITIVE create-path forward
// fast-path for a freshly-CREATED binding (reconcile.ReconcileBindingForward, sub-phase
// IAM-FMB) driven through the pg ReconcileAdapter + testcontainers Postgres 16.
//
// The create-forward materializes the binding's desired ACTIVE per-object members
// ADDITIVELY (SHARE advisory lock, LoadBindingUnlocked / no FOR UPDATE, write-missing-only,
// NO delete-stale diff) — the throughput fix for a mass-binding-create burst. The FULL
// EXCLUSIVE ReconcileBinding REMAINS the Role.Update fan-out + sweep backstop (delete-stale
// needs EXCLUSIVE there).
//
// Coverage (traces the IAM-FMB acceptance scenarios):
//   01 FAST-MATERIALIZE   (IAM-FMB-01) — forward materializes the binding's grant + the
//                          per-object tuples are DURABLE in fga_outbox (drainer backstop).
//   03 EQUIVALENCE        (IAM-FMB-03) — forward grant-set ≡ FULL grant-set; a cross-scope
//                          object is granted by NEITHER path.
//   04 RACE FWD-vs-FULL   (IAM-FMB-04, -race, REQUIRED) — forward(B) ∥ FULL ReconcileBinding
//                          (B) on the SAME binding: no deadlock (40P01), desired-set holds,
//                          exactly 1 member / 1 ledger row per (rule_fp,object), no lost-update.
//   05 CREATE-VS-REVOKE   (IAM-FMB-05, -race, REQUIRED) — forward(B) ∥ [Role.Update removes
//                          verb + FULL(B)]: after convergence the state is coherent with the
//                          FINAL role (no stuck `update` tuple), independent of interleaving.
//   07 IDEMPOTENT         (IAM-FMB-07, REQUIRED) — double forward → exactly 1 member / 1 ledger.
//   08 FANOUT-REVOKE      (IAM-FMB-08) — a forward-created member is delete-stale-able by the
//                          FULL Role.Update fan-out (revoke STICKS; forward not applied to fan-out).
//   10 DELEGATE-FULL      (IAM-FMB-10) — a binding that already has members routes to the FULL
//                          path so a now-unmatched grant is delete-stale-revoked.
//   12 EMPTY-SCOPE        (IAM-FMB-12) — no matching objects → zero members, no error.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Test 01 — FAST-MATERIALIZE (IAM-FMB-01). A single create-forward pass materializes the
// binding's desired ACTIVE members + per-object tuples, and those tuples are DURABLE in
// fga_outbox inside the forward writer-tx (the at-least-once drainer backstop, D-5) — so
// the grant converges even if the post-commit sync-FGA write were to fail.
func TestReconcileBindingForward_01_FastMaterialize_Durable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd1")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule() // compute.instance {get, update}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd1role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "iX", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iY", string(fx.prj), string(fx.accID), nil, now)

	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

	subj := "user:" + string(fx.member)
	// Both in-scope objects are materialized ACTIVE (a create-forward materializes the whole
	// binding's desired set, unlike the object-forward which is single-object).
	for _, id := range []string{"iX", "iY"} {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", id)
		require.True(t, ok, "object %s materialized by create-forward", id)
		assert.Equal(t, domain.VerificationActive, st)
		assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:"+id),
			"create-forward records v_update for %s in the ledger", id)
		// The per-object tuple is DURABLE in fga_outbox (drainer applies at-least-once even
		// if the post-commit sync-FGA write failed — Operation.done never waits on it, ban #9).
		assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:"+id), 1,
			"per-object tuple durable in fga_outbox for %s (D-5 backstop)", id)
	}
}

// Test 03 — EQUIVALENCE (IAM-FMB-03). Two identical grant configs (same role/scope/objects,
// different subjects): one materialized create-FORWARD, one materialized FULL
// ReconcileBinding. The resulting grant-set is IDENTICAL, and a cross-scope object (in the
// mirror but under a foreign project) is granted by NEITHER path.
func TestReconcileBindingForward_03_Equivalence_ForwardEqFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd3")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd3role", domain.Rules{rule})

	subjFwd := fx.member
	subjFull := mustSeedUser(t, ctx, pool, "bfwd3full")
	bidFwd := insertThinBinding(t, ctx, fx.repo, subjFwd, roleID, fx.prj)
	bidFull := insertThinBinding(t, ctx, fx.repo, subjFull, roleID, fx.prj)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "iX", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iY", string(fx.prj), string(fx.accID), nil, now)
	// Cross-scope object: in the mirror but under the OTHER project (foreign containment).
	seedMirrorRow(t, ctx, pool, "compute.instance", "iForeign", string(fx.prjOth), string(fx.accID), nil, now)

	require.NoError(t, rec.ReconcileBindingForward(ctx, bidFwd))
	require.NoError(t, rec.ReconcileBinding(ctx, bidFull))

	fwdU := "user:" + string(subjFwd)
	fullU := "user:" + string(subjFull)
	for _, id := range []string{"iX", "iY"} {
		obj := "compute_instance:" + id
		for _, rel := range []string{"v_get", "v_update", "v_delete", "editor"} {
			assert.Equal(t,
				ledgerHasTuple(t, ctx, pool, bidFull, fullU, rel, obj),
				ledgerHasTuple(t, ctx, pool, bidFwd, fwdU, rel, obj),
				"forward ≡ FULL for %s on %s", rel, id)
			assert.True(t, ledgerHasTuple(t, ctx, pool, bidFwd, fwdU, rel, obj),
				"both paths grant %s on %s", rel, id)
		}
		// Member status parity.
		stF, okF := memberStatusByRule(t, ctx, pool, bidFwd, fp, "compute.instance", id)
		stL, okL := memberStatusByRule(t, ctx, pool, bidFull, fp, "compute.instance", id)
		assert.Equal(t, okL, okF)
		assert.Equal(t, stL, stF)
	}
	// Cross-scope object granted by NEITHER path (no over-grant on either).
	assert.False(t, ledgerHasTuple(t, ctx, pool, bidFwd, fwdU, "v_get", "compute_instance:iForeign"),
		"forward does not grant a cross-scope object")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bidFull, fullU, "v_get", "compute_instance:iForeign"),
		"FULL does not grant a cross-scope object")
	// Forward is additive-only: it writes NO REJECTED member (the FULL path owns REJECTED+audit).
	_, okRejFwd := memberStatusByRule(t, ctx, pool, bidFwd, fp, "compute.instance", "iForeign")
	assert.False(t, okRejFwd, "additive forward writes no REJECTED member for the foreign object")
}

// Test 04 — RACE FORWARD vs FULL (IAM-FMB-04, REQUIRED, run under -race). A create-forward
// of binding B and a concurrent FULL ReconcileBinding(B) (sweep / Role.Update trigger on the
// SAME binding) must not deadlock (SHARE ⊥ EXCLUSIVE take turns on the per-binding advisory
// lock), must converge to the role's desired-set, and must leave EXACTLY one member /
// ledger row per (rule_fp,object) — no duplicate, no lost-update.
func TestReconcileBindingForward_04_Race_ForwardVsFull_ExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd4")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd4role", domain.Rules{rule})
	now := time.Now()

	// Repeat with a fresh subject + binding + objects each iteration to shake out
	// interleavings. A FRESH subject per iteration keeps each binding distinct under the
	// active-grant partial-UNIQUE (subject,role,resource) WHERE status=ACTIVE (migration 0003/0055).
	for iter := 0; iter < 5; iter++ {
		member := mustSeedUser(t, ctx, pool, fmt.Sprintf("bfwd4m%d", iter))
		subj := "user:" + string(member)
		bid := insertThinBinding(t, ctx, fx.repo, member, roleID, fx.prj)
		const m = 4
		ids := make([]string, m)
		for j := 0; j < m; j++ {
			ids[j] = fmt.Sprintf("i%02d_%02d", iter, j)
			seedMirrorRow(t, ctx, pool, "compute.instance", ids[j], string(fx.prj), string(fx.accID), nil, now)
		}

		var wg sync.WaitGroup
		errCh := make(chan error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errCh <- rec.ReconcileBindingForward(ctx, bid) }()
		go func() { defer wg.Done(); errCh <- rec.ReconcileBinding(ctx, bid) }()
		wg.Wait()
		close(errCh)
		for e := range errCh {
			require.NoError(t, e, "no deadlock/error in forward|full race (iter %d)", iter)
		}
		// Converge (a late forward) then assert the final consistent state.
		require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

		for _, id := range ids {
			st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", id)
			require.True(t, ok, "object %s materialized (iter %d)", id, iter)
			assert.Equal(t, domain.VerificationActive, st, "object %s ACTIVE (iter %d)", id, iter)
			// Exactly ONE member row (additive UPSERT idempotency — no dup under the race).
			assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", id),
				"exactly one member row for %s (iter %d)", id, iter)
			// No lost-update: BOTH verbs survive the concurrent full recompute.
			assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "compute_instance:"+id),
				"v_get survives (iter %d)", iter)
			assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:"+id),
				"v_update survives (iter %d)", iter)
			// Exactly ONE ledger row per (relation,object) — no duplicate materialization.
			var n int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
				  WHERE binding_id=$1 AND object=$2 AND relation='v_update'`,
				string(bid), "compute_instance:"+id).Scan(&n))
			assert.Equal(t, 1, n, "exactly one v_update ledger row for %s (iter %d)", id, iter)
		}
	}
}

// Test 05 — CREATE-vs-CONCURRENT-REVOKE (IAM-FMB-05, REQUIRED, run under -race). A create-
// forward of binding B races a Role.Update that REMOVES verb `update` (+ its FULL fan-out
// recompute of B). Regardless of interleaving, after both settle (a convergence FULL pass)
// the materialized state is coherent with the FINAL role: `get` stays granted, `update` is
// revoked and does NOT stay stuck. No deadlock in either pass.
func TestReconcileBindingForward_05_CreateVsConcurrentRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd5")
	rec, _ := newReconciler(pool)
	subj := "user:" + string(fx.member)
	now := time.Now()

	for iter := 0; iter < 4; iter++ {
		// Fresh role {get, update}, binding, object each iteration.
		full := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}
		getOnly := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}
		roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, fmt.Sprintf("bfwd5role%d", iter), domain.Rules{full})
		bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
		objID := fmt.Sprintf("iRev%02d", iter)
		seedMirrorRow(t, ctx, pool, "compute.instance", objID, string(fx.prj), string(fx.accID), nil, now)
		obj := "compute_instance:" + objID
		// Precompute the compiled permissions + selectors OUTSIDE the goroutine (mustCompile
		// uses require and must run on the test goroutine, not a spawned one).
		getOnlyPerms := mustCompile(t, domain.Rules{getOnly})
		getOnlySelectors := domain.Rules{getOnly}.MaterializingSelectors()

		var wg sync.WaitGroup
		errCh := make(chan error, 2)
		wg.Add(2)
		// A: create-forward (may materialize {get,update}).
		go func() { defer wg.Done(); errCh <- rec.ReconcileBindingForward(ctx, bid) }()
		// B: Role.Update removes `update`, then FULL fan-out recompute of B (delete-stale).
		go func() {
			defer wg.Done()
			w, werr := fx.repo.Writer(ctx)
			if werr != nil {
				errCh <- werr
				return
			}
			updated := domain.Role{ID: roleID, ProjectID: fx.prj, Name: domain.RoleName(fmt.Sprintf("bfwd5role%d", iter)),
				Rules: domain.Rules{getOnly}, Permissions: getOnlyPerms, IsSystem: false}
			if _, uerr := w.RolesW().Update(ctx, updated, []string{"rules"}); uerr != nil {
				_ = w.Rollback(ctx)
				errCh <- uerr
				return
			}
			if rerr := w.RolesW().ReplaceRuleSelectors(ctx, roleID, getOnlySelectors); rerr != nil {
				_ = w.Rollback(ctx)
				errCh <- rerr
				return
			}
			if cerr := w.Commit(ctx); cerr != nil {
				errCh <- cerr
				return
			}
			errCh <- rec.ReconcileBinding(ctx, bid)
		}()
		wg.Wait()
		close(errCh)
		for e := range errCh {
			require.NoError(t, e, "no deadlock/error in forward|revoke race (iter %d)", iter)
		}

		// Convergence pass (the sweep backstop) re-materializes against the FINAL role {get}
		// and delete-stales any `update` the forward materialized before the revoke landed.
		require.NoError(t, rec.ReconcileBinding(ctx, bid))

		// Coherent with the FINAL role: `get` granted, `update` revoked (no stuck tuple).
		assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", obj),
			"get stays granted after revoke settles (iter %d)", iter)
		assert.False(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", obj),
			"update is revoked and does NOT stay stuck (iter %d)", iter)
	}
}

// Test 07 — IDEMPOTENT (IAM-FMB-07, REQUIRED). Running the create-forward TWICE for the same
// binding is a safe no-op: exactly one member row and one ledger row per (rule_fp,object).
func TestReconcileBindingForward_07_Idempotent_DoubleForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd7")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd7role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iDup", string(fx.prj), string(fx.accID), nil, time.Now())

	// First forward — additive materialize. Second forward — the binding now HAS members,
	// so it routes to the FULL path (delete-stale guard, D-4), which is idempotent for an
	// unchanged desired-set. Either way: exactly one member / one ledger row.
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iDup")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationActive, st)
	assert.Equal(t, 1, countTargetMembers(t, ctx, pool, bid, fp, "compute.instance", "iDup"),
		"double forward does not duplicate the member")
	var ledgerRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object=$2 AND relation='v_update'`,
		string(bid), "compute_instance:iDup").Scan(&ledgerRows))
	assert.Equal(t, 1, ledgerRows, "ledger holds exactly one v_update row (idempotent overlap)")
}

// Test 08 — FANOUT-REVOKE (IAM-FMB-08). A member materialized by the create-forward must be
// delete-stale-able by the FULL Role.Update fan-out: removing verb `update` from the role
// and running the FULL ReconcileBinding REVOKES the `update` grant (revoke STICKS) while
// `get` stays — proving the forward is NOT applied to the fan-out (which needs EXCLUSIVE +
// delete-stale) and forward-created members reconcile correctly under a later role change.
func TestReconcileBindingForward_08_FanoutRevokeSticks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd8")
	rec, _ := newReconciler(pool)
	subj := "user:" + string(fx.member)

	full := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}
	getOnly := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd8role", domain.Rules{full})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iFan", string(fx.prj), string(fx.accID), nil, time.Now())
	obj := "compute_instance:iFan"

	// Create-forward materializes {get, update}.
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", obj), "create-forward granted update")

	// Role.Update removes `update` → FULL fan-out recompute (delete-stale).
	w, err := fx.repo.Writer(ctx)
	require.NoError(t, err)
	updated := domain.Role{ID: roleID, ProjectID: fx.prj, Name: "bfwd8role",
		Rules: domain.Rules{getOnly}, Permissions: mustCompile(t, domain.Rules{getOnly}), IsSystem: false}
	_, err = w.RolesW().Update(ctx, updated, []string{"rules"})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, roleID, updated.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// Revoke STICKS: update gone, get stays.
	assert.False(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", obj),
		"Role.Update fan-out delete-stale revokes the update grant materialized by the create-forward")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", obj),
		"get stays granted (only the removed verb is revoked)")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", obj), 1,
		"the fan-out eager-revokes the update tuple (post-revoke Check must DENY)")
}

// Test 10 — DELEGATE-TO-FULL (IAM-FMB-10). A create-forward called on a binding that ALREADY
// has materialized members whose desired-set has SHRUNK (a rule/label change removed a grant)
// must delegate to the FULL ReconcileBinding so the now-unmatched grant is delete-stale-
// revoked — the additive path alone would leave it stuck.
func TestReconcileBindingForward_10_ExistingMembers_DelegatesToFull_DeleteStale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd10")
	rec, _ := newReconciler(pool)
	subj := "user:" + string(fx.member)

	// ARM_LABELS rule: v_get on compute.instance labeled team=a.
	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "a"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd10role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	// Create: object labeled team=a → forward materializes the grant (no prior members).
	seedMirrorRow(t, ctx, pool, "compute.instance", "iLbl", string(fx.prj), string(fx.accID), map[string]string{"team": "a"}, now)
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "compute_instance:iLbl"), "create materializes the grant")

	// The object's label FLIPS to team=b (no longer matches) — then the binding is re-
	// reconciled via ReconcileBindingForward. The binding NOW has members → the delete-stale
	// guard routes to the FULL path, which revokes the now-unmatched grant.
	seedMirrorRow(t, ctx, pool, "compute.instance", "iLbl", string(fx.prj), string(fx.accID), map[string]string{"team": "b"}, now.Add(time.Second))
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iLbl")
	assert.False(t, stillMember, "label-flipped object is no longer a member (delete-stale via delegated FULL path)")
	assert.False(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_get", "compute_instance:iLbl"),
		"REVOKE STICKS: the now-unmatched grant is delete-stale-revoked (not left stuck by the additive path)")
}

// Test 12 — EMPTY-SCOPE (IAM-FMB-12). A create-forward for a binding whose role matches a
// type with NO registered objects in scope materializes ZERO members, completes without
// error, and is bounded (does not scan a non-existent scope).
func TestReconcileBindingForward_12_EmptyScope_ZeroMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "bfwd12")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "bfwd12role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	// No compute.instance rows in the mirror for this scope.
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

	var members int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members WHERE binding_id=$1`,
		string(bid)).Scan(&members))
	assert.Equal(t, 0, members, "empty scope → zero materialized members, no error")
}
