// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_unified_p4_integration_test.go — RBAC explicit-model 2026 unified
// materializer integration tests, driven through the pg ReconcileAdapter +
// testcontainers Postgres 16.
//
// The unified materializer extends the reconciler from ARM_LABELS-only to ALL
// selectors — ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS — each × scope-boundary
// (GLOBAL/ACCOUNT/PROJECT). The reconciler materializes DIRECT per-object FGA
// tuples (`<type>:<id> # v_<verb>/<tier> @ subject`) for every match-object inside
// the binding's scope. Binding-time scope_grant emission is removed wholesale — the
// reconciler is the SINGLE path.
//
// Coverage:
//   - grant @ PROJECT, selector `all` (ARM_ANCHOR) → per-object v_* on the
//     type's objects in scope; NO scope_grant; other types untouched.
//   - grant @ PROJECT, selector `names[]` (ARM_NAMES) → only named objects.
//   - grant @ ACCOUNT, selector `all` → cross-project within the account.
//   - forward-materialization: object created AFTER the grant → reconciler
//     materializes its tuple on the mirror-change event (ReconcileObject).
//   - revoke / scope-exit removes the materialized tuple by ledger.
//   - concurrent reconcile (≥2 goroutines, advisory-lock) → exactly one
//     emit, no duplicate member/ledger row (partial-UNIQUE backstop).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// scopeGrantOutboxCount counts ANY scope_grant:* fga_outbox row (P4 invariant: the
// unified materializer NEVER emits a scope_grant — only direct per-object tuples).
func scopeGrantOutboxCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox WHERE payload->>'object' LIKE 'scope_grant:%'`).Scan(&n))
	return n
}

// ── grant @ PROJECT, selector `all` (ARM_ANCHOR) → per-object v_*, NO sg ──────

func TestP4_A01_AnchorAll_Project_PerObject_NoScopeGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4a01")
	rec, _ := newReconciler(pool)

	// ARM_ANCHOR (all): vpc.network get/list, selector all, project-scoped.
	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"}}
	require.Equal(t, domain.ArmAnchor, rule.Arm(), "test fixture must be an ARM_ANCHOR rule")
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4a01role", domain.Rules{rule})

	now := time.Now()
	// Two vpc.network objects in the binding's project + a foreign-type object.
	seedMirrorRow(t, ctx, pool, "vpc.network", "n1", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "n2", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "i1", string(fx.prj), string(fx.accID), nil, now)

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// Both networks materialized ACTIVE under the anchor rule_fp.
	for _, n := range []string{"n1", "n2"} {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", n)
		require.True(t, ok, "network %s materialized by ARM_ANCHOR(all)", n)
		assert.Equal(t, domain.VerificationActive, st)
		assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:"+n), 1,
			"direct per-object v_* tuple on %s", n)
	}
	// Foreign type (compute.instance) NOT materialized.
	_, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "i1")
	assert.False(t, ok, "ARM_ANCHOR(vpc.network) must not touch compute.instance")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i1"))

	// Invariant: NO scope_grant tuple at all (binding-time emit removed).
	assert.Equal(t, 0, scopeGrantOutboxCount(t, ctx, pool),
		"unified materializer never emits scope_grant")
}

// ── grant @ PROJECT, selector `names[]` (ARM_NAMES) → only named objects ──────

func TestP4_A02_Names_Project_OnlyNamed_NoScopeGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4a02")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
		ResourceNames: []string{"n1"}}
	require.Equal(t, domain.ArmNames, rule.Arm())
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4a02role", domain.Rules{rule})

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "n1", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "n2", string(fx.prj), string(fx.accID), nil, now)

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "n1")
	require.True(t, ok, "named object n1 materialized")
	assert.Equal(t, domain.VerificationActive, st)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:n1"), 1)

	_, ok2 := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "n2")
	assert.False(t, ok2, "unnamed object n2 not materialized (names selector)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:n2"))
	assert.Equal(t, 0, scopeGrantOutboxCount(t, ctx, pool), "names selector emits no scope_grant")
}

// ── grant @ ACCOUNT, selector `all` → cross-project within the account ────────

func TestP4_A04_AnchorAll_Account_CrossProject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4a04")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "p4a04role", domain.Rules{rule})

	now := time.Now()
	// n1 in prj, n3 in prjOth (both inside the account); nX in a foreign account.
	seedMirrorRow(t, ctx, pool, "vpc.network", "n1", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "n3", string(fx.prjOth), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "nX", "prj_foreign", "acc_foreign", nil, now)

	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	for _, n := range []string{"n1", "n3"} {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", n)
		require.True(t, ok, "account-scoped all materializes %s (in account)", n)
		assert.Equal(t, domain.VerificationActive, st)
	}
	// nX is in a foreign account → REJECTED or absent, never a tuple.
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:nX"),
		"object outside the account never gets a tuple")
	assert.Equal(t, 0, scopeGrantOutboxCount(t, ctx, pool))
}

// ── forward-materialization — object created AFTER the grant ──────────────────

func TestP4_C01b_ForwardMaterialization_AnchorAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4c01b")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4c01brole", domain.Rules{rule})

	// Grant FIRST, on an empty project (no networks yet) — like an owner-binding.
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// LATER: a network is created in the project (consumer emits RegisterResource →
	// resource_mirror upsert → ReconcileObject). The forward path must materialize.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nlate", string(fx.prj), string(fx.accID), nil, time.Now())
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nlate"))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "nlate")
	require.True(t, ok, "forward-materialization: late object picked up by ARM_ANCHOR(all) on its mirror event")
	assert.Equal(t, domain.VerificationActive, st)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:nlate"), 1,
		"owner/grant does not go stale on objects created after the binding")
}

// ── forward-materialization for a names selector ──────────────────────────────

func TestP4_C01b_ForwardMaterialization_Names(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4c01bn")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
		ResourceNames: []string{"nnamed"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4c01bnrole", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// The named object appears later — forward path must pick it up by id.
	seedMirrorRow(t, ctx, pool, "vpc.network", "nnamed", string(fx.prj), string(fx.accID), nil, time.Now())
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nnamed"))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "nnamed")
	require.True(t, ok, "forward-materialization for a names selector on its mirror event")
	assert.Equal(t, domain.VerificationActive, st)
}

// ── object leaves scope (deleted from mirror) → tuple revoked by ledger ───────

func TestP4_E03_AnchorAll_ScopeExit_RevokesByLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4e03")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4e03role", domain.Rules{rule})

	seedMirrorRow(t, ctx, pool, "vpc.network", "ngone", string(fx.prj), string(fx.accID), nil, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "ngone")
	require.True(t, ok)
	require.Equal(t, domain.VerificationActive, st)

	// The object leaves the mirror (UnregisterResource on Delete). Reconcile must
	// revoke the materialized tuple from the SAVED ledger (not re-derive).
	_, err = pool.Exec(ctx, `DELETE FROM kacho_iam.resource_mirror WHERE object_type=$1 AND object_id=$2`,
		"vpc.network", "ngone")
	require.NoError(t, err)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "ngone"))

	_, okGone := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "ngone")
	assert.False(t, okGone, "object that left the scope is no longer a member")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "vpc_network:ngone"), 1,
		"scope-exit eager-revokes the materialized tuple")
	var ledger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id=$1 AND object='vpc_network:ngone'`,
		string(bid)).Scan(&ledger))
	assert.Equal(t, 0, ledger, "ledger holds no residual for the departed object")
}

// ── concurrent reconcile of an ARM_ANCHOR binding → exactly one emit ──────────
//
// A steady-state reconcile-tx takes pg_advisory_xact_lock(hashtext(binding_id))
// (xact-scoped). With ≥2 concurrent passes the lock serializes them so exactly one
// materializes the member; the partial-UNIQUE backstop on the ledger guards against
// any duplicate emit even if the lock were bypassed.
func TestP4_H05_ConcurrentAnchorReconcile_ExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4h05")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4h05role", domain.Rules{rule})
	seedMirrorRow(t, ctx, pool, "vpc.network", "nconc", string(fx.prj), string(fx.accID), nil, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rec.ReconcileBinding(ctx, bid) }()
	}
	wg.Wait()
	require.NoError(t, rec.ReconcileBinding(ctx, bid)) // converge

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "nconc")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationActive, st)

	var members, ledger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members WHERE binding_id=$1 AND rule_fp=$2`,
		string(bid), fp).Scan(&members))
	assert.Equal(t, 1, members, "exactly one materialized member (advisory-lock serialized passes)")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id=$1 AND object='vpc_network:nconc'`,
		string(bid)).Scan(&ledger))
	assert.GreaterOrEqual(t, ledger, 1, "ledger has the materialized tuple")
	// No duplicate ledger row beyond the per-verb tuples (one v_get + one tier here).
	assert.LessOrEqual(t, ledger, 2, "partial-UNIQUE backstop prevents duplicate ledger rows")

	// Singleton emit: the advisory lock serializes the 8 concurrent
	// passes so the fga_outbox carries the object's tuples EXACTLY ONCE (≤2 = 1 v_get +
	// 1 tier), never N× the materialization. A duplicate emit here would mean a pass
	// bypassed the lock / re-emitted an already-recorded member.
	emits := countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:nconc")
	assert.GreaterOrEqual(t, emits, 1, "the object's tuple is emitted")
	assert.LessOrEqual(t, emits, 2, "exactly one materialization emit (1 v_get + 1 tier), not N× under concurrency")
}

// fgaOutboxTuple reports whether the fga_outbox holds a write of the exact
// (user, relation, object) tuple.
func fgaOutboxTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user, relation, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type='fga.tuple.write'
		    AND payload->>'user'=$1 AND payload->>'relation'=$2 AND payload->>'object'=$3`,
		user, relation, object).Scan(&n))
	return n > 0
}

// ── SCOPE-SELF tuple (no-access-loss). ──────────────────────────────────────────
//
// A rules-role bound on an account/project scope must materialize the role's tier
// (+ verb-bearing v_*) tuple ON THE SCOPE OBJECT ITSELF — `account:<X> # admin @
// subject` for a `*.*` admin role, `# viewer` for a read role. This is the
// write-authz anchor / self-access on the bare account.
//
// Binding-time emission is removed; the reconciler is the SINGLE materialization
// path. A `*.*` role (empty ObjectTypes — wildcard skipped) matches no CONTENT
// objects, so the scope-self tuple is what carries the subject's tier on the scope
// anchor; without it the subject would lack relation viewer/editor/admin on the
// account/project (every authz step would 403).
func TestP4_ScopeSelf_WildcardAdmin_Account_MaterializesTierOnAnchor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4self")
	rec, _ := newReconciler(pool)

	// `*.*` verbs `*` — the system `admin` superuser shape (migration 0031).
	rule := domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "p4selfadmin", domain.Rules{rule})

	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	subject := "user:" + string(fx.member)
	object := "account:" + string(fx.accID)
	// The tier tuple on the scope anchor itself — the no-access-loss anchor.
	assert.True(t, fgaOutboxTuple(t, ctx, pool, subject, "admin", object),
		"`*.*` admin role bound on account → admin tier tuple on account:<id> (write-authz anchor)")
	// account is verb-bearing: the self-access v_* set is materialized too.
	for _, v := range []string{"v_get", "v_list", "v_create", "v_update", "v_delete"} {
		assert.True(t, fgaOutboxTuple(t, ctx, pool, subject, v, object),
			"verb-bearing self %s on account:<id>", v)
	}
	// Still NO scope_grant primitive (reconciler is the single path).
	assert.Equal(t, 0, scopeGrantOutboxCount(t, ctx, pool),
		"scope-self materialization never emits scope_grant")
}

// TestP4_ScopeSelf_ViewRole_Project_ViewerTier — a read-only rules-role bound on a
// project materializes ONLY the viewer tier on the project scope object (no editor/
// admin escalation). Proves the scope-self tier honours the role's verb-class.
func TestP4_ScopeSelf_ViewRole_Project_ViewerTier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "p4selfv")
	rec, _ := newReconciler(pool)

	// `*.*` read verbs — the system `view` shape (migration 0031).
	rule := domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"read", "list", "get"}}
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "p4selfview", domain.Rules{rule})

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	subject := "user:" + string(fx.member)
	object := "project:" + string(fx.prj)
	assert.True(t, fgaOutboxTuple(t, ctx, pool, subject, "viewer", object),
		"read-only role → viewer tier on project:<id>")
	assert.False(t, fgaOutboxTuple(t, ctx, pool, subject, "admin", object),
		"read-only role must NOT escalate to admin on the scope anchor")
	assert.False(t, fgaOutboxTuple(t, ctx, pool, subject, "editor", object),
		"read-only role must NOT escalate to editor on the scope anchor")
}
