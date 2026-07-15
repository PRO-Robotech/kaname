// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migrate_backfill_p8_integration_test.go — integration tests over the
// pg backfill/verify adapter + the seed.BackfillRunner / seed.VerifyGate
// use-cases, driven by testcontainers Postgres 16.
//
// The migrate step does NOT remove the FGA derivation cascade / scope_grant — that is the
// SUBSEQUENT contract phase (Contract-A removed the cascade + scope_grant;
// Contract-B removed the dead B2B org type). The migrate step only:
//   1. owner-binding backfill for EXISTING accounts (migration 0036, SQL data
//      migration — idempotent via the active-grant partial-UNIQUE; the per-object
//      tuples are materialized FORWARD by the reconcile-sweep below).
//   2. reconcile-backfill SWEEP over EVERY active binding (singleton single-shot
//      under a process-wide pg_advisory_xact_lock; chunked tx-size bound).
//      Each binding is reconciled by the SAME single materialization path
//      (reconciler) → its per-object FGA tuples land in the ledger.
//   3. verify-gate (continuous/forward-aware): every active binding's new
//      explicit tuples are materialized (no-access-loss) + a forward-smoke on a
//      freshly-created resource confirms the forward path is live (gate for the
//      contract phase).
//
// Coverage:
//   - backfill does not lose operator access (post-backfill ledger present).
//   - idempotent re-apply: repeat backfill → 0 new owner-bindings, 0 dup tuples.
//   - commutative/idempotent backfill-sweep vs live forward-mat (partial-UNIQUE).
//   - replica coordination: N concurrent RunOnce → exactly one executes the
//     sweep (singleton advisory-lock), no duplicate ledger rows.
//   - chunked tx-size bound (sweep does not reconcile all bindings in one tx).
//   - forward-aware verify-gate: 100% no-access-loss + live forward-smoke.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// activeOwnerBindingCount counts ACTIVE owner-role bindings for an account.
func activeOwnerBindingCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings
		  WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		    AND revoked_at IS NULL`,
		domain.OwnerRoleID, string(accID)).Scan(&n))
	return n
}

// ownerBindingID returns the (single) active owner-binding id for an account.
func ownerBindingID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) domain.AccessBindingID {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.access_bindings
		  WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		    AND revoked_at IS NULL
		  LIMIT 1`,
		domain.OwnerRoleID, string(accID)).Scan(&id))
	return domain.AccessBindingID(id)
}

// ledgerTupleCount counts access_binding_emitted_tuples rows for a binding.
func ledgerTupleCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bID)).Scan(&n))
	return n
}

// ledgerHasTuple asserts a specific (relation, object) tuple is recorded for a binding.
func ledgerHasTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, fgaUser, relation, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND fga_user = $2 AND relation = $3 AND object = $4`,
		string(bID), fgaUser, relation, object).Scan(&n))
	return n > 0
}

// newBackfill wires the backfill runner + verify-gate over the pg adapter.
func newBackfill(pool *pgxpool.Pool) (*seed.BackfillRunner, *seed.VerifyGate) {
	rec, _ := newReconciler(pool)
	adapter := kachopg.NewBackfillAdapter(pool)
	runner := seed.NewBackfillRunner(rec, adapter, seed.BackfillConfig{ChunkSize: 2})
	gate := seed.NewVerifyGate(rec, adapter, nil)
	return runner, gate
}

// ── owner-binding backfill for EXISTING accounts (migration 0036) ────────
//
// An account created before owner-bindings were auto-created gets an owner-binding by
// migration 0036. Idempotent: the active-grant partial-UNIQUE means a re-apply
// (or an account that ALREADY has an owner-binding) inserts nothing.

func TestP8_01_OwnerBindingBackfill_ExistingAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // goose.Up applies migration 0036 (owner-binding backfill)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// An account seeded the "legacy" way (mustSeedUser INSERTs accounts directly,
	// no owner AccessBinding) — but it was seeded AFTER goose.Up, so migration 0036
	// already ran and did NOT see it. Re-run the backfill SQL idempotently here to
	// emulate "existing account at migrate time".
	owner := mustSeedUser(t, ctx, pool, "p8acc")
	acc := seedAccount(t, ctx, repo, "p8-legacy-acc", owner)

	// Before backfill: no owner-binding (seedAccount does not create one).
	require.Equal(t, 0, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"seedAccount must not create an owner-binding")

	// Run the idempotent backfill SQL (the body of migration 0036) — exposed so a
	// post-goose.Up account is covered too.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"backfill must create exactly one owner-binding for the existing account")

	// idempotent: re-run → still exactly one (active-grant partial-UNIQUE).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"re-running owner-binding backfill must be a no-op (idempotent, H-02)")

	// The owner-binding subject is the account's owner_user_id, role=owner.
	bID := ownerBindingID(t, ctx, pool, acc.ID)
	var subjType, subjID, roleID string
	var protected bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT subject_type, subject_id, role_id, deletion_protection
		   FROM kacho_iam.access_bindings WHERE id = $1`, string(bID)).
		Scan(&subjType, &subjID, &roleID, &protected))
	assert.Equal(t, "user", subjType)
	assert.Equal(t, string(owner), subjID)
	assert.Equal(t, domain.OwnerRoleID, roleID)
	assert.True(t, protected, "backfilled owner-binding must be deletion_protected (D-8a)")

	// access_binding_subjects has the projected single subject row.
	var subjRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_subjects WHERE binding_id = $1`,
		string(bID)).Scan(&subjRows))
	assert.Equal(t, 1, subjRows, "owner-binding must have its projected subject row")

	// No-access-loss: the backfill must ALSO queue the owner-binding OBJECT
	// hierarchy parent-pointer fga_outbox intent
	//   account:<A>#account@iam_access_binding:<bindingID>
	// so the account owner resolves Get/Delete on the owner-binding OBJECT via the FGA
	// `viewer/editor from account` cascade (the reconcile-sweep materializes per-object
	// CONTENT, NOT this binding-lifecycle pointer). Without it Get/Delete authz-DENY
	// (403) on the owner-binding object.
	var hierTuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type        = 'fga.tuple.write'
		    AND payload->>'user'     = 'account:' || $1
		    AND payload->>'relation' = 'account'
		    AND payload->>'object'   = 'iam_access_binding:' || $2`,
		string(acc.ID), string(bID)).Scan(&hierTuples))
	assert.Equal(t, 1, hierTuples,
		"backfill must queue exactly one owner-binding hierarchy parent-pointer "+
			"account:<A>#account@iam_access_binding:<id> (no-access-loss, КФ-БАГ-2)")

	// Idempotent: the hierarchy-tuple emit de-dupes on the payload NOT EXISTS guard.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type        = 'fga.tuple.write'
		    AND payload->>'user'     = 'account:' || $1
		    AND payload->>'relation' = 'account'
		    AND payload->>'object'   = 'iam_access_binding:' || $2`,
		string(acc.ID), string(bID)).Scan(&hierTuples))
	assert.Equal(t, 1, hierTuples,
		"re-running backfill must NOT duplicate the hierarchy parent-pointer intent (H-02)")
}

// ── reconcile-backfill sweep materializes per-object tuples ────────
//
// After owner-binding backfill, the per-object owner tuples on account:<A> are NOT
// yet in the ledger (the migration creates only the binding row — content is
// materialized FORWARD). The reconcile-sweep (singleton RunOnce) reconciles
// EVERY active binding through the single materialization path → the ledger fills.

func TestP8_02_ReconcileSweep_MaterializesPerObjectTuples(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8sweep")
	acc := seedAccount(t, ctx, repo, "p8-sweep-acc", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	bID := ownerBindingID(t, ctx, pool, acc.ID)

	// Pre-sweep: owner-binding exists but its scope-self tuples are NOT materialized.
	require.Equal(t, 0, ledgerTupleCount(t, ctx, pool, bID),
		"owner-binding ledger empty before the reconcile sweep (forward materialization)")

	runner, _ := newBackfill(pool)
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, res.Executed, "the (only) RunOnce must execute the sweep")
	assert.GreaterOrEqual(t, res.BindingsReconciled, 1, "at least the owner-binding reconciled")

	// Post-sweep: the owner scope-self v_* tuples on account:<A> are in the ledger
	// (the `*.*.*` owner rule yields verb-bearing self verbs on the scope object).
	assert.Greater(t, ledgerTupleCount(t, ctx, pool, bID), 0,
		"reconcile sweep must materialize the owner-binding scope-self tuples (H-01)")
	obj := "account:" + string(acc.ID)
	user := "user:" + string(owner)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, user, "v_get", obj),
		"owner scope-self v_get on account:<A> materialized")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, user, "admin", obj),
		"owner scope-self admin tier on account:<A> materialized (write-authz anchor)")

	// idempotent: re-run the sweep → ledger count unchanged (partial-UNIQUE).
	before := ledgerTupleCount(t, ctx, pool, bID)
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, ledgerTupleCount(t, ctx, pool, bID),
		"re-running the sweep is idempotent — no new ledger rows (H-02/H-04)")
}

// ── singleton — N concurrent RunOnce → exactly one executes ─────

func TestP8_03_Singleton_ConcurrentRunOnce_ExactlyOneExecutes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8conc")
	acc := seedAccount(t, ctx, repo, "p8-conc-acc", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	bID := ownerBindingID(t, ctx, pool, acc.ID)

	// N runners over the SAME pool race RunOnce. The process-wide singleton
	// pg_advisory_xact_lock (NON-blocking try-lock) means exactly one acquires
	// the lock and executes the sweep; the others skip (Executed=false). No
	// duplicate ledger rows regardless.
	const n = 6
	var executed int32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner, _ := newBackfill(pool)
			res, rerr := runner.RunOnce(ctx)
			if rerr != nil {
				errs <- rerr
				return
			}
			if res.Executed {
				atomic.AddInt32(&executed, 1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&executed),
		"exactly ONE concurrent RunOnce executes the singleton backfill (КФ-1/H-05)")

	// The single execution materialized the ledger exactly once (no dup tuples).
	var dups int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) - count(DISTINCT (fga_user, relation, object))
		   FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bID)).Scan(&dups))
	assert.Equal(t, 0, dups, "no duplicate ledger tuples after concurrent backfill (partial-UNIQUE)")
}

// ── chunked tx-size — sweep splits work into bounded chunks ──────────

func TestP8_04_ChunkedTxSizeBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Seed several owner-bindings (multiple accounts) → more bindings than ChunkSize.
	const accounts = 5
	for i := 0; i < accounts; i++ {
		o := mustSeedUser(t, ctx, pool, "p8chunk"+string(rune('a'+i)))
		seedAccount(t, ctx, repo, "p8-chunk-acc-"+string(rune('a'+i)), o)
	}
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	runner, _ := newBackfill(pool) // ChunkSize=2 from newBackfill
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, res.Executed)
	assert.GreaterOrEqual(t, res.BindingsReconciled, accounts,
		"every owner-binding reconciled across chunks")
	// with ChunkSize=2 and ≥5 bindings, the sweep used ≥3 chunks (no single
	// monster tx). Each binding still reconciles in its OWN reconcile writer-tx, so
	// the per-binding tx is naturally bounded; Chunks reports the listing batches.
	assert.GreaterOrEqual(t, res.Chunks, 3, "work split into bounded chunks (КФ-5)")
}

// ── forward-aware verify-gate — no-access-loss + forward-smoke ──

func TestP8_05_VerifyGate_NoAccessLoss_ForwardSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8verify")
	member := mustSeedUser(t, ctx, pool, "p8verifymem")
	acc := seedAccount(t, ctx, repo, "p8-verify-acc", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "p8-verify-prj")
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	// A REGULAR ARM_ANCHOR selector binding (vpc.network get, all) on the project —
	// the implemented + bounded forward path the verify-gate smokes with a matching
	// selector; the owner `*.*.*` content-forward is a separate contract-phase
	// concern, NOT smoked here.
	selRole := seedAccountRulesRole(t, ctx, pool, repo, acc.ID, "p8_net_viewer",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	selBinding := insertThinBindingScope(t, ctx, repo, member, selRole, "project", string(prj.ID), domain.ScopeProject)

	runner, gate := newBackfill(pool)
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)

	// Verify-gate: every active binding's explicit tuples are materialized
	// (no-access-loss) AND a forward-smoke on a freshly-created resource confirms
	// the forward path is live (gate for the contract phase).
	report, err := gate.Verify(ctx)
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss,
		"verify-gate must report 100%% no-access-loss before contract is permitted (КФ-4)")
	assert.Empty(t, report.Failures, "no binding without materialized explicit tuples")
	assert.GreaterOrEqual(t, report.BindingsChecked, 2, "owner-binding + selector binding checked")

	// Forward-smoke: a vpc.network created in the project AFTER the grant must be
	// picked up by the forward path (ReconcileObject on its mirror change) — the
	// selector binding's ARM_ANCHOR rule materializes its tuple.
	fresh := ids.NewID("net")
	smoke, err := gate.ForwardSmoke(ctx, seed.ForwardSmokeSpec{
		ExpectBinding: selBinding,
		ObjectType:    "vpc.network",
		ObjectID:      fresh,
		ParentProject: string(prj.ID),
		ParentAccount: string(acc.ID),
	})
	require.NoError(t, err)
	assert.True(t, smoke, "live forward-smoke on a fresh resource passes (КФ-4/H-06 gate)")

	// Belt-and-braces: the selector binding's ledger now records the fresh object's
	// tuple (the smoke removed the synthetic mirror row, but the ledger persists).
	assert.True(t, ledgerHasTuple(t, ctx, pool, selBinding, "user:"+string(member), "v_get", "vpc_network:"+fresh),
		"forward-materialization recorded the fresh resource tuple in the selector binding ledger (H-06)")
}

// ── revoked owner-binding must NOT block re-grant on backfill ───
//
// backfillOwnerBindingsSQL used a DETERMINISTIC id 'acb'||substr(md5('owner-binding:'
// ||a.id),1,17) with ON CONFLICT (id) DO NOTHING. If an account's owner-binding was
// previously REVOKED (the row survives as a tombstone carrying that exact id with
// revoked_at set), the NOT EXISTS(... revoked_at IS NULL) guard correctly finds NO
// active owner-binding and yields the row to insert — but the INSERT then collides
// with the tombstone PK and DO NOTHING silently drops it → the account is left with
// NO active owner-binding (no-access-loss hole). The fix must re-create an ACTIVE
// owner-binding whenever none exists, regardless of a revoked tombstone.
func TestReview15_RevokedOwnerBinding_BackfillRecreatesActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv15own")
	acc := seedAccount(t, ctx, repo, "acc-rv15", owner)

	// First backfill creates the owner-binding (deterministic id).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID), "owner-binding created by first backfill")
	revokedID := ownerBindingID(t, ctx, pool, acc.ID)

	// Revoke it (tombstone: status=REVOKED, revoked_at set) — leaving the deterministic
	// id occupied. This is exactly the state TransitionStatus/Delete produces.
	_, err = pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings SET status='REVOKED', revoked_at=now() WHERE id=$1`,
		string(revokedID))
	require.NoError(t, err)
	require.Equal(t, 0, activeOwnerBindingCount(t, ctx, pool, acc.ID), "no ACTIVE owner-binding after revoke")

	// Re-run the backfill. It MUST re-create an ACTIVE owner-binding for the account
	// (the revoked tombstone must not suppress the re-grant).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	assert.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"revoked owner-binding must be re-created as ACTIVE on backfill (no-access-loss, review #15)")

	// The new active owner-binding is a DISTINCT row from the revoked tombstone.
	newID := ownerBindingID(t, ctx, pool, acc.ID)
	assert.NotEqual(t, revokedID, newID,
		"re-grant uses a fresh id, not the revoked deterministic id (idempotency via active-grant partial-UNIQUE)")

	// Idempotent: a second backfill with an active owner-binding present adds nothing.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	assert.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"backfill remains idempotent once an ACTIVE owner-binding exists (H-02)")
}

// ── Verify must flag a binding that SHOULD materialize ≥1 member ──
//
//	but produced 0 (a wholesale reconcile failure the active_members-derived Verify
//	was blind to). An ACTIVE account-scoped OWNER binding ALWAYS materializes ≥1 member
//	(its scope-self member on account:<A> — the owner `*.*` role's ScopeSelfVerbs are
//	non-empty and the account is always contained in its own scope), so an owner
//	binding with 0 ACTIVE members is unambiguously a reconcile failure — computable
//	without false positives. Verify now flags it.
func TestReview16_Verify_FlagsOwnerBindingWithZeroMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv16own")
	acc := seedAccount(t, ctx, repo, "acc-rv16", owner)

	// Owner-binding created but NEVER reconciled → 0 ACTIVE target members. The old
	// Verify (ExpectsTuples = active_members>0) read this as "expects nothing" and
	// passed it silently — a wholesale-reconcile-failure blind spot.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingID(t, ctx, pool, acc.ID)
	require.Equal(t, 0, ledgerTupleCount(t, ctx, pool, ownerBID),
		"precondition: owner-binding not yet reconciled (empty ledger / no members)")

	runner, gate := newBackfill(pool)
	report, err := gate.Verify(ctx)
	require.NoError(t, err)

	assert.False(t, report.NoAccessLoss,
		"Verify must FAIL: an owner-binding that should materialize ≥1 member produced 0 (review #16)")
	var flagged bool
	for _, f := range report.Failures {
		if f.BindingID == ownerBID {
			flagged = true
		}
	}
	assert.True(t, flagged, "the un-reconciled owner-binding must be listed as a failure (review #16)")

	// After the reconcile-sweep materializes every owner-binding's scope-self member
	// (incl. the seeded kacho-system account's owner-binding), Verify is clean — no
	// owner-binding is left with 0 members.
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, ledgerTupleCount(t, ctx, pool, ownerBID), 1,
		"sweep reconciled the owner-binding (scope-self member + ledger present)")

	report2, err := gate.Verify(ctx)
	require.NoError(t, err)
	assert.True(t, report2.NoAccessLoss,
		"after the reconcile-sweep every owner-binding has ≥1 member → Verify passes (review #16)")
	for _, f := range report2.Failures {
		assert.NotEqual(t, ownerBID, f.BindingID, "reconciled owner-binding must no longer be flagged")
	}
}

var _ = reconcile.New // keep the reconcile import referenced if a test path changes
