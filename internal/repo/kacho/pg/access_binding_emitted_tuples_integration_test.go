// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_emitted_tuples_integration_test.go — emitted-tuple ledger tests.
//
// testcontainers Postgres 16 integration tests for the persisted emitted-tuple
// ledger (kacho_iam.access_binding_emitted_tuples, migration 0024) that makes
// AccessBinding revoke + Role.Update reconcile byte-symmetric to the grant:
//
//   - -COMMIT: InsertEmittedTuples co-committed with EmitRelationWrite +
//     SelectEmittedTuples reads back the EXACT set (round-trip).
//   - -CASCADE: deleting the binding row CASCADE-drops its emitted-tuple rows
//     (FK ON DELETE CASCADE) — no orphan ledger rows after revoke.
//   - -REPLACE: ReplaceEmittedTuples wholesale-replaces the set (reconcile path).
//   - -ROLLBACK: a rolled-back writer-tx leaves NO ledger row (atomic emit-in-tx,
//     ban #10).
//   - -RACE: concurrent Role.Update-style ReplaceEmittedTuples ∥ revoke Delete on
//     the SAME binding serialize to a consistent terminal state — either the
//     binding is gone (CASCADE cleared the ledger, zero orphan rows) or it
//     survived with exactly the replaced set; never a half-state.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	reconcileapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func emittedTuplesCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bindingID domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bindingID)).Scan(&n))
	return n
}

// seedABForEmitted creates a real access_bindings row (account-scoped) so the
// emitted-tuple FK has a parent to reference.
func seedABForEmitted(t *testing.T, ctx context.Context, repo *kachopg.Repository, uid domain.UserID, accID domain.AccountID) domain.AccessBinding {
	t.Helper()
	return insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer",
		ResourceType: "account",
		ResourceID:   string(accID),
	})
}

// TestABEmittedTuples_B14_ConcurrentScopeGrantLedger_OneTupleSet — RBAC
// rules-model 2026 concurrency mandate for the scope_grant emitted-set.
//
// The scope_grant emitted-set (rulesBindingTuples output for an ARM_NAMES /
// ARM_ANCHOR rule) is persisted via InsertEmittedTuples with PK (binding_id,
// fga_user, relation, object) + ON CONFLICT DO NOTHING. N goroutines that
// concurrently persist the IDENTICAL scope_grant tuple-set for the same binding
// must converge to EXACTLY that one set — no duplicate rows, no second-writer
// inflation (ban #10, DB-level idempotency, not software check-then-act).
func TestABEmittedTuples_B14_ConcurrentScopeGrantLedger_OneTupleSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "b14")
	acc := seedAccount(t, ctx, repo, "acc-b14", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// The scope_grant tuple-set an ARM_NAMES {vpc.address,[get,update],addr5k} rule
	// emits: per-object per-verb tuples + the back-compat tier tuple. Identical
	// across all goroutines (the realistic concurrent re-grant shape).
	scopeGrantSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_address:addr5k"},
		{User: "user:" + string(uid), Relation: "v_update", Object: "vpc_address:addr5k"},
		{User: "user:" + string(uid), Relation: "editor", Object: "vpc_address:addr5k"},
	}

	const N = 8
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, ierr := repo.Writer(ctx)
			if ierr != nil {
				errs <- ierr
				return
			}
			if ierr := w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, scopeGrantSet); ierr != nil {
				_ = w.Rollback(ctx)
				errs <- ierr
				return
			}
			errs <- w.Commit(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "concurrent idempotent InsertEmittedTuples must not error (ON CONFLICT DO NOTHING)")
	}

	// Exactly the 3 tuples persist — no duplicate, no inflation under concurrency.
	require.Equal(t, len(scopeGrantSet), emittedTuplesCount(t, ctx, pool, ab.ID),
		"concurrent identical scope_grant ledger writes must converge to ONE tuple-set")
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, scopeGrantSet, got, "the converged set must be exactly the emitted scope_grant set")
}

func TestABEmittedTuples_178_InsertSelect_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em01")
	acc := seedAccount(t, ctx, repo, "acc-em01", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}

	// Co-commit the emit + the ledger in one writer-tx.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w.Commit(ctx))

	// Read back the exact set.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, tuples, got, "SelectEmittedTuples must return the exact persisted set")

	// Idempotent re-insert (ON CONFLICT DO NOTHING) does not duplicate.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w2.Commit(ctx))
	require.Equal(t, 2, emittedTuplesCount(t, ctx, pool, ab.ID), "re-insert must be idempotent (PK)")
}

func TestABEmittedTuples_178_DeleteBinding_CascadesLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em02")
	acc := seedAccount(t, ctx, repo, "acc-em02", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 1, emittedTuplesCount(t, ctx, pool, ab.ID))

	// Revoke (delete the binding row) → FK ON DELETE CASCADE clears the ledger.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w2.Commit(ctx))
	require.Equal(t, 0, emittedTuplesCount(t, ctx, pool, ab.ID),
		"deleting the binding must CASCADE-drop its emitted-tuple ledger rows (no orphan store rows)")
}

func TestABEmittedTuples_178_Replace_WholesaleSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em03")
	acc := seedAccount(t, ctx, repo, "acc-em03", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	oldSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}
	newSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, oldSet))
	require.NoError(t, w.Commit(ctx))

	// Reconcile: wholesale-replace admin → viewer.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, newSet))
	require.NoError(t, w2.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, newSet, got, "ReplaceEmittedTuples must wholesale-swap the ledger to the new set")
}

// TestABEmittedTuples_RoleUpdateReconcile_PreservesMemberTuples — RBAC
// rules-model 2026, CRITICAL ledger-source fix.
//
// The emitted-tuple ledger holds BOTH binding-level tuples (InsertEmittedTuples /
// the Role.Update RoleTupleReconciler via ReplaceEmittedTuples) AND ARM_LABELS
// per-member tuples (the per-member reconciler RecordEmittedTuples). A binding-level
// Role.Update reconcile (ReplaceEmittedTuples) MUST NOT revoke or wipe the
// per-member tuples — those are owned by RoleMembershipFanout, not the
// binding-level reconcile. Before the `source` split, ReplaceEmittedTuples did a
// `DELETE … WHERE binding_id` wholesale wipe, dropping the member rows on every
// rules-changing Role.Update of a custom role mixing a binding-level arm with an
// ARM_LABELS arm — transient (or, on a post-commit fan-out failure,
// durable-until-sweep) loss of label-selected access.
func TestABEmittedTuples_RoleUpdateReconcile_PreservesMemberTuples(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "emsrc")
	acc := seedAccount(t, ctx, repo, "acc-emsrc", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// (1) Binding-level emitted-set the RoleTupleReconciler owns (anchor/hierarchy).
	bindingLevel := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, bindingLevel))
	require.NoError(t, w.Commit(ctx))

	// (2) ARM_LABELS per-member tuples the per-member reconciler owns — written via the
	// PRODUCTION member-writer (RecordEmittedTuples), object-space <fga_type>:<id>.
	memberTuples := []domain.MembershipTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_subnet:sub-emsrc"},
		{User: "user:" + string(uid), Relation: "viewer", Object: "vpc_subnet:sub-emsrc"},
	}
	adapter := kachopg.NewReconcileAdapter(pool)
	require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcileapp.ReconcileStore) error {
		return s.RecordEmittedTuples(ctx, ab.ID, memberTuples)
	}))
	require.Equal(t, len(bindingLevel)+len(memberTuples), emittedTuplesCount(t, ctx, pool, ab.ID),
		"precondition: ledger holds both binding-level and member tuples")

	// (3) Role.Update reconcile: a binding-level tier change (admin → viewer) via
	// ReplaceEmittedTuples — exactly what RoleTupleReconciler does for a rules
	// change. It must replace ONLY the binding-level subset.
	newBindingLevel := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, newBindingLevel))
	require.NoError(t, w2.Commit(ctx))

	// (4) The ARM_LABELS per-member tuples MUST survive the binding-level reconcile.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)

	wantMember := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_subnet:sub-emsrc"},
		{User: "user:" + string(uid), Relation: "viewer", Object: "vpc_subnet:sub-emsrc"},
	}
	for _, m := range wantMember {
		require.Contains(t, got, m,
			"ARM_LABELS member tuple %v must NOT be wiped by a binding-level Role.Update reconcile", m)
	}
	// And the binding-level subset was replaced (admin gone, viewer present).
	require.Contains(t, got, repoab.RelationTuple{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)})
	require.NotContains(t, got, repoab.RelationTuple{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		"binding-level reconcile must still replace its own (admin → viewer) subset")
}

func TestABEmittedTuples_178_RollbackDiscardsLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em04")
	acc := seedAccount(t, ctx, repo, "acc-em04", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}))
	require.NoError(t, w.Rollback(ctx))
	require.Equal(t, 0, emittedTuplesCount(t, ctx, pool, ab.ID),
		"rolled-back writer-tx must leave NO ledger row (atomic emit-in-tx, ban #10)")
}

// TestABEmittedTuples_178_ConcurrentReplaceVsRevoke_Consistent — concurrent
// Role.Update-style ReplaceEmittedTuples ∥ revoke Delete on the SAME binding
// serialize on the binding row-lock / FK to a consistent terminal state: either
// the Delete won (binding gone, CASCADE cleared the ledger → 0 rows) or the
// Replace won and the Delete then dropped both (also 0 rows). The invariant: NO
// orphan ledger rows remain referencing a deleted binding, and no half-state.
func TestABEmittedTuples_178_ConcurrentReplaceVsRevoke_Consistent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em05")
	acc := seedAccount(t, ctx, repo, "acc-em05", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// Seed an initial emitted-set.
	wSeed, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, wSeed.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}))
	require.NoError(t, wSeed.Commit(ctx))

	var wg sync.WaitGroup
	wg.Add(2)
	// Goroutine A — reconcile (Role.Update fan-out): replace admin → viewer.
	go func() {
		defer wg.Done()
		w, e := repo.Writer(ctx)
		if e != nil {
			return
		}
		if e := w.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
			{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
		}); e != nil {
			_ = w.Rollback(ctx)
			return
		}
		_ = w.Commit(ctx)
	}()
	// Goroutine B — revoke: delete the binding (CASCADE drops the ledger).
	go func() {
		defer wg.Done()
		w, e := repo.Writer(ctx)
		if e != nil {
			return
		}
		if e := w.AccessBindingsW().Delete(ctx, ab.ID); e != nil {
			_ = w.Rollback(ctx)
			return
		}
		_ = w.Commit(ctx)
	}()
	wg.Wait()

	// Terminal invariant: if the binding row is gone, the ledger MUST be empty
	// (CASCADE). If it survived (replace committed, delete lost its row was still
	// present — but delete on an existing row never "loses"), the ledger holds the
	// replaced set. Either way: zero ROWS referencing a NON-existent binding.
	var bindingExists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM kacho_iam.access_bindings WHERE id = $1)`, string(ab.ID)).Scan(&bindingExists))
	ledger := emittedTuplesCount(t, ctx, pool, ab.ID)
	if !bindingExists {
		require.Equal(t, 0, ledger,
			"binding deleted ⇒ ledger MUST be CASCADE-cleared (no orphan rows)")
	} else {
		require.LessOrEqual(t, ledger, 1, "surviving binding holds at most the replaced single-tuple set")
	}
	// Orphan-row safety net: there must be ZERO ledger rows whose binding_id has
	// no matching access_bindings row.
	var orphans int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples e
		 WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.access_bindings ab WHERE ab.id = e.binding_id)`).Scan(&orphans))
	require.Equal(t, 0, orphans, "no emitted-tuple row may reference a non-existent binding (FK CASCADE invariant)")
}
