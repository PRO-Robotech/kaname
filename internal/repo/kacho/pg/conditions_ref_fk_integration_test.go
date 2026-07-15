// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// conditions_ref_fk_integration_test.go — testcontainers Postgres tests for the
// migration 0048 DB-level enforcement of the named-Condition reference carried
// by access_binding_conditions (params ->> 'condition_id').
//
// Before 0048 the reference was a bare JSONB path with no FK, so Condition
// delete relied on a software count-then-delete refcheck (TOCTOU — hard-rule
// #10). These tests prove the reference is now enforced at the DB level:
//   - inserting an attach row that references a non-existent Condition → 23503;
//   - deleting a still-referenced Condition → 23503 (ON DELETE RESTRICT);
//   - a concurrent attach-vs-delete pair serializes so exactly one wins and no
//     dangling reference is ever left behind (the write-skew the old software
//     refcheck could not stop).

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestConditionRefFK_InsertDanglingReference_Rejected — an attach row whose
// params.condition_id points at a non-existent Condition is rejected by the FK
// (23503) instead of silently creating a dangling reference.
func TestConditionRefFK_InsertDanglingReference_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, abID, _, _ := kac127SeedABRow(t, ctx, pool, "crfk1", domain.AccessBindingStatusActive)

	missing := string(domain.ConditionID(ids.NewID(domain.PrefixConditionResource)))
	_, err := pool.Exec(ctx, `
		INSERT INTO access_binding_conditions (id, binding_id, expression, params)
		VALUES ($1, $2, 'mfa_fresh', jsonb_build_object('condition_id', $3::text))`,
		"cond_crfk1_dangling", abID, missing)
	require.Error(t, err, "attach referencing a non-existent Condition must be rejected")
	assertSQLState(t, err, "23503")
}

// TestConditionRefFK_DeleteReferencedCondition_Restricted — deleting a Condition
// that is still referenced by an attach row fails with 23503 (ON DELETE
// RESTRICT), atomically, instead of leaving the binding dangling.
func TestConditionRefFK_DeleteReferencedCondition_Restricted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, abID, _, _ := kac127SeedABRow(t, ctx, pool, "crfk2", domain.AccessBindingStatusActive)

	condID := string(domain.ConditionID(ids.NewID(domain.PrefixConditionResource)))
	_, err := pool.Exec(ctx, `
		INSERT INTO conditions (id, folder_id, name, expression, status)
		VALUES ($1, 'prj_crfk2', 'ref-cond', 'current_time < valid_until', 'ACTIVE')`,
		condID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO access_binding_conditions (id, binding_id, expression, params)
		VALUES ($1, $2, 'mfa_fresh', jsonb_build_object('condition_id', $3::text))`,
		"cond_crfk2_attach", abID, condID)
	require.NoError(t, err, "attach referencing a live Condition must succeed")

	_, err = pool.Exec(ctx, `DELETE FROM conditions WHERE id=$1`, condID)
	require.Error(t, err, "deleting a referenced Condition must be restricted")
	assertSQLState(t, err, "23503")

	// Condition survives — no partial delete.
	var cnt int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM conditions WHERE id=$1`, condID).Scan(&cnt))
	require.Equal(t, 1, cnt)
}

// TestConditionRefFK_ConcurrentAttachVsDelete_ExactlyOneWins — the TOCTOU proof.
// One tx attaches (references cond_x) and holds the FK KEY-SHARE lock on the
// conditions row; a concurrent tx tries to DELETE cond_x. Without the FK the
// delete proceeds immediately and leaves a dangling reference (the 2026-era
// software refcheck race). With the FK the delete blocks on the lock, and once
// the attach commits the delete hits ON DELETE RESTRICT → 23503. Exactly one
// outcome; the Condition survives and the reference stays valid.
func TestConditionRefFK_ConcurrentAttachVsDelete_ExactlyOneWins(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, abID, _, _ := kac127SeedABRow(t, ctx, pool, "crfk3", domain.AccessBindingStatusActive)

	condID := string(domain.ConditionID(ids.NewID(domain.PrefixConditionResource)))
	_, err := pool.Exec(ctx, `
		INSERT INTO conditions (id, folder_id, name, expression, status)
		VALUES ($1, 'prj_crfk3', 'race-cond', 'current_time < valid_until', 'ACTIVE')`,
		condID)
	require.NoError(t, err)

	// txAttach: insert the attach row referencing cond_x, but do NOT commit yet —
	// it now holds a FOR KEY SHARE lock on the conditions row via the FK.
	txAttach, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = txAttach.Exec(ctx, `
		INSERT INTO access_binding_conditions (id, binding_id, expression, params)
		VALUES ($1, $2, 'mfa_fresh', jsonb_build_object('condition_id', $3::text))`,
		"cond_crfk3_attach", abID, condID)
	require.NoError(t, err)

	// txDelete: attempt to delete cond_x on a separate connection. It must BLOCK
	// on txAttach's key-share lock (proving the FK serialization), not complete.
	txDelete, err := pool.Begin(ctx)
	require.NoError(t, err)
	delErr := make(chan error, 1)
	go func() {
		_, e := txDelete.Exec(ctx, `DELETE FROM conditions WHERE id=$1`, condID)
		delErr <- e
	}()

	// Deterministic barrier: block until the delete is registered as waiting on a
	// lock (positive signal that it started AND is blocked) — not a fixed sleep.
	requireDeleteBlocked(t, ctx, pool, condID)

	select {
	case e := <-delErr:
		t.Fatalf("DELETE completed without blocking on the attach lock (FK absent): err=%v", e)
	default:
	}

	// Commit the attach → the delete unblocks and hits ON DELETE RESTRICT.
	require.NoError(t, txAttach.Commit(ctx))

	e := <-delErr
	require.Error(t, e, "concurrent DELETE of a now-referenced Condition must fail")
	assertSQLState(t, e, "23503")
	_ = txDelete.Rollback(ctx)

	// Invariant: attach won, Condition survives, reference is intact.
	var condCnt, refCnt int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM conditions WHERE id=$1`, condID).Scan(&condCnt))
	require.Equal(t, 1, condCnt, "Condition must survive the lost delete")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM access_binding_conditions WHERE condition_id=$1`, condID).Scan(&refCnt))
	require.Equal(t, 1, refCnt, "the surviving attach must reference the live Condition")
}

// requireDeleteBlocked polls pg_stat_activity until a DELETE on conditions is
// waiting on a lock, giving a deterministic barrier in place of a fixed sleep.
func requireDeleteBlocked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, condID string) {
	t.Helper()
	_ = condID
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE state = 'active'
			   AND wait_event_type = 'Lock'
			   AND query ILIKE 'DELETE FROM conditions%'`).Scan(&n)
		return err == nil && n >= 1
	}, 10*time.Second, 25*time.Millisecond, "DELETE never became lock-blocked")
}
