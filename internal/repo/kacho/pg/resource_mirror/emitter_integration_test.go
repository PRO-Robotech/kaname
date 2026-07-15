// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// emitter_integration_test.go — integration tests for the resource_mirror
// emit-in-tx helper. Mirror of the fga_outbox emitter tests.
//
// Verifies (DB-side):
//   - UpsertTx INSERTs/UPSERTs one row per (object_type, object_id) with the
//     labels + parent_* copied from the owner payload;
//   - rollback of the caller tx discards the row (atomic emit-in-tx, ban #10);
//   - repeat UpsertTx of the same key does not duplicate (PK, idempotent);
//   - changed labels on the same key are overwritten last-write (mirror side);
//   - empty labels payload lands as '{}';
//   - DeleteTx removes the row by (object_type, object_id).
//
// Skipped under `go test -short`.
package resource_mirror_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
)

func TestResourceMirror_UpsertTx_InsertsRowAtomically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      "compute.instance",
		ObjectID:        "inst-abc",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		Labels:          map[string]string{"env": "dev", "team": "core"},
	}))
	require.NoError(t, tx.Commit(ctx))

	gotType, gotPrj, gotAcc, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-abc")
	require.Equal(t, "compute.instance", gotType)
	require.Equal(t, "prj-P", gotPrj)
	require.Equal(t, "acc-A", gotAcc)
	require.Equal(t, map[string]string{"env": "dev", "team": "core"}, gotLabels)
}

func TestResourceMirror_UpsertTx_EmptyLabelsLandsAsObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      "compute.instance",
		ObjectID:        "inst-nolabels",
		ParentProjectID: "prj-P",
		Labels:          nil, // legacy / no-labels caller
	}))
	require.NoError(t, tx.Commit(ctx))

	_, gotPrj, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-nolabels")
	require.Equal(t, "prj-P", gotPrj)
	require.Equal(t, map[string]string{}, gotLabels, "nil labels persists as JSONB '{}'")
}

func TestResourceMirror_UpsertTx_RollbackDiscardsRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-rollback", ParentProjectID: "prj-P",
	}))
	require.NoError(t, tx.Rollback(ctx))

	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-rollback"),
		"rollback must discard the mirror row (atomic emit-in-tx, ban #10)")
}

func TestResourceMirror_UpsertTx_RepeatDoesNotDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	row := resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-dup", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"},
	}
	upsertCommitted(t, ctx, pool, row)
	upsertCommitted(t, ctx, pool, row) // repeat — drainer retry (β-06)

	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-dup"),
		"PK (object_type,object_id) ⇒ exactly one row on repeat")
}

// Two DISTINCT source-states (monotonically increasing source_version) → the
// newer one's labels win (last-SOURCE-state-wins). Updated from the
// pre-hardening "last-applier-wins" form, which carried no version: under the new
// conditional UPSERT two genuine source mutations carry distinct emit-versions.
func TestResourceMirror_UpsertTx_OverwritesLabelsLastWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v1 := time.Now().Truncate(time.Microsecond)
	v2 := v1.Add(time.Second)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-upd", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, SourceVersion: v1,
	})
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-upd", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod", "team": "core"}, SourceVersion: v2,
	})

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-upd")
	require.Equal(t, map[string]string{"env": "prod", "team": "core"}, gotLabels, "newer source-state wins (UPSERT)")
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-upd"))
}

// TestResourceMirror_UpsertTx_StaleSourceVersionIsNoop — the mirror UPSERT must
// be last-SOURCE-state-wins, not
// last-APPLIER-wins. Under an HA register-drainer two register-intents for ONE
// object can be applied out of order (replica B applies v2, then replica A
// applies the stale v1). Apply v2-labels first, then the stale v1 → the mirror
// must KEEP v2-labels (the stale v1 is a no-op, not an error: at-least-once OK).
//
// Without the conditional `WHERE source_version < EXCLUDED.source_version`
// guard the second UPSERT would last-applier-win → v1 overwrites v2.
func TestResourceMirror_UpsertTx_StaleSourceVersionIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v1 := time.Now().Truncate(time.Microsecond)
	v2 := v1.Add(time.Second)

	// Apply the NEWER state first (v2-labels), as the reordered HA-drainer would.
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-reorder", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, SourceVersion: v2,
	})
	// Now the STALE older register-intent (v1-labels) arrives — must be a no-op.
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-reorder", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, SourceVersion: v1,
	})

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-reorder")
	require.Equal(t, map[string]string{"env": "prod"}, gotLabels,
		"last-source-state-wins: stale v1 register must NOT overwrite the already-applied v2")
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-reorder"))
}

// TestResourceMirror_UpsertTx_SameSourceVersionIsIdempotentNoop — a repeated
// register-intent carrying the SAME source_version (drainer retry of one intent)
// must be a no-op, not an error and not a spurious update (at-least-once).
func TestResourceMirror_UpsertTx_SameSourceVersionIsIdempotentNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v := time.Now().Truncate(time.Microsecond)
	row := resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-idem-ver", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, SourceVersion: v,
	}
	upsertCommitted(t, ctx, pool, row)
	upsertCommitted(t, ctx, pool, row) // drainer retry of the SAME intent

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-idem-ver")
	require.Equal(t, map[string]string{"env": "prod"}, gotLabels)
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-idem-ver"))
	require.Equal(t, v.UTC(), readMirrorVersion(t, ctx, pool, "compute.instance", "inst-idem-ver").UTC())
}

// TestResourceMirror_UpsertTx_NewerSourceVersionApplies — the in-order case:
// a register-intent strictly NEWER than the stored version overwrites labels and
// advances source_version (the normal label-sync path still works).
func TestResourceMirror_UpsertTx_NewerSourceVersionApplies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v1 := time.Now().Truncate(time.Microsecond)
	v2 := v1.Add(time.Second)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-newer", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, SourceVersion: v1,
	})
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-newer", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod", "team": "core"}, SourceVersion: v2,
	})

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-newer")
	require.Equal(t, map[string]string{"env": "prod", "team": "core"}, gotLabels, "newer source_version applies")
	require.Equal(t, v2.UTC(), readMirrorVersion(t, ctx, pool, "compute.instance", "inst-newer").UTC())
}

// TestResourceMirror_DeleteTx_StaleTombstoneDoesNotWipeFreshRow — Delete-after-
// Update reorder: an unregister tombstone OLDER than the stored register must NOT
// wipe the fresh mirror row (the row reflects a newer state than the tombstone).
//
// DeleteTx is conditional `WHERE source_version <= $tombstone`.
func TestResourceMirror_DeleteTx_StaleTombstoneDoesNotWipeFreshRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	older := time.Now().Truncate(time.Microsecond)
	newer := older.Add(time.Second)

	// Stored register reflects the NEWER state (v2).
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-stale-del", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, SourceVersion: newer,
	})
	// A STALE tombstone (older than the stored register) arrives — must be a no-op.
	deleteCommitted(t, ctx, pool, "compute.instance", "inst-stale-del", older)

	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-stale-del"),
		"stale tombstone must NOT wipe a fresher mirror row")
}

// TestResourceMirror_DeleteTx_FreshTombstoneRemovesRow — the in-order Delete:
// an unregister tombstone >= the stored register version removes the row.
func TestResourceMirror_DeleteTx_FreshTombstoneRemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	regV := time.Now().Truncate(time.Microsecond)
	delV := regV.Add(time.Second)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-fresh-del", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, SourceVersion: regV,
	})
	deleteCommitted(t, ctx, pool, "compute.instance", "inst-fresh-del", delV)

	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-fresh-del"),
		"a tombstone >= the stored register version removes the row")
}

func TestResourceMirror_DeleteTx_RemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-del", ParentProjectID: "prj-P",
	})
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-del"))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, resource_mirror.DeleteTx(ctx, tx, "compute.instance", "inst-del", time.Time{}))
	require.NoError(t, tx.Commit(ctx))

	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-del"))
}

func TestResourceMirror_DeleteTx_AbsentIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	require.NoError(t, resource_mirror.DeleteTx(ctx, tx, "compute.instance", "inst-absent", time.Time{}),
		"delete of absent row must be OK (idempotent, β-07/D-β5)")
	require.NoError(t, tx.Commit(ctx))
}

// ── helpers ──────────────────────────────────────────────────────────────────

func upsertCommitted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, row resource_mirror.Row) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, resource_mirror.UpsertTx(ctx, tx, row))
	require.NoError(t, tx.Commit(ctx))
}

func deleteCommitted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string, tombstone time.Time) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, resource_mirror.DeleteTx(ctx, tx, objType, objID, tombstone))
	require.NoError(t, tx.Commit(ctx))
}

func readMirrorVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) time.Time {
	t.Helper()
	var v time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT source_version FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&v))
	return v
}

func readMirror(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) (gotType, prj, acc string, labels map[string]string) {
	t.Helper()
	var raw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT object_type, parent_project_id, parent_account_id, labels::text
		   FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`, objType, objID).
		Scan(&gotType, &prj, &acc, &raw))
	labels = map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(raw), &labels))
	return gotType, prj, acc, labels
}

func countMirror(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&n))
	return n
}
