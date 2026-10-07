// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// emitter_integration_test.go — integration tests for the projection admission
// (resource_mirror.UpsertTx / DeleteTx → trigger `resource_event`).
//
// Verifies (DB-side):
//   - an applied registration writes one mirror row per (object_type, object_id) with
//     the labels + parent_* copied from the owner payload, and the head;
//   - rollback of the caller tx discards the row (atomic emit-in-tx, ban #10);
//   - a generation not newer than the head — equal, older, or not newer than the
//     tombstone of a withdrawal — writes nothing (REJECTED_STALE);
//   - empty labels payload lands as '{}';
//   - an applied withdrawal removes the row and leaves the tombstone.
//
// Skipped under `go test -short`.
package resource_mirror_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestResourceMirror_UpsertTx_InsertsRowAtomically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, upsertErr(resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      "compute.instance",
		ObjectID:        "inst-abc",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		Labels:          map[string]string{"env": "dev", "team": "core"},
		Generation:      1,
	})))
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
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, upsertErr(resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      "compute.instance",
		ObjectID:        "inst-nolabels",
		ParentProjectID: "prj-P",
		Labels:          nil, // no-labels caller
		Generation:      1,
	})))
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
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, upsertErr(resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-rollback", ParentProjectID: "prj-P",
		Generation: 1,
	})))
	require.NoError(t, tx.Rollback(ctx))

	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-rollback"),
		"rollback must discard the mirror row (atomic emit-in-tx, ban #10)")
}

func TestResourceMirror_UpsertTx_RepeatDoesNotDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	row := resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-dup", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, Generation: 1,
	}
	upsertCommitted(t, ctx, pool, row)
	upsertCommitted(t, ctx, pool, row) // repeat — drainer retry (β-06)

	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-dup"),
		"PK (object_type,object_id) ⇒ exactly one row on repeat")
}

// Two DISTINCT source-states (increasing generations) → the newer one's labels win.
func TestResourceMirror_UpsertTx_OverwritesLabelsLastWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-upd", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, Generation: 1,
	})
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-upd", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod", "team": "core"}, Generation: 2,
	})

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-upd")
	require.Equal(t, map[string]string{"env": "prod", "team": "core"}, gotLabels, "newer generation wins")
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-upd"))
	require.Equal(t, int64(2), readMirrorVersion(t, ctx, pool, "compute.instance", "inst-upd"))
	require.Equal(t, int64(2), readHead(t, ctx, pool, "compute.instance", "inst-upd"))
}

// TestResourceMirror_UpsertTx_OlderGenerationIsNoop — two register-intents for ONE
// object applied out of order (replica B applies g2, then replica A the stale g1): the
// stale one is REJECTED_STALE, the mirror keeps g2's labels — a no-op, not an error.
func TestResourceMirror_UpsertTx_OlderGenerationIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-reorder", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, Generation: 2,
	})
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-reorder", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "dev"}, Generation: 1,
	})

	_, _, _, gotLabels := readMirror(t, ctx, pool, "compute.instance", "inst-reorder")
	require.Equal(t, map[string]string{"env": "prod"}, gotLabels,
		"the stale g1 register must NOT overwrite the already-applied g2")
	require.Equal(t, int64(2), readHead(t, ctx, pool, "compute.instance", "inst-reorder"))
}

// TestResourceMirror_DeleteTx_StaleWithdrawalDoesNotWipeFreshRow — a withdrawal whose
// generation is not newer than the head (the object was re-registered past it) is
// REJECTED_STALE: the fresh row stays, the head is unchanged.
func TestResourceMirror_DeleteTx_StaleWithdrawalDoesNotWipeFreshRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-stale-del", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, Generation: 3,
	})
	require.False(t, deleteCommitted(t, ctx, pool, "compute.instance", "inst-stale-del", 2),
		"a withdrawal not newer than the head is not applied")

	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-stale-del"),
		"a stale withdrawal must NOT wipe a fresher mirror row")
	require.Equal(t, int64(3), readHead(t, ctx, pool, "compute.instance", "inst-stale-del"))
}

// TestResourceMirror_DeleteTx_LeavesATombstone — the in-order withdrawal removes the row
// and leaves the TOMBSTONE: a registration not newer than it does not bring the row
// back; a newer one does (twin by one fact).
func TestResourceMirror_DeleteTx_LeavesATombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	row := func(g int64) resource_mirror.Row {
		return resource_mirror.Row{
			ObjectType: "compute.instance", ObjectID: "inst-tomb", ParentProjectID: "prj-P",
			Labels: map[string]string{"env": "prod"}, Generation: g,
		}
	}
	upsertCommitted(t, ctx, pool, row(1))
	require.True(t, deleteCommitted(t, ctx, pool, "compute.instance", "inst-tomb", 2))
	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-tomb"))
	require.Equal(t, int64(2), readHead(t, ctx, pool, "compute.instance", "inst-tomb"), "the tombstone")

	upsertCommitted(t, ctx, pool, row(2))
	require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", "inst-tomb"),
		"a registration not newer than the tombstone does not bring the row back")

	upsertCommitted(t, ctx, pool, row(3))
	require.Equal(t, 1, countMirror(t, ctx, pool, "compute.instance", "inst-tomb"),
		"twin: a registration newer than the tombstone applies")
}

func TestResourceMirror_DeleteTx_AbsentObjectLeavesTheTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	require.True(t, deleteCommitted(t, ctx, pool, "compute.instance", "inst-absent", 5),
		"withdrawal of a never-registered object applies (idempotent, β-07/D-β5)")
	require.Equal(t, int64(5), readHead(t, ctx, pool, "compute.instance", "inst-absent"),
		"and leaves the tombstone a late registration must find")
}

// TestResourceMirror_ZeroGenerationIsRefused — there is no admission without a
// generation: the call refuses before the admission, and writes nothing.
func TestResourceMirror_ZeroGenerationIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-zero", ParentProjectID: "prj-P",
	})
	require.ErrorContains(t, err, "there is no admission without a generation")
	_, err = resource_mirror.DeleteTx(ctx, tx, "compute.instance", "inst-zero", 0)
	require.ErrorContains(t, err, "there is no admission without a generation")
}

// TestResourceMirror_ParentDerivedFromTheChainWhenColumnsAreEmpty — a registration with
// BOTH parent columns empty and a chain naming a project and an account gets them from
// the chain (nearest of each kind): a row with a chain and no columns is invisible to
// materialization (kacho#2051), and the producer — not a second writer — closes it.
// Twin by one fact: columns sent by the owner are kept as they are.
func TestResourceMirror_ParentDerivedFromTheChainWhenColumnsAreEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	chain := []string{"registry_registry:reg-1", "project:prj-chain", "account:acc-chain"}
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "registry.repositories", ObjectID: "reg-1/app", ParentChain: chain, Generation: 1,
	})
	_, prj, acc, _ := readMirror(t, ctx, pool, "registry.repositories", "reg-1/app")
	require.Equal(t, "prj-chain", prj, "project derived from the chain")
	require.Equal(t, "acc-chain", acc, "account derived from the chain")

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "registry.repositories", ObjectID: "reg-1/kept", ParentChain: chain,
		ParentProjectID: "prj-owner", Generation: 1,
	})
	_, prj, acc, _ = readMirror(t, ctx, pool, "registry.repositories", "reg-1/kept")
	require.Equal(t, "prj-owner", prj, "twin: the owner's column is kept")
	require.Equal(t, "", acc, "twin: nothing derived when the owner named a parent")
}

// TestResourceMirror_MalformedAncestorIsARefusalThatWritesNothing — a chain link that is
// not `"<type>:<id>"` is a REFUSAL, not a skip: a skipped link makes the chain shorter
// than the real one, and the object lands under an ancestor it is not under. The trigger
// refuses before the head is compared, so nothing — head, mirror, chain — is written.
// Twin: a colon inside the id is fine (the separator is the FIRST colon).
func TestResourceMirror_MalformedAncestorIsARefusalThatWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	bad := []string{"", "project", ":prj-abc", "project:"}
	for i, link := range bad {
		id := fmt.Sprintf("inst-badlink-%d", i)
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		_, err = resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
			ObjectType: "compute.instance", ObjectID: id, ParentChain: []string{link}, Generation: 1,
		})
		require.ErrorContains(t, err, "непонятая форма предка", "link %q", link)
		require.NoError(t, tx.Commit(ctx))
		require.Equal(t, 0, countMirror(t, ctx, pool, "compute.instance", id), "link %q: no mirror row", link)
		require.Equal(t, int64(0), readHead(t, ctx, pool, "compute.instance", id), "link %q: no head", link)
	}

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-goodlink",
		ParentChain: []string{"account:acc:weird"}, Generation: 1,
	})
	var parentID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT parent_id FROM kaname.resource_parent_edge
		 WHERE object_type = 'compute_instance' AND object_id = 'inst-goodlink' AND depth = 1`).Scan(&parentID))
	require.Equal(t, "acc:weird", parentID, "twin: the rest after the first colon is the id")
	t.Logf("осмотрено: непонятых звеньев %d, законных 1", len(bad))
}

// ── helpers ──────────────────────────────────────────────────────────────────

func upsertCommitted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, row resource_mirror.Row) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, upsertErr(resource_mirror.UpsertTx(ctx, tx, row)))
	require.NoError(t, tx.Commit(ctx))
}

func deleteCommitted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string, generation int64) bool {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	out, err := resource_mirror.DeleteTx(ctx, tx, objType, objID, generation)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return out.Applied
}

// readHead — поколение головы объекта; 0 — головы нет.
func readHead(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) int64 {
	t.Helper()
	var g int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce((SELECT generation FROM kaname.object_head
		                   WHERE object_type = $1 AND object_id = $2), 0)`, objType, objID).Scan(&g))
	return g
}

func readMirrorVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) int64 {
	t.Helper()
	var v int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT source_version FROM kaname.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&v))
	return v
}

func readMirror(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) (gotType, prj, acc string, labels map[string]string) {
	t.Helper()
	var raw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT object_type, parent_project_id, parent_account_id, labels::text
		   FROM kaname.resource_mirror
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
		`SELECT count(*) FROM kaname.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`, objType, objID).Scan(&n))
	return n
}

// upsertErr drops UpsertTx's `changed` flag so these slices — which assert the ROW state
// the statement leaves behind — read as before. The flag itself is contracted by
// TestResourceMirror_UpsertTx_ReportsWhetherRowChanged below.
func upsertErr(_ resource_mirror.Outcome, err error) error { return err }

// TestResourceMirror_UpsertTx_ReportsWhetherRowChanged pins the redelivery signal the
// register use-case gates on: the head's verdict, surfaced as `Applied`. A fresh
// registration and a strictly-newer one report true; an equal or older generation
// reports false, having written nothing.
func TestResourceMirror_UpsertTx_ReportsWhetherRowChanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	row := func(g int64, labels map[string]string) resource_mirror.Row {
		return resource_mirror.Row{
			ObjectType: "compute.instance", ObjectID: "inst-changed",
			ParentProjectID: "prj-P", Labels: labels, Generation: g,
		}
	}
	exec := func(r resource_mirror.Row) bool {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		out, err := resource_mirror.UpsertTx(ctx, tx, r)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return out.Applied
	}

	require.True(t, exec(row(2, map[string]string{"tier": "gold"})), "a fresh registration applies")
	require.False(t, exec(row(2, map[string]string{"tier": "gold"})),
		"an EQUAL generation writes nothing — the second delivery of an applied register")
	require.False(t, exec(row(1, map[string]string{"tier": "gold"})), "an OLDER generation writes nothing")
	require.True(t, exec(row(3, map[string]string{"tier": "bronze"})),
		"a strictly-NEWER generation applies — a real label update must never be gated away")
}

// TestResourceMirror_UpsertTx_ReportsWhetherProjectionWasReplaced pins the SECOND verdict
// — the one `Applied` cannot express: did an applied write REPLACE part of the projection
// a selector reads (parent-scope, labels), or did it only advance the generation?
//
// The distinction decides whether the caller may take the additive materialization path
// or must take the delete-stale one, i.e. whether a revoke gets applied. So both
// directions are pinned: a generation-only change reports unchanged, and EVERY projection
// edit reports replaced.
func TestResourceMirror_UpsertTx_ReportsWhetherProjectionWasReplaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	exec := func(r resource_mirror.Row) resource_mirror.Outcome {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		out, err := resource_mirror.UpsertTx(ctx, tx, r)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return out
	}
	row := func(g int64, prj, acc string, labels map[string]string) resource_mirror.Row {
		return resource_mirror.Row{
			ObjectType: "vpc.network", ObjectID: "net-projection",
			ParentProjectID: prj, ParentAccountID: acc, Labels: labels, Generation: g,
		}
	}
	gold := map[string]string{"tier": "gold", "env": "dev"}

	// A fresh registration had no stored projection to compare with: Applied without the
	// exemption, so the caller keeps its guarded path (conservative by construction).
	out := exec(row(1, "prj-P", "acc-A", gold))
	require.True(t, out.Applied, "a fresh registration applies")
	require.False(t, out.ProjectionUnchanged, "there was no stored projection to leave unchanged")

	// Newer generation, identical projection — including the same labels in a DIFFERENT
	// key order, which jsonb equality must not treat as a different projection.
	out = exec(row(2, "prj-P", "acc-A", map[string]string{"env": "dev", "tier": "gold"}))
	require.True(t, out.Applied, "a strictly-newer generation applies")
	require.True(t, out.ProjectionUnchanged,
		"a write that only advanced the generation replaced nothing — nothing materialized "+
			"from these facts can have gone stale")

	// A LABEL EDIT — the grant-matching label is dropped.
	out = exec(row(3, "prj-P", "acc-A", map[string]string{"tier": "bronze", "env": "dev"}))
	require.True(t, out.Applied)
	require.False(t, out.ProjectionUnchanged, "a label edit REPLACED the projection")

	// A MOVE to another parent — the second axis a selector reads.
	out = exec(row(4, "prj-Q", "acc-A", map[string]string{"tier": "bronze", "env": "dev"}))
	require.True(t, out.Applied)
	require.False(t, out.ProjectionUnchanged, "a parent-project move REPLACED the projection")

	out = exec(row(5, "prj-Q", "acc-B", map[string]string{"tier": "bronze", "env": "dev"}))
	require.True(t, out.Applied)
	require.False(t, out.ProjectionUnchanged, "a parent-account move REPLACED the projection")

	// A NOT-NEWER redelivery is not applied at all, and claims no exemption with it.
	out = exec(row(5, "prj-Q", "acc-B", map[string]string{"tier": "bronze", "env": "dev"}))
	require.False(t, out.Applied, "an equal generation writes nothing")
	require.False(t, out.ProjectionUnchanged, "a write that did not happen exempts nothing")
}
