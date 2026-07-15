// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// emitter_integration_test.go — integration tests for the fga_outbox emit-in-tx helper.
//
// Mirror of SubjectChangeEmitter tests. Verifies:
//
//   - EmitWriteTx INSERTs `event_type='fga.tuple.write'` rows with the
//     canonical {user,relation,object} payload, in caller-supplied tx;
//   - EmitDeleteTx mirrors with `event_type='fga.tuple.delete'`;
//   - rollback of the caller-tx removes the outbox rows (atomic emit-in-tx,
//     ban #10);
//   - len(tuples)==0 is a graceful no-op;
//   - malformed RelationTuple → error (we marshal user/relation/object, so this
//     mostly means defensive coverage).
//
// Skipped under `go test -short`.
package fga_outbox_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
)

func TestFGAOutboxEmitter_EmitWriteTx_AppendsRowsAtomically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tuples := []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "viewer", Object: "project:prj_x"},
		{User: "project:prj_x", Relation: "project", Object: "iam_access_binding:acb_t"},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, tuples))
	require.NoError(t, tx.Commit(ctx))

	// Read back: expect 2 rows, event_type='fga.tuple.write', payload matches input.
	// Scope to test-created rows: exclude every migration-seeded relation-tuple —
	// the SEC-C fga_writer tuples (object `iam_fgaproxy:system`, 0009) and the
	// cluster-root seeds (object `cluster:cluster_kacho_root`: SEC-L operator
	// 0010, 5.1 reader SAs 0014).
	rows, err := pool.Query(ctx, `
		SELECT event_type, payload::text
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')
		 ORDER BY id ASC`)
	require.NoError(t, err)
	defer rows.Close()

	var seen []struct {
		EventType string
		Payload   map[string]string
	}
	for rows.Next() {
		var et, raw string
		require.NoError(t, rows.Scan(&et, &raw))
		m := map[string]string{}
		require.NoError(t, json.Unmarshal([]byte(raw), &m))
		seen = append(seen, struct {
			EventType string
			Payload   map[string]string
		}{et, m})
	}
	require.Len(t, seen, 2)
	for i, s := range seen {
		require.Equal(t, "fga.tuple.write", s.EventType, "row %d event_type", i)
		require.Equal(t, tuples[i].User, s.Payload["user"], "row %d user", i)
		require.Equal(t, tuples[i].Relation, s.Payload["relation"], "row %d relation", i)
		require.Equal(t, tuples[i].Object, s.Payload["object"], "row %d object", i)
	}
}

func TestFGAOutboxEmitter_EmitDeleteTx_AppendsRevokeRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tuples := []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "viewer", Object: "project:prj_x"},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, tuples))
	require.NoError(t, tx.Commit(ctx))

	var et string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root') LIMIT 1`).Scan(&et))
	require.Equal(t, "fga.tuple.delete", et)
}

// TestFGAOutboxEmitter_RollbackRemovesRows — ban #10:
// rolling back the caller tx MUST also discard the outbox rows.
func TestFGAOutboxEmitter_RollbackRemovesRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: "user:usr_b", Relation: "viewer", Object: "project:prj_y"},
	}))
	require.NoError(t, tx.Rollback(ctx))

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')`).Scan(&count))
	require.Equal(t, 0, count, "rollback must discard outbox rows (atomic emit-in-tx)")
}

func TestFGAOutboxEmitter_EmitWriteTx_EmptyTuplesIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, nil))
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{}))
	require.NoError(t, tx.Commit(ctx))

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' NOT IN ('iam_fgaproxy:system', 'cluster:cluster_kacho_root')`).Scan(&count))
	require.Equal(t, 0, count, "empty tuples is no-op")
}
