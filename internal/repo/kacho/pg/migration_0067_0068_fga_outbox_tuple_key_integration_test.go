// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0067_0068_fga_outbox_tuple_key_integration_test.go
//
// Pins the SHIPPED shape of kacho_iam.fga_outbox that the drainer's
// partition-head-only claim depends on:
//
//   0067 — the ordering partition key is materialised into a `tuple_key` column by a
//          BEFORE INSERT trigger and indexed for the claim's correlated NOT EXISTS.
//   0099 — that key is the GRANT identity (user, object), not the triple: one row
//          carries a subject's WHOLE relation set on one object, so the partition has
//          to cover every row the set can be ordered against. The COLUMN NAME is
//          historical — renaming it would break the claim query of any pod still on
//          the previous release, which turns a rollout into a stalled drainer.
//   0068 — there is NO OTHER partial index over `sent_at IS NULL`, because any
//          further ordering of the pending rows is a decoy the planner takes under
//          the empty-queue statistics a queue table carries into a burst.
//
// WHY a migration-side test on top of the drainer's own plan tests: the drainer
// proves "given THIS shape the claim orders per tuple and stays cheap", against its
// own mirror of the schema. Nothing else proves the shipped table has that shape —
// exactly the gap that let migration 0061 ship an index the planner never used.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// TestMigration0067_FGAOutbox_TupleKeyPartition asserts the column, the trigger
// that fills it for every writer, and the partial index the claim seeks on.
func TestMigration0067_FGAOutbox_TupleKeyPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	t.Run("column_exists", func(t *testing.T) {
		var dataType string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT data_type FROM information_schema.columns
			  WHERE table_schema='kacho_iam' AND table_name='fga_outbox' AND column_name='tuple_key'`,
		).Scan(&dataType),
			"kacho_iam.fga_outbox must carry the tuple_key ordering-partition column (migration 0067)")
		assert.Equal(t, "text", dataType)
	})

	// The trigger is the single source of truth for ALL emit sites — the Go
	// emitters, the access_binding writer, the boot backfill and the data
	// migrations. A per-caller computation would drift the moment one of them
	// forgot, and a drifted key silently splits one tuple across partitions, which
	// is the ordering hole this whole mechanism exists to close.
	t.Run("trigger_fills_key_for_every_writer", func(t *testing.T) {
		var got string
		require.NoError(t, pool.QueryRow(ctx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ('fga.tuple.write',
			         '{"user":"user:usr01","relation":"v_get","object":"vpc_network:net01"}'::jsonb,
			         now())
			 RETURNING tuple_key`,
		).Scan(&got))
		assert.Equal(t, "user:usr01 vpc_network:net01", got,
			"the BEFORE INSERT trigger must render `user object` — the GRANT key (migration "+
				"0099). The drainer's claim compares this value between rows, so a different "+
				"rendering per writer would put two events of ONE grant into two partitions "+
				"and drop the ordering between a grant and its revoke. It must NOT include the "+
				"relation: one row carries a subject's whole relation set, and a key naming a "+
				"single relation would split that row's own successors away from it.")
	})

	// The set form of the row must key exactly like the single-relation form: both are
	// events on ONE grant, and they are ordered against each other or they are not
	// ordered at all.
	t.Run("trigger_keys_the_set_form_the_same", func(t *testing.T) {
		var got string
		require.NoError(t, pool.QueryRow(ctx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ('fga.tuple.write',
			         '{"user":"user:usr01","object":"vpc_network:net01","relation":"v_get","relations":["v_get","v_update"]}'::jsonb,
			         now())
			 RETURNING tuple_key`,
		).Scan(&got))
		assert.Equal(t, "user:usr01 vpc_network:net01", got,
			"a set row and a single-relation row naming the same (subject, object) must land "+
				"in the SAME partition — otherwise a revoke of the set could be applied ahead "+
				"of the grant it supersedes and the tuple would survive its own removal")
	})

	// A payload missing a component cannot produce a key, and a NULL key never
	// blocks a successor (NULL = NULL is not true) — such a row would silently opt
	// out of ordering. The NOT VALID check turns that into a loud failure at emit
	// time instead.
	t.Run("incomplete_payload_rejected_at_emit", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ('fga.tuple.write', '{"relation":"v_get","object":"vpc_network:net01"}'::jsonb, now())`)
		require.Error(t, err,
			"a tuple payload missing a component must be rejected at INSERT: it cannot yield "+
				"a partition key, and a NULL-keyed row silently escapes the ordering predicate")
		assert.Contains(t, err.Error(), "fga_outbox_tuple_key_present_check")
	})

	t.Run("partition_head_index_on_tuple_key", func(t *testing.T) {
		var cnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_indexes
			  WHERE schemaname='kacho_iam' AND tablename='fga_outbox'
			    AND indexdef LIKE '%btree (tuple_key, id)%'
			    AND indexdef LIKE '%WHERE (sent_at IS NULL)%'`,
		).Scan(&cnt))
		require.Equal(t, 1, cnt,
			"the claim's correlated NOT EXISTS seeks (tuple_key, id) over the PENDING rows; "+
				"without this partial index it degrades to scanning the backlog per candidate")
	})

	t.Run("object_partition_index_removed", func(t *testing.T) {
		var cnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_indexes
			  WHERE schemaname='kacho_iam' AND tablename='fga_outbox'
			    AND indexdef LIKE '%payload ->> ''object''%'`,
		).Scan(&cnt))
		assert.Zero(t, cnt,
			"migration 0061's object-keyed partition index is superseded by 0067 and nothing "+
				"reads it; an unused index on a queue table is write amplification on every "+
				"INSERT and every sent_at UPDATE")
	})
}

// TestMigration0068_FGAOutbox_NoDecoyPendingIndex is the general form of the
// 0068 drop: the table carries EXACTLY the two partial indexes the claim needs and
// no third ordering of the pending rows.
//
// This is not tidiness. The claim's efficiency rests on the LIMIT stopping an
// index-ordered scan after the first few partition heads. A queue table is empty
// almost all the time, so its last ANALYZE almost always ran on an empty backlog
// and the estimate carried INTO a burst is `rows=1` — on which a Sort is free, and
// ANY partial index over the pending rows in another order gives the planner a
// cheap-looking unordered scan to sort. That plan must materialise the whole
// pending set before the LIMIT applies, so the anti-join runs once per pending row.
// Measured on a live stand at 8 600 pending rows, same statement, sole difference
// being the extra (created_at) index: 6 990 ms per claim with it, 29 ms without.
func TestMigration0068_FGAOutbox_NoDecoyPendingIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var defs []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(array_agg(indexdef ORDER BY indexname), '{}')
		   FROM pg_indexes
		  WHERE schemaname='kacho_iam' AND tablename='fga_outbox'
		    AND indexdef LIKE '%WHERE (sent_at IS NULL)%'`,
	).Scan(&defs))

	assert.Lenf(t, defs, 2,
		"kacho_iam.fga_outbox must carry EXACTLY two partial indexes over the pending rows — "+
			"(tuple_key, id) for the claim's partition-head lookup and (attempt_count, id) for "+
			"its outer ordered scan. Every additional ordering of `sent_at IS NULL` is a decoy "+
			"the planner takes under empty-queue statistics, which destroys the LIMIT's early "+
			"stop and makes the claim read the whole queue it is draining. got: %v", defs)

	joined := ""
	for _, d := range defs {
		joined += d + "\n"
	}
	assert.NotContains(t, joined, "(created_at)",
		"the (created_at) WHERE sent_at IS NULL index (migration 0001) is the decoy 0068 "+
			"removes; nothing reads it — the oldest-pending metric aggregates the whole table "+
			"with FILTER clauses and no WHERE, and the wedge scan groups by the partition key")
}
