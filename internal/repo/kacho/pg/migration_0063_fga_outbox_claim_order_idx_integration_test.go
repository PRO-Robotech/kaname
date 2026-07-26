// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0063_fga_outbox_claim_order_idx_integration_test.go
//
// Pins the index set kacho_iam.fga_outbox must carry for the drainer's
// partition-head-only CLAIM to stay constant-cost in backlog depth
// (pkg/outbox/drainer Config.PartitionColumn documents BOTH indexes as required).
//
// WHY a migration-side test on top of the drainer's plan test: the drainer proves
// "given both indexes the claim does not scale with the queue", against its own
// mirror of this schema. Nothing else proves the SHIPPED table actually has them.
// Migration 0061 supplied only the correlated-NOT-EXISTS index and the outer
// ORDER BY (attempt_count, id) went unindexed — so the planner never reached the
// nested-loop anti-join 0061 was built for, seq-scanned the whole pending backlog
// twice per claim, and the drain rate fell as the backlog grew (throughput
// inversion: 11.7ms per claim at 5k pending, 327ms at 80k, measured on a live
// stand). That gap was invisible precisely because no test tied the migration to
// the claim it serves. This test is that tie.

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

func TestMigration0063_FGAOutbox_CarriesBothClaimIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Both indexes are PARTIAL on `sent_at IS NULL` so their size tracks only the
	// pending backlog, never the append-mostly table. Asserting on the rendered
	// indexdef pins the actual access path (key columns + partiality) rather than an
	// index NAME, which a rename could drift away from silently. Matching by
	// substrings (not one exact rendering) tolerates Postgres's parenthesisation of
	// expression keys while still failing if a key column or the partiality is lost.
	for _, tc := range []struct {
		name     string
		what     string
		keyDesc  string
		contains []string
	}{
		{
			name:    "partition_head",
			what:    "correlated NOT EXISTS — partition-predecessor lookup (migration 0067)",
			keyDesc: "(tuple_key, id)",
			contains: []string{
				"btree (tuple_key, id)",
				"WHERE (sent_at IS NULL)",
			},
		},
		{
			name:    "claim_order",
			what:    "outer ordered scan ORDER BY (attempt_count, id) (migration 0063)",
			keyDesc: "(attempt_count, id)",
			contains: []string{
				"btree (attempt_count, id)",
				"WHERE (sent_at IS NULL)",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cnt int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM pg_indexes
				  WHERE schemaname = 'kacho_iam'
				    AND tablename  = 'fga_outbox'
				    AND indexdef LIKE ALL (
				        SELECT '%' || needle || '%' FROM unnest($1::text[]) AS needle)`,
				tc.contains,
			).Scan(&cnt))

			require.Equal(t, 1, cnt,
				"kacho_iam.fga_outbox must carry exactly one partial index %s WHERE sent_at IS NULL "+
					"(%s), found %d. The drainer claim needs BOTH indexes: with only one, Postgres "+
					"cannot produce the claim's order from an index, falls back to a double seq-scan "+
					"of the whole pending backlog, and the drain gets slower the deeper the queue it "+
					"must drain. See pkg/outbox/drainer Config.PartitionColumn.",
				tc.keyDesc, tc.what, cnt)
		})
	}
}

// TestMigration0064_FGAOutbox_KeepsStatisticsFresh pins the per-table autovacuum
// settings that let the planner actually CHOOSE the indexes above.
//
// The indexes are necessary but not sufficient. The claim filters on
// `sent_at IS NULL`, and the planner's estimate for that predicate comes from the
// last ANALYZE. A queue table is empty almost all the time, so the last analyze
// almost always ran on an EMPTY backlog and the estimate carried into a burst is
// `rows=1` — on which the planner discards both partial indexes and picks a nested
// loop that re-scans the pending set per candidate row. Measured on a live stand,
// the same claim on the same table: 4488ms with statistics gathered on an empty
// queue (2495 pending) versus 3.6ms right after ANALYZE (7849 pending — a DEEPER
// backlog). Autovacuum's default trigger (50 + 0.1 * n_live_tup ≈ 21751 rows
// there) is larger than an entire burst, so without these settings statistics stay
// frozen exactly across the window where the plan matters.
func TestMigration0064_FGAOutbox_KeepsStatisticsFresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var reloptions []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(c.reloptions, '{}')
		   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'kacho_iam' AND c.relname = 'fga_outbox'`,
	).Scan(&reloptions))

	// reloptions come back as "key=value" strings; compare NUMERICALLY so the
	// assertion does not depend on how a given Postgres spells the stored float
	// ("0" vs "0.0").
	opts := make(map[string]float64, len(reloptions))
	for _, kv := range reloptions {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		opts[k] = f
	}

	// scale_factor=0 decouples the trigger from table SIZE (an append-mostly outbox
	// outgrows any percentage-based threshold); the fixed threshold ties it to
	// absolute churn instead. The threshold is asserted as an upper bound, not an
	// exact value — tuning it DOWN keeps the guarantee, raising it past a burst's
	// worth of churn silently restores the stale-statistics plan.
	for _, want := range []struct {
		key    string
		atMost float64
	}{
		{"autovacuum_analyze_scale_factor", 0},
		{"autovacuum_analyze_threshold", 1000},
		{"autovacuum_vacuum_scale_factor", 0},
		{"autovacuum_vacuum_threshold", 1000},
	} {
		got, ok := opts[want.key]
		require.True(t, ok,
			"kacho_iam.fga_outbox must pin %s so the planner's `sent_at IS NULL` estimate is "+
				"refreshed during a burst rather than frozen at the empty-queue snapshot. "+
				"Without it the claim indexes exist but the planner will not choose them under "+
				"backlog, and the drain degrades to O(backlog) again. got reloptions=%v",
			want.key, reloptions)
		require.LessOrEqual(t, got, want.atMost,
			"kacho_iam.fga_outbox %s=%v is too high: statistics would go stale for more than a "+
				"burst's worth of churn, and the claim falls back to the O(backlog) plan under "+
				"exactly the backlog it must drain.", want.key, got)
	}
}
