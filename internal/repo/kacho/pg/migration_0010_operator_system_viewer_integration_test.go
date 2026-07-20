// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0010_operator_system_viewer_integration_test.go — SEC-L.
//
// Migration 0010 seeds, via kacho_iam.fga_outbox, the operator-SA relation
// tuple `service_account:<op>#system_viewer@cluster:cluster_kacho_root` so the
// FGA-relation-driven AccountService.List / ProjectService.List return ALL
// accounts/projects to the kacho-vpc-operator ns-syncer.
//
// Asserts:
//   - the outbox row exists with exactly the SEC-L payload (relation
//     `system_viewer`, NOT `viewer`; object cluster:cluster_kacho_root; subject
//     = the deterministic operator-SA id, same expression as 0009).
//   - re-applying the migration set leaves exactly ONE such row (idempotent
//     ON CONFLICT DO NOTHING).
//   - the down migration removes it.
//   - 0009's fga_writer tuples are untouched (ban #5 — 0009 not edited).

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// operatorSysViewerSQL — the exact subject expression mirrored from 0009/0010
// so the test pins the deterministic operator-SA id.
const operatorSysViewerSubjectSQL = `'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17))`

func TestMigration0010_SECL_SeedsOperatorSystemViewerTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // applies migrations 0001..0010
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Exactly one outbox row with the SEC-L operator system_viewer tuple.
	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write'
		    AND payload->>'relation' = 'system_viewer'
		    AND payload->>'object'   = 'cluster:cluster_kacho_root'
		    AND payload->>'user'     = `+operatorSysViewerSubjectSQL).Scan(&cnt))
	require.Equal(t, 1, cnt,
		"migration 0010 must seed exactly one operator system_viewer@cluster tuple")

	// It must be `system_viewer`, never `viewer` (INV-6 over-exposure fix).
	var relCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = 'cluster:cluster_kacho_root'
		    AND payload->>'user'   = `+operatorSysViewerSubjectSQL+`
		    AND payload->>'relation' = 'viewer'`).Scan(&relCnt))
	require.Equal(t, 0, relCnt,
		"operator must be seeded system_viewer (NON-wildcard), never viewer (INV-6)")
}

// TestMigration0010_SECL_Idempotent_DownReverts drives a raw goose cycle
// (re-up = idempotent; down removes the tuple; 0009 fga_writer untouched).
func TestMigration0010_SECL_Idempotent_DownReverts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // already at 0010
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	count := func() int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user'     = `+operatorSysViewerSubjectSQL).Scan(&c))
		return c
	}
	fgaWriterCount := func() int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE payload->>'relation' = 'fga_writer'
			    AND payload->>'object'   = 'iam_fgaproxy:system'`).Scan(&c))
		return c
	}

	require.Equal(t, 1, count(), "baseline: one operator system_viewer tuple after up")
	require.Equal(t, 5, fgaWriterCount(),
		"at HEAD: 0009 seeds 3 fga_writer tuples (vpc/compute/nlb) + 0044 registry-SA + 0057 storage-SA tuples")

	// Re-up the whole set: ON CONFLICT DO NOTHING keeps it at one (idempotent).
	require.NoError(t, goose.Up(db, "."))
	require.Equal(t, 1, count(), "re-apply must remain idempotent (exactly one row)")

	// Down to version 9 → reverts every migration stacked at/above 0010 (0010
	// itself, plus any later migration that seeds onto the same fga_outbox, e.g.
	// 5.1's 0014). DownTo(9) is robust to head drift: a single goose.Down would
	// only revert the current HEAD (no longer 0010 once newer migrations land),
	// so it could not assert 0010's own down. After DownTo(9) the operator tuple
	// (0010) is removed; 0009's fga_writer tuples (version 9, the floor) remain.
	require.NoError(t, goose.DownTo(db, ".", 9))
	require.Equal(t, 0, count(), "down 0010 must remove the operator system_viewer tuple")
	require.Equal(t, 3, fgaWriterCount(),
		"0009 fga_writer tuples must remain untouched after 0010 down (ban #5)")
}
