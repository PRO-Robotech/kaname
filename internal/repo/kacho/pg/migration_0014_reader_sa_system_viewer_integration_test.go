// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0014_reader_sa_system_viewer_integration_test.go — system_viewer seed
// verification for internal-reader module SAs.
//
// Migration 0014 seeds, via kacho_iam.fga_outbox, the cluster-level read-only
// relation `service_account:<sva>#system_viewer@cluster:cluster_kacho_root` for
// the legitimate internal-reader module SAs (api-gateway / vpc / compute) so
// they pass the SystemViewerFloor on the :9091 READ-RPCs in production-mode.
//
// vpc-operator is NOT seeded by 0014 (already seeded by SEC-L migration 0010,
// reviewer-decision Q2) — scenario 08 asserts no-conflict / no-duplicate.
//
// Asserts (mirror of migration_0010 SEC-L test, byte-for-byte payload shape):
//   - exactly one outbox row per {api-gateway, vpc, compute} with relation
//     `system_viewer`, object cluster:cluster_kacho_root, subject = the
//     deterministic sva-id ('sva'||substr(md5('kacho-<svc>'),1,17)).
//   - the seed grants ONLY system_viewer — no editor/admin/owner/fga_writer
//     for these reader SAs (least-priv, INV-FLOOR-4).
//   - re-applying the migration set leaves exactly ONE row per SA (idempotent
//     ON CONFLICT DO NOTHING).
//   - vpc-operator has exactly one system_viewer row (from 0010), un-duplicated.
//   - down 0014 removes exactly its 3 intents; 0010's operator row + 0009's
//     fga_writer tuples are untouched (ban #5).

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

// readerSysViewerSubjectSQL pins the deterministic sva-id for a module svc,
// mirroring the seed migration's own expression.
func readerSysViewerSubjectSQL(svc string) string {
	return `'service_account:' || ('sva' || substr(md5('kacho-` + svc + `'), 1, 17))`
}

// reader SAs seeded by 0014 (vpc-operator excluded — SEC-L 0010 owns it).
var migration0014ReaderSvcs = []string{"api-gateway", "vpc", "compute"}

func TestMigration0014_5_1_SeedsReaderSAsSystemViewer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // applies migrations 0001..0014
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	for _, svc := range migration0014ReaderSvcs {
		var cnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE event_type = 'fga.tuple.write'
			    AND payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user'     = `+readerSysViewerSubjectSQL(svc)).Scan(&cnt))
		require.Equal(t, 1, cnt,
			"migration 0014 must seed exactly one system_viewer@cluster tuple for %q", svc)

		// Least-priv (INV-FLOOR-4): no editor/admin/owner/fga_writer for this SA.
		var overGrant int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE payload->>'user' = `+readerSysViewerSubjectSQL(svc)+`
			    AND payload->>'object' = 'cluster:cluster_kacho_root'
			    AND payload->>'relation' IN ('editor','admin','owner','fga_writer')`).Scan(&overGrant))
		require.Equal(t, 0, overGrant,
			"reader SA %q must be granted system_viewer ONLY (no editor/admin/owner/fga_writer)", svc)
	}

	// vpc-operator is seeded by 0010, not 0014: exactly one row, no duplication
	// (scenario 08 — no-conflict regression guard).
	var opCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'relation' = 'system_viewer'
		    AND payload->>'object'   = 'cluster:cluster_kacho_root'
		    AND payload->>'user'     = `+readerSysViewerSubjectSQL("vpc-operator")).Scan(&opCnt))
	require.Equal(t, 1, opCnt,
		"vpc-operator must have exactly one system_viewer tuple (from 0010, not duplicated by 0014)")
}

// TestMigration0014_5_1_Idempotent_DownReverts drives a raw goose cycle:
// re-up = idempotent (exactly one row per reader SA); down 0014 removes ONLY its
// 3 intents; 0010's operator row + 0009's fga_writer tuples remain (ban #5).
func TestMigration0014_5_1_Idempotent_DownReverts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // already at 0014
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	readerCount := func() int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user' IN (
			        `+readerSysViewerSubjectSQL("api-gateway")+`,
			        `+readerSysViewerSubjectSQL("vpc")+`,
			        `+readerSysViewerSubjectSQL("compute")+`)`).Scan(&c))
		return c
	}
	operatorCount := func() int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user'     = `+readerSysViewerSubjectSQL("vpc-operator")).Scan(&c))
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

	require.Equal(t, 3, readerCount(), "baseline: 3 reader system_viewer tuples after up (api-gateway/vpc/compute)")
	require.Equal(t, 1, operatorCount(), "baseline: 1 operator system_viewer tuple (SEC-L 0010)")
	require.Equal(t, 4, fgaWriterCount(),
		"at HEAD: 0009 seeds 3 fga_writer tuples (vpc/compute/nlb) + 0044 seeds the registry-SA tuple")

	// Re-up the whole set: ON CONFLICT DO NOTHING keeps it stable (idempotent).
	require.NoError(t, goose.Up(db, "."))
	require.Equal(t, 3, readerCount(), "re-apply must remain idempotent (3 reader rows)")
	require.Equal(t, 1, operatorCount(), "re-apply must not duplicate the operator row")

	// Down to version 13 → reverts every migration stacked at/above 0014 (0014
	// itself, plus any later migration). DownTo(13) is robust to head drift (a
	// bare goose.Down only reverts the current HEAD). After it, the 3 reader
	// intents (0014) are gone; the operator tuple (0010) + fga_writer (0009) stay.
	require.NoError(t, goose.DownTo(db, ".", 13))
	require.Equal(t, 0, readerCount(), "down 0014 must remove the 3 reader system_viewer tuples")
	require.Equal(t, 1, operatorCount(),
		"down 0014 must NOT touch the operator system_viewer tuple (SEC-L 0010, ban #5)")
	require.Equal(t, 3, fgaWriterCount(),
		"down 0014 must NOT touch 0009 fga_writer tuples (ban #5)")
}
