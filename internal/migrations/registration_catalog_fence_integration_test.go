// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// verifies https://github.com/PRO-Robotech/kaname/issues/983
func registrationCatalogWrites(t *testing.T, ctx context.Context, tx pgx.Tx) int64 {
	t.Helper()
	var n int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT n_tup_upd FROM pg_stat_xact_user_tables WHERE relid='kaname.catalog_resource'::regclass`).Scan(&n))
	return n
}

func registrationCatalogXmin(t *testing.T, ctx context.Context, tx pgx.Tx) string {
	t.Helper()
	var xmin string
	require.NoError(t, tx.QueryRow(ctx, `SELECT xmin::text FROM kaname.catalog_resource WHERE dotted='registry.registries' AND live`).Scan(&xmin))
	return xmin
}

// Physical writes, not elapsed time or implementation text: one top-level
// transaction registers eight real objects and recolors their raw projections.
func TestRegistrationCatalogFence_PhysicalWrites(t *testing.T) {
	ctx, _, writer, _ := registrationRRDB(t)
	tx, err := writer.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	start := registrationCatalogWrites(t, ctx, tx)
	for i := 0; i < 8; i++ {
		_, err = tx.Exec(ctx, registrationRRCommand, fmt.Sprintf("catalog-fence-%d", i))
		require.NoError(t, err)
	}
	afterRegister := registrationCatalogWrites(t, ctx, tx)
	_, err = tx.Exec(ctx, `UPDATE kaname.resource_mirror SET labels='{"fence":"recolor"}' WHERE object_id LIKE 'catalog-fence-%'`)
	require.NoError(t, err)
	afterMirror := registrationCatalogWrites(t, ctx, tx)
	_, err = tx.Exec(ctx, `UPDATE kaname.resource_parent_edge SET updated_at=clock_timestamp() WHERE object_id LIKE 'catalog-fence-%'`)
	require.NoError(t, err)
	afterEdge := registrationCatalogWrites(t, ctx, tx)
	var mirrors, bindings, edges, bad int
	require.NoError(t, tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_id LIKE 'catalog-fence-%' AND labels='{"fence":"recolor"}'),
 (SELECT count(*) FROM kaname.object_project_binding WHERE object_id LIKE 'catalog-fence-%' AND project_id='registrationRR-P'),
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id LIKE 'catalog-fence-%'),
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id LIKE 'catalog-fence-%' AND parent_type='project' AND parent_id<>'registrationRR-P')`).Scan(&mirrors, &bindings, &edges, &bad))
	require.Equal(t, 8, mirrors)
	require.Equal(t, 8, bindings)
	require.Equal(t, 16, edges)
	require.Zero(t, bad)
	// Non-fatal assertions retain all three real baseline failure counts.
	t.Logf("catalog updates registration=%d raw-mirror=%d raw-edge=%d", afterRegister-start, afterMirror-afterRegister, afterEdge-afterMirror)
	if afterRegister-start > 2 {
		t.Errorf("eight registrations rewrote the same protected catalog row %d times; want at most 2", afterRegister-start)
	}
	if afterMirror != afterRegister {
		t.Errorf("raw recolor rewrote protected catalog: delta=%d", afterMirror-afterRegister)
	}
	if afterEdge != afterMirror {
		t.Errorf("raw edge rewrote protected catalog: delta=%d", afterEdge-afterMirror)
	}
}

func TestRegistrationCatalogFence_SavepointsAndReuse(t *testing.T) {
	for _, mode := range []string{"child_rollback", "outer_survives_rollback", "child_release", "active_child"} {
		t.Run(mode, func(t *testing.T) {
			ctx, _, writer, _ := registrationRRDB(t)
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			if mode == "outer_survives_rollback" {
				_, err = tx.Exec(ctx, registrationRRCommand, "outer-fence")
				require.NoError(t, err)
			}
			before := registrationCatalogXmin(t, ctx, tx)
			_, err = tx.Exec(ctx, `SAVEPOINT fence_child`)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, registrationRRCommand, "child-fence")
			require.NoError(t, err)
			child := registrationCatalogXmin(t, ctx, tx)
			var top string
			require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::xid::text`).Scan(&top))
			if mode != "outer_survives_rollback" {
				require.NotEqual(t, top, child, "subtransaction tuple is not top-level ownership")
			}
			if mode == "child_release" {
				_, err = tx.Exec(ctx, `RELEASE SAVEPOINT fence_child`)
			} else if mode != "active_child" {
				_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT fence_child`)
				require.NoError(t, err)
				require.Equal(t, before, registrationCatalogXmin(t, ctx, tx), "rolled-back tuple cannot remain a witness")
				_, err = tx.Exec(ctx, `RELEASE SAVEPOINT fence_child`)
			}
			require.NoError(t, err)
			n := registrationCatalogWrites(t, ctx, tx)
			_, err = tx.Exec(ctx, registrationRRCommand, "after-child")
			require.NoError(t, err)
			delta := registrationCatalogWrites(t, ctx, tx) - n
			if mode == "outer_survives_rollback" {
				require.Zero(t, delta, "surviving top-level tuple remains protected")
			} else {
				require.Positive(t, delta, "missing/top-unproven witness requires real fallback write")
			}
		})
	}
	t.Run("same_connection_new_transaction", func(t *testing.T) {
		ctx, _, writer, _ := registrationRRDB(t)
		for i := 0; i < 2; i++ {
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			n := registrationCatalogWrites(t, ctx, tx)
			_, err = tx.Exec(ctx, registrationRRCommand, fmt.Sprintf("reuse-%d", i))
			require.NoError(t, err)
			require.Positive(t, registrationCatalogWrites(t, ctx, tx)-n)
			require.NoError(t, tx.Commit(ctx))
		}
	})
}

func TestRegistrationCatalogFence_RawEdgeAllCatalogRows(t *testing.T) {
	ctx, observer, writer, _ := registrationRRDB(t)
	_, err := observer.Exec(ctx, `INSERT INTO kaname.catalog_resource(module,resource,dotted,object_type,live,retired_at,retired_reason)
 VALUES ('registry','fence_alias','registry.fence_alias','registry_registry',false,now(),'test retired alias')`)
	require.NoError(t, err)
	tx, err := writer.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(ctx, registrationRREdge, "raw-all-rows", "registrationRR-P")
	require.NoError(t, err)
	var total, owned int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE xmin=pg_current_xact_id()::xid) FROM kaname.catalog_resource WHERE object_type='registry_registry'`).Scan(&total, &owned))
	require.Equal(t, 2, total)
	require.Equal(t, total, owned, "both live and retired matching rows are fenced")
	n := registrationCatalogWrites(t, ctx, tx)
	_, err = tx.Exec(ctx, registrationRREdge, "raw-all-rows-second", "registrationRR-P")
	require.NoError(t, err)
	require.Equal(t, n, registrationCatalogWrites(t, ctx, tx), "every matching row already owned, no redundant rewrite")
}

func TestRegistrationCatalogFence_DifferentTypesAndInvalidSecondCall(t *testing.T) {
	ctx, _, writer, _ := registrationRRDB(t)
	tx, err := writer.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(ctx, registrationRRCommand, "first-type")
	require.NoError(t, err)
	var other string
	require.NoError(t, tx.QueryRow(ctx, `SELECT dotted FROM kaname.catalog_resource WHERE live AND dotted<>'registry.registries' ORDER BY dotted LIMIT 1`).Scan(&other))
	n := registrationCatalogWrites(t, ctx, tx)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.resource_registration_command(dotted_type,object_id,parent_project_id,parent_account_id,source_version) VALUES ($1,'other-type','','',now())`, other)
	require.NoError(t, err)
	require.Positive(t, registrationCatalogWrites(t, ctx, tx)-n, "another type has its own first physical fence")
	_, err = tx.Exec(ctx, `SAVEPOINT invalid_second`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.resource_registration_command(dotted_type,object_id,parent_project_id,parent_account_id,source_version,parent_chain) VALUES ('registry.registries','first-type','registrationRR-Q','registrationRR-A',now(),ARRAY['project:registrationRR-Q'])`)
	require.Equal(t, "23", registrationRRState(err)[:2], "ownership does not authorize conflicting second payload")
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT invalid_second`)
	require.NoError(t, err)
	var project string
	require.NoError(t, tx.QueryRow(ctx, `SELECT project_id FROM kaname.object_project_binding WHERE object_id='first-type'`).Scan(&project))
	require.Equal(t, "registrationRR-P", project)
}

func TestRegistrationCatalogFence_DownUpAndXidEpoch(t *testing.T) {
	ctx, _, writer, _ := registrationRRDB(t)
	var low string
	require.NoError(t, writer.QueryRow(ctx, `SELECT '4294967301'::xid8::xid::text`).Scan(&low))
	require.Equal(t, "5", low, "PostgreSQL conversion discards the epoch, not decimal digits")
	body, err := migrations.FS.ReadFile("20261031150000_registration_reuses_its_catalog_fence.sql")
	require.NoError(t, err)
	parts := strings.Split(string(body), "-- +goose Down")
	require.Len(t, parts, 2)
	for _, up := range []bool{false, true} {
		sql := parts[1]
		if up {
			sql = parts[0]
		}
		_, err = writer.Exec(ctx, sql)
		require.NoError(t, err)
		tx, err := writer.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(ctx, registrationRRCommand, "roundtrip-first")
		require.NoError(t, err)
		n := registrationCatalogWrites(t, ctx, tx)
		_, err = tx.Exec(ctx, registrationRRCommand, "roundtrip-second")
		require.NoError(t, err)
		delta := registrationCatalogWrites(t, ctx, tx) - n
		if up {
			require.Zero(t, delta, "Up reuses the surviving catalog tuple")
		} else {
			require.Positive(t, delta, "Down restores the original physical write")
		}
		require.NoError(t, tx.Rollback(ctx))
	}
}
