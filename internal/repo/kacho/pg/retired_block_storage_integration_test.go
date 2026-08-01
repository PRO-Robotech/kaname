// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// retired_block_storage_integration_test.go — the effective-state half of the
// block-storage retire gate.
//
// services/iam/internal/check/retired_block_storage_test.go covers the artefacts
// in the tree: iam's four vocabularies, the canonical authorization model, the
// generated ConfigMap, the permission catalog. None of that can see a ROW. A
// vocabulary can be spotless while nine bindable system roles still name the
// resource, their wildcard selectors still expand onto it, and the reconciler is
// still handed mirror rows of that type — which is exactly the state the compute
// retire left behind.
//
// So this file asserts the schema a migrated database actually has, and it does it
// twice over, because the two questions are different:
//
//	after every migration — the seeded state carries no retired name any more;
//	on a re-run of the retiring migration — its statements REMOVE a retired row
//	that is present, and LEAVE a live one alone. A fresh database is empty of
//	retired rows whether or not the DELETE works, so the first assertion alone
//	would be satisfied by a migration that does nothing at all.
//
// Every assertion is paired with a positive control from the SAME module
// (compute.instance) or the present owner (storage.volumes): "the retired name is
// absent" is otherwise indistinguishable from "the table is empty" and from "the
// migration deleted more than it was supposed to".

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// retiredDottedTypes / retiredRoleNames — the block-storage identities iam has
// taken off its books. Mirrors services/iam/internal/check/retired_block_storage_test.go;
// duplicated deliberately so this gate fails on its own, without importing the
// package it guards.
var (
	retiredDottedTypes = []string{"compute.disk", "compute.image", "compute.snapshot"}
	retiredRoleNames   = []string{
		"compute.disk.admin", "compute.disk.edit", "compute.disk.view",
		"compute.image.admin", "compute.image.edit", "compute.image.view",
		"compute.snapshot.admin", "compute.snapshot.edit", "compute.snapshot.view",
	}
	// liveSiblingRoleNames — same module, still owned by compute. They are the
	// control that the retire was targeted: a migration that wiped every
	// `compute.%` role would pass the negative assertions and fail here.
	liveSiblingRoleNames = []string{"compute.instance.admin", "compute.instance.edit", "compute.instance.view"}
	// liveDottedTypes — types that must survive in the same columns.
	liveDottedTypes = []string{"compute.instance", "storage.volumes"}
)

func TestRetiredBlockStorageIsGoneFromMigratedSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Volume of what was inspected — "no retired row" must be distinguishable
	// from "no row at all".
	var totalRoles, totalSelectors int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.roles`).Scan(&totalRoles))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.role_rule_selectors`).Scan(&totalSelectors))
	require.NotZero(t, totalRoles, "no roles are seeded at all — this gate would assert nothing")
	require.NotZero(t, totalSelectors, "no role_rule_selectors rows exist at all — this gate would assert nothing")
	t.Logf("scanned: %d roles, %d role_rule_selectors rows", totalRoles, totalSelectors)

	// (1) No retired system role survives, and its live sibling does.
	for _, name := range retiredRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.roles WHERE name = $1`, name).Scan(&n))
		require.Zerof(t, n, "system role %q is still seeded and bindable — kacho-storage owns this resource; a grantable role for it is a promise the product cannot keep", name)
	}
	for _, name := range liveSiblingRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.roles WHERE name = $1`, name).Scan(&n))
		require.Equalf(t, 1, n, "system role %q is missing — the retire must remove the block-storage roles, not the module", name)
	}

	// (2) No selector expands onto a retired type; the live ones still do.
	for _, ty := range retiredDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE $1 = ANY(object_types)`, ty).Scan(&n))
		require.Zerof(t, n, "%d role_rule_selectors rows still select object type %q — the reconciler would materialize per-object tuples on a type no resource produces", n, ty)
	}
	for _, ty := range liveDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE $1 = ANY(object_types)`, ty).Scan(&n))
		require.NotZerof(t, n, "no role_rule_selectors row selects %q — the wildcard system-role selectors must keep the live types, or the negative half above proves nothing", ty)
	}

	// (3) Nothing may be granted on a retired role.
	for _, name := range retiredRoleNames {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kacho_iam.access_bindings b
			  JOIN kacho_iam.roles r ON r.id = b.role_id
			 WHERE r.name = $1`, name).Scan(&n))
		require.Zerof(t, n, "access_bindings still reference retired role %q", name)
	}

	// (4) resource_mirror carries no retired type. On a fresh database this is
	// vacuous by itself — TestRetireMigrationRemovesRetiredRowsOnly below is what
	// proves the statement behind it.
	for _, ty := range retiredDottedTypes {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.resource_mirror WHERE object_type = $1`, ty).Scan(&n))
		require.Zerof(t, n, "resource_mirror still holds rows of retired object type %q", ty)
	}
}

// retireMigrationPrefix — the migration under test. Named once so the gate moves
// with it.
const retireMigrationPrefix = "0074"

func TestRetireMigrationRemovesRetiredRowsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// A retired-type mirror row and a live-type one, side by side.
	seedRetireFixtureMirrorRow(t, ctx, pool, "compute.disk", "dsk-retired-fixture")
	seedRetireFixtureMirrorRow(t, ctx, pool, "compute.instance", "ins-live-fixture")
	seedRetireFixtureMirrorRow(t, ctx, pool, "storage.volumes", "vol-live-fixture")

	// A custom role whose selector names a retired type ALONGSIDE a live one. The
	// retire must strip the retired element and keep the row; dropping the whole
	// row would take the live type's materialization with it.
	owner := mustSeedUser(t, ctx, pool, "retiredbs")
	acc := seedAccount(t, ctx, kachopg.New(pool, nil), "retiredbs-acc", owner)
	mixedRole := seedCustomRoleSQL(t, ctx, pool, acc.ID, "retiredbs_mixed")
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, object_types, match_labels, arm, resource_names)
		VALUES ($1, 'fp_mixed', ARRAY['compute.disk','compute.instance'], '{"env":"prod"}'::jsonb, 'labels', '{}')`,
		mixedRole)
	require.NoError(t, err, "seed mixed selector")

	// A custom role whose selector names ONLY retired types: nothing is left to
	// select, and role_rule_selectors_types_nonempty forbids a zero-type row, so
	// the row itself must go.
	onlyRole := seedCustomRoleSQL(t, ctx, pool, acc.ID, "retiredbs_only")
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, object_types, match_labels, arm, resource_names)
		VALUES ($1, 'fp_only', ARRAY['compute.disk','compute.image'], '{"env":"prod"}'::jsonb, 'labels', '{}')`,
		onlyRole)
	require.NoError(t, err, "seed retired-only selector")

	// Re-run the REAL migration body (not a copy of it) against the seeded state.
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, applyMigrationUpBody(t, db, retireMigrationPrefix),
		"re-running the retire migration must be idempotent")

	// Mirror: the retired row is gone, the live ones are untouched.
	requireMirrorCount(t, ctx, pool, "compute.disk", "dsk-retired-fixture", 0)
	requireMirrorCount(t, ctx, pool, "compute.instance", "ins-live-fixture", 1)
	requireMirrorCount(t, ctx, pool, "storage.volumes", "vol-live-fixture", 1)

	// Mixed selector: kept, with the retired element removed and the live one left.
	var mixedTypes []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT object_types FROM kacho_iam.role_rule_selectors WHERE role_id = $1 AND rule_fp = 'fp_mixed'`,
		mixedRole).Scan(&mixedTypes))
	require.Equal(t, []string{"compute.instance"}, mixedTypes,
		"the retired element must be stripped and the live one kept — dropping the row would take the live type's materialization with it")

	// Retired-only selector: removed entirely (a zero-type row is forbidden).
	var onlyLeft int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1 AND rule_fp = 'fp_only'`,
		onlyRole).Scan(&onlyLeft))
	require.Zero(t, onlyLeft, "a selector left with no object type at all must be removed, not left violating role_rule_selectors_types_nonempty")
}

func seedRetireFixtureMirrorRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType, objectID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
		VALUES ($1, $2, '', '', '{}'::jsonb)`, objectType, objectID)
	require.NoError(t, err, "seed resource_mirror %s:%s", objectType, objectID)
}

func requireMirrorCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType, objectID string, want int) {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		objectType, objectID).Scan(&n))
	require.Equalf(t, want, n, "resource_mirror %s:%s", objectType, objectID)
}
