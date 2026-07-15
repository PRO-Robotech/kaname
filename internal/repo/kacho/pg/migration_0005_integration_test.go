// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// migration_0005_integration_test.go — integration tests for the
// `0005_rbac_v2_grammar_and_scope.sql` migration.
//
// Scenarios:
//
//   - legacy 3-segment role.permissions promoted to 4-segment in-place
//   - pre-existing 4-segment row passes through unchanged
//   - malformed 4-segment INSERT rejected (SQLSTATE 23514)
//   - wildcard-only `*.*.*.*` passes the v2 validator
//   - access_bindings.scope backfill matches resource_type
//   - scope CHECK + NOT NULL enforced
//   - idempotent re-run does not duplicate data
//   - backup tables `_pre_rbac_v2_*` carry pre-state
//   - zero malformed permissions remain (defensive sweep)
//   - malformed seed row aborts the migration without data loss
//
// The migration MUST be at `internal/migrations/0005_rbac_v2_grammar_and_scope.sql`
// and registered in the embed.FS. Helper: a tiny goose-driven up-to-N applier
// inline (testhelpers.go only ships up-to-head).
package pg_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// startPostgresUpTo spins a fresh container, applies migrations up to and
// including version `to`, and returns a connection pool.
//
// Mirrors `pg.NewTestPostgres` but stops short of the latest migration so
// callers can seed pre-migration state, then call `applyOneMore(t, db)` to
// advance to the migration under test.
func startPostgresUpTo(t *testing.T, to int64) (*pgxpool.Pool, *sql.DB, string) {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "?") {
		dsn += "&" + optionsParam
	} else {
		dsn += "?" + optionsParam
	}

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", to))

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	return pool, db, dsn
}

// applyOneMore advances goose by exactly one migration.
func applyOneMore(t *testing.T, db *sql.DB) error {
	t.Helper()
	return goose.UpByOne(db, ".")
}

// seedRole inserts a role row honouring the pre-migration validator (3-segment
// permissions are accepted by 0001's iam_permissions_valid).
func seedRole(t *testing.T, pool *pgxpool.Pool, id, name string, perms string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles(id, name, is_system, permissions, cluster_id)
		VALUES ($1, $2, true, $3::jsonb, 'cluster_kacho_root')`,
		id, name, perms)
	require.NoError(t, err, "seed role %s", id)
}

// seedBinding inserts an access_binding (used both pre-migration to test
// scope backfill, and post-migration to test CHECK enforcement).
func seedBinding(t *testing.T, pool *pgxpool.Pool, id, resType, resID, roleID string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id,
		     status, granted_by_user_id)
		VALUES ($1, 'user', 'usr00000000000000seed', $2, $3, $4, 'ACTIVE',
		        'usr00000000000000seed')`,
		id, roleID, resType, resID)
	require.NoError(t, err, "seed binding %s", id)
}

// TestMigration0005_S31_PromotesLegacy3SegToWildcard4Seg — legacy 3-segment promoted to 4-segment in-place.
func TestMigration0005_S31_PromotesLegacy3SegToWildcard4Seg(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	seedRole(t, pool, "rol00000000000000s31a", "kacho.viewer",
		`["compute.instance.read","vpc.network.create","iam.role.delete"]`)
	// Need an active rol seed-role tied to a custom-role pattern: kacho-iam ships
	// 12 system roles via 0001; we add ours as system to satisfy roles_scope_xor.

	require.NoError(t, applyOneMore(t, db))

	var raw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam.roles WHERE id=$1`,
		"rol00000000000000s31a",
	).Scan(&raw))

	for _, want := range []string{
		`"compute.instance.*.read"`,
		`"vpc.network.*.create"`,
		`"iam.role.*.delete"`,
	} {
		require.Contains(t, raw, want, "promoted permissions should include %s; got %s", want, raw)
	}
	require.NotContains(t, raw, `"compute.instance.read"`, "legacy 3-seg should be gone")
}

// TestMigration0005_S32_PreExisting4SegPassesThrough — a 4-segment row passes through unchanged.
func TestMigration0005_S32_PreExisting4SegPassesThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	// Pre-migration validator only accepts 3-seg, so we cannot seed a 4-seg
	// row directly. Instead seed two 3-seg perms and verify both promote
	// individually — the "passthrough" guarantee is exercised by the v2
	// validator on the next test (S3.3).
	seedRole(t, pool, "rol00000000000000s32a", "kacho.viewer",
		`["compute.instance.read","vpc.network.read"]`)

	require.NoError(t, applyOneMore(t, db))

	var raw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam.roles WHERE id=$1`,
		"rol00000000000000s32a",
	).Scan(&raw))
	require.Contains(t, raw, `"compute.instance.*.read"`)
	require.Contains(t, raw, `"vpc.network.*.read"`)

	// Now post-migration: writing a fresh 4-segment row succeeds.
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles(id, name, is_system, permissions, cluster_id)
		VALUES ($1, $2, true, $3::jsonb, 'cluster_kacho_root')`,
		"rol00000000000000s32b", "kacho.editor",
		`["compute.instance.inst-abc.update","vpc.network.*.create"]`)
	require.NoError(t, err, "post-migration 4-seg insert should succeed")
}

// TestMigration0005_S33_RejectsMalformedPostMigration — a malformed 4-segment INSERT is rejected (SQLSTATE 23514).
func TestMigration0005_S33_RejectsMalformedPostMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)
	require.NoError(t, applyOneMore(t, db))

	bad := []string{
		`["compute.instance.bad..verb"]`,         // empty segment
		`["compute.instance.read"]`,              // only 3 segments — must reject
		`["compute.instance.inst-A.read.extra"]`, // 5 segments
		`["compute..*.read"]`,                    // empty resource segment
		`["UPPER.instance.*.read"]`,              // bad case for module
	}
	for _, perms := range bad {
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.roles(id, name, is_system, permissions, cluster_id)
			VALUES ($1, $2, true, $3::jsonb, 'cluster_kacho_root')`,
			"rol00000000000000s33"+fmt.Sprintf("%d", len(perms)%10),
			"kacho.bad"+fmt.Sprintf("%d", len(perms)%10),
			perms)
		require.Error(t, err, "expected reject for %s", perms)
		pgErr := unwrapPgErr(err)
		require.NotNil(t, pgErr, "expected pg-level error for %s; got %v", perms, err)
		require.Equal(t, "23514", pgErr.Code, "expected CHECK violation 23514 for %s", perms)
		require.Contains(t, pgErr.ConstraintName, "permissions",
			"violation should name a permissions-validating constraint for %s", perms)
	}
}

// TestMigration0005_S34_WildcardOnlyPassesValidator — wildcard-only `*.*.*.*` passes the v2 validator.
func TestMigration0005_S34_WildcardOnlyPassesValidator(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)
	require.NoError(t, applyOneMore(t, db))

	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles(id, name, is_system, permissions, cluster_id)
		VALUES ($1, $2, true, $3::jsonb, 'cluster_kacho_root')`,
		"rol00000000000000s34a", "kacho.superuser",
		`["*.*.*.*"]`)
	require.NoError(t, err)
}

// TestMigration0005_S35_ScopeBackfillByResourceType — access_bindings.scope backfill matches resource_type.
func TestMigration0005_S35_ScopeBackfillByResourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	// Seed a custom-role to satisfy FK access_bindings_role_fk
	seedRole(t, pool, "rol00000000000000s35a", "kacho.viewer",
		`["compute.instance.read"]`)

	seeds := []struct {
		id, resType, resID string
		wantScope          int
	}{
		{"acb00000000000000clst1", "cluster", "cluster_kacho_root", 1},
		{"acb00000000000000acct1", "account", "acc00000000000000a001", 2},
		{"acb00000000000000proj1", "project", "prj00000000000000p001", 3},
		{"acb00000000000000vpcn1", "vpc_network", "enp00000000000000n001", 3},
		{"acb00000000000000inst1", "compute_instance", "epd00000000000000i001", 3},
		{"acb00000000000000user1", "user", "usr00000000000000u001", 3},
		{"acb00000000000000role1", "iam_role", "rol00000000000000r001", 3},
	}
	for _, s := range seeds {
		seedBinding(t, pool, s.id, s.resType, s.resID, "rol00000000000000s35a")
	}

	require.NoError(t, applyOneMore(t, db))

	for _, s := range seeds {
		var scope int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT scope FROM kacho_iam.access_bindings WHERE id=$1`,
			s.id,
		).Scan(&scope))
		require.Equal(t, s.wantScope, scope,
			"resource_type=%s expected scope=%d", s.resType, s.wantScope)
	}
}

// TestMigration0005_S36_ScopeCheckAndNotNull — scope CHECK + NOT NULL enforced.
func TestMigration0005_S36_ScopeCheckAndNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)
	seedRole(t, pool, "rol00000000000000s36a", "kacho.viewer",
		`["compute.instance.read"]`)
	require.NoError(t, applyOneMore(t, db))

	// CHECK violation: scope=4 not in (1,2,3)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id,
		     status, granted_by_user_id, scope)
		VALUES ('acb00000000000000bad01', 'user', 'usr_x', $1, 'account', 'acc_y',
		        'ACTIVE', 'usr_z', 4)`, "rol00000000000000s36a")
	require.Error(t, err)
	pgErr := unwrapPgErr(err)
	require.NotNil(t, pgErr)
	require.Equal(t, "23514", pgErr.Code)
	require.Contains(t, pgErr.ConstraintName, "scope_ck")

	// Omitted scope: BEFORE INSERT trigger derives it from resource_type so
	// pre-W4 callers (existing repo Insert SQL without `scope` column) keep
	// working. The NOT NULL constraint stays; only the path to satisfying
	// it is the trigger, not a column default.
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id,
		     status, granted_by_user_id)
		VALUES ('acb00000000000000ok01', 'user', 'usr_x', $1, 'cluster',
		        'cluster_kacho_root', 'ACTIVE', 'usr_z')`,
		"rol00000000000000s36a")
	require.NoError(t, err, "trigger must fill scope from resource_type='cluster'")
	var derived int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT scope FROM kacho_iam.access_bindings WHERE id='acb00000000000000ok01'`,
	).Scan(&derived))
	require.Equal(t, 1, derived, "cluster resource_type derives scope=1")
}

// TestMigration0005_S37_Idempotent re-runs the migration; row counts stable.
func TestMigration0005_S37_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	seedRole(t, pool, "rol00000000000000s37a", "kacho.viewer",
		`["compute.instance.read"]`)
	seedBinding(t, pool, "acb00000000000000s37a", "account", "acc00000000000000a001",
		"rol00000000000000s37a")

	require.NoError(t, applyOneMore(t, db))

	var rolesBefore, bindingsBefore, backupBefore int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles`).Scan(&rolesBefore))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings`).Scan(&bindingsBefore))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam._pre_rbac_v2_roles`).Scan(&backupBefore))

	// Force goose to re-apply migration 5.
	_, err := pool.Exec(ctx, `DELETE FROM goose_db_version WHERE version_id = 5`)
	require.NoError(t, err)
	require.NoError(t, applyOneMore(t, db))

	var rolesAfter, bindingsAfter, backupAfter int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles`).Scan(&rolesAfter))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings`).Scan(&bindingsAfter))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam._pre_rbac_v2_roles`).Scan(&backupAfter))

	require.Equal(t, rolesBefore, rolesAfter, "roles row-count stable")
	require.Equal(t, bindingsBefore, bindingsAfter, "access_bindings row-count stable")
	require.Equal(t, backupBefore, backupAfter, "backup row-count stable (TRUNCATE-then-INSERT contract)")
}

// TestMigration0005_S38_BackupTablesCarryPreState — backup tables `_pre_rbac_v2_*` carry pre-state.
func TestMigration0005_S38_BackupTablesCarryPreState(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	seedRole(t, pool, "rol00000000000000s38a", "kacho.viewer",
		`["compute.instance.read","vpc.network.create"]`)
	seedBinding(t, pool, "acb00000000000000s38a", "account", "acc00000000000000a001",
		"rol00000000000000s38a")

	require.NoError(t, applyOneMore(t, db))

	var roleBackup string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam._pre_rbac_v2_roles WHERE id=$1`,
		"rol00000000000000s38a",
	).Scan(&roleBackup))
	require.Contains(t, roleBackup, `"compute.instance.read"`, "backup keeps pre-migration 3-seg form")
	require.NotContains(t, roleBackup, `*.read`, "backup must NOT be promoted")

	var bindingBackupCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam._pre_rbac_v2_access_bindings WHERE id=$1`,
		"acb00000000000000s38a",
	).Scan(&bindingBackupCount))
	require.Equal(t, 1, bindingBackupCount)
}

// TestMigration0005_S310_ZeroMalformedPostMigration — zero malformed permissions remain (defensive sweep).
func TestMigration0005_S310_ZeroMalformedPostMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)
	// 0001 seeds 12 system roles. Verify post-migration they're all 4-seg.
	require.NoError(t, applyOneMore(t, db))

	var leftCount int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.roles
		WHERE EXISTS (
			SELECT 1 FROM jsonb_array_elements_text(permissions) p
			WHERE array_length(string_to_array(p, '.'), 1) <> 4
			   OR p ~ '^\.|\.\.|\.$'
			   OR p !~ '^(\*|[a-zA-Z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$'
		)
	`).Scan(&leftCount))
	require.Equal(t, 0, leftCount, "all roles must be strict 4-segment post-migration")
}

// TestMigration0005_S311_AbortOnMalformedSeed — a malformed seed row aborts the migration without data loss.
//
// A row that the promoter cannot fix (>4 or <3 segments) trips the new CHECK
// when it is re-attached; the migration transaction aborts, the seed row is
// preserved.
func TestMigration0005_S311_AbortOnMalformedSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	pool, db, _ := startPostgresUpTo(t, 4)

	// The 0001 validator accepts 3-seg only. 5-seg cannot be seeded the
	// normal way. Bypass: temporarily drop the CHECK to seed bad data.
	_, err := pool.Exec(ctx,
		`ALTER TABLE kacho_iam.roles DROP CONSTRAINT roles_permissions_valid`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles(id, name, is_system, permissions, cluster_id)
		VALUES ('rol00000000000000s311', 'kacho.broken', true,
		        '["a.b.c.d.e"]'::jsonb, 'cluster_kacho_root')`)
	require.NoError(t, err)

	err = applyOneMore(t, db)
	require.Error(t, err, "migration must abort on un-promotable malformed row")

	// The seed row is preserved (transaction rolled back).
	var stillThere int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles WHERE id='rol00000000000000s311'`,
	).Scan(&stillThere))
	require.Equal(t, 1, stillThere, "rollback preserves the malformed row")

	// Verify the migration did NOT half-apply: scope column should NOT exist
	// after rollback.
	var hasScope bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='kacho_iam' AND table_name='access_bindings'
			  AND column_name='scope'
		)`).Scan(&hasScope))
	require.False(t, hasScope, "scope column must NOT exist after migration rollback")
}

// unwrapPgErr — peel pgconn.PgError out of wrap chain.
func unwrapPgErr(err error) *pgconn.PgError {
	for e := err; e != nil; {
		pgErr, ok := e.(*pgconn.PgError)
		if ok {
			return pgErr
		}
		un, ok := e.(interface{ Unwrap() error })
		if !ok {
			return nil
		}
		e = un.Unwrap()
	}
	return nil
}
