// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migrations_iam_extensions_integration_test.go — testcontainers Postgres 16
// integration tests for the iam-extension migrations.
//
// Tested scenarios:
// - Fresh apply: migrations succeed; schema_migrations records the baseline.
// - Idempotent re-apply: second goose.Up == no-op (returns nil; no DDL re-runs).
// - Down + Up round-trip: rollback then re-apply.
// - clusters singleton: 1 row seeded; second INSERT → SQLSTATE 23514.
// - multi-scope Role CHECK + partial UNIQUE per scope.
// - access_bindings status / condition_id / expires_at / granted_by_user_id present.
//
// Запуск: `go test -tags=integration ./internal/repo/kacho/pg/... -run Kac127 -race`.
// Skip с `-short`.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// setupKac127TestDB отдаёт вызывающему СОБСТВЕННУЮ базу с полностью прогнанными
// миграциями на общем Postgres пакета. Возвращает *sql.DB, чтобы caller мог
// рантаймно проверять schema (information_schema, pg_constraint, и т.д.).
//
// Раньше на каждый вызов поднимался отдельный контейнер и заново проигрывалась
// вся цепочка. Теперь база клонируется из шаблона, который TestMain смигрировал
// один раз тем же `goose.Up(db, ".")` — состояние то же и изоляция та же (см.
// internal/pgtest), а контейнер один на пакет.
//
// goose BaseFS/dialect выставляются здесь, а не в телах тестов: они сами зовут
// goose.Up / goose.DownTo на возвращённом *sql.DB и полагаются на эту настройку.
func setupKac127TestDB(t testing.TB) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	return db
}

// ── 6.1.1 — Fresh apply: 0011..0014 succeed; schema_migrations records new versions
func TestIamExt_Migrations_6_1_1_FreshApply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Squashed baseline (0001_initial.sql) — the entire pre-prune schema
	// is collapsed into a single migration. Just assert that version 1 is
	// applied and the seeded artefacts (cluster singleton + system roles)
	// are present.
	var applied bool
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM goose_db_version WHERE version_id = 1 AND is_applied = true)").Scan(&applied))
	assert.True(t, applied, "squashed baseline migration 0001 must be applied")

	// clusters singleton — exactly one row, id = cluster_kacho_root.
	var clusterCount int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kacho_iam.clusters").Scan(&clusterCount))
	assert.Equal(t, 1, clusterCount, "exactly one cluster row seeded")

	var clusterID string
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT id FROM kacho_iam.clusters").Scan(&clusterID))
	assert.Equal(t, "cluster_kacho_root", clusterID)

	// Two new system roles seeded by 0011.
	var sysRoleCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.roles
		 WHERE is_system = true AND cluster_id = 'cluster_kacho_root'
		 AND name IN ('kacho-system.admin', 'kacho-system.viewer')`).Scan(&sysRoleCount))
	assert.Equal(t, 2, sysRoleCount, "two new system roles seeded")

	// Verify expected tables exist after the extension migrations (sample check).
	for _, table := range []string{
		"clusters", "cluster_admin_grants",
		"service_account_oauth_clients",
		"audit_outbox",
		"session_revocations",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kacho_iam' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "table kacho_iam.%s must exist", table)
	}

	// Retired tables — must NOT come back. 0065 drops the signing-key store:
	// iam owns no keyset (it mints nothing; Hydra is the issuer and signer),
	// the table's only writers died with the nightly rotation (713f7e1), and it
	// held zero rows on a fully working stand. 0075 drops the tenant-facing
	// condition surface: the resource table and the per-binding overlay, the
	// latter with no production writer at any point in its life.
	for _, table := range []string{
		"oidc_jwks_keys",
		"conditions",
		"access_binding_conditions",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kacho_iam' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "retired table kacho_iam.%s must be gone", table)
	}

	// Verify new columns on extended tables.
	for _, col := range []struct {
		table, column string
	}{
		{"roles", "cluster_id"},
		{"roles", "project_id"},
		{"access_bindings", "status"},
		{"access_bindings", "expires_at"},
		{"access_bindings", "granted_by_user_id"},
		{"access_bindings", "revoked_at"},
		{"access_bindings", "revoked_by_user_id"},
		// `service_accounts.project_id` из этого списка снят: колонку никто не
		// заполнял, и она ушла вместе с полем контракта (миграция 0071).
		{"service_accounts", "enabled"},
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.columns
			 WHERE table_schema = 'kacho_iam'
			 AND table_name = $1 AND column_name = $2
			)`, col.table, col.column).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "column %s.%s must exist", col.table, col.column)
	}
}

// ── 6.1.2 — Idempotent re-apply: second goose.Up returns nil; no DDL re-execution
func TestIamExt_Migrations_6_1_2_IdempotentReapply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Capture cluster count + system role count BEFORE second up.
	var beforeClusters, beforeRoles int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM kacho_iam.clusters").Scan(&beforeClusters))
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kacho_iam.roles WHERE is_system=true").Scan(&beforeRoles))

	// Second goose.Up — must be no-op.
	require.NoError(t, goose.Up(db, "."))

	var afterClusters, afterRoles int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM kacho_iam.clusters").Scan(&afterClusters))
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kacho_iam.roles WHERE is_system=true").Scan(&afterRoles))

	assert.Equal(t, beforeClusters, afterClusters, "cluster count unchanged after re-apply")
	assert.Equal(t, beforeRoles, afterRoles, "system role count unchanged after re-apply")
}

// ── Down + Up round-trip: rollback then re-apply.
//
// The squashed baseline (0001_initial.sql) collapses the whole history into a
// single migration — the Down step drops the entire kacho_iam schema, the Up
// step recreates it. The round-trip therefore asserts on that single-shot
// DROP / re-CREATE.
func TestIamExt_Migrations_6_1_RoundTripDownUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Down to 0 — squashed baseline drops the whole kacho_iam schema.
	require.NoError(t, goose.DownTo(db, ".", 0))

	// Verify tables are gone.
	for _, table := range []string{
		"clusters",
		"audit_outbox",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kacho_iam' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "table kacho_iam.%s must be gone after Down", table)
	}

	// Up again — re-apply the squashed baseline.
	require.NoError(t, goose.Up(db, "."))

	// Verify tables back. oidc_jwks_keys is NOT in this set: 0065 retires it,
	// so a full Down-to-0 + Up round-trip must leave it dropped.
	for _, table := range []string{
		"clusters",
		"audit_outbox",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kacho_iam' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "table kacho_iam.%s must be re-created", table)
	}
}

// ── 6.2.1 — clusters singleton: second INSERT rejected by CHECK
func TestIamExt_Migrations_6_2_1_ClusterSingleton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		"INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_other', 'other')")
	require.Error(t, err)
	// SQLSTATE 23514 (CHECK violation on clusters_id_singleton_ck).
	assert.Contains(t, err.Error(), "23514", "expected CHECK violation 23514")

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kacho_iam.clusters").Scan(&count))
	assert.Equal(t, 1, count, "clusters table still has exactly one row")
}

// ── 6.4.4 — Multi-scope Role: two non-NULL scope columns → CHECK violation
func TestIamExt_Migrations_6_4_4_RoleScopeXor_TwoScopesInvalid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Создаем User → Account → Project (валидные scope target'ы).
	_, err := db.ExecContext(ctx, `
		INSERT INTO kacho_iam.users (id, external_id, email, account_id, invite_status)
		VALUES ('usr_kac127test0001ab', 'ext_kac127_001', 'kac127@test.local', 'acc_kac127test001ab', 'ACTIVE')`)
	// Сначала Account через DEFERRABLE FK.
	// Простой план: INSERT user→account в одной TX с deferred FKs.
	require.Error(t, err, "expected FK violation since accounts not created yet")

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "SET CONSTRAINTS ALL DEFERRED")
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		VALUES ('acc_kac127test001ab', 'kac127-test-acc', 'usr_kac127test0001ab')`)
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kacho_iam.users (id, external_id, email, account_id, invite_status)
		VALUES ('usr_kac127test0001ab', 'ext_kac127_001', 'kac127@test.local', 'acc_kac127test001ab', 'ACTIVE')`)
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kacho_iam.projects (id, account_id, name)
		VALUES ('prj_kac127test001ab', 'acc_kac127test001ab', 'kac127-test-prj')`)
	require.NoError(t, err)

	require.NoError(t, tx.Commit())

	// Теперь invalid INSERT: custom role с двумя non-NULL scope (account_id + project_id).
	_, err = db.ExecContext(ctx, `
		INSERT INTO kacho_iam.roles
		 (id, account_id, project_id, name, permissions)
		VALUES
		 ('rol_kac127twoscope1', 'acc_kac127test001ab', 'prj_kac127test001ab',
		 'invalid_two_scope', '["compute.instance.*.read"]'::jsonb)`)
	require.Error(t, err, "expected CHECK violation roles_definition_tier_xor")
	assert.Contains(t, err.Error(), "23514", "expected CHECK violation 23514")
	assert.Contains(t, strings.ToLower(err.Error()), "roles_definition_tier_xor",
		"expected violation на constraint roles_definition_tier_xor (renamed from roles_scope_xor in 0056)")

	// Valid project-scoped role работает.
	_, err = db.ExecContext(ctx, `
		INSERT INTO kacho_iam.roles
		 (id, project_id, name, permissions)
		VALUES
		 ('rol_kac127prj00001a', 'prj_kac127test001ab',
		 'deployer', '["compute.instance.*.read","compute.instance.*.list"]'::jsonb)`)
	require.NoError(t, err, "valid project-scoped role insert must succeed")
}

// ── 6.5.0 — backward-compat: legacy access_bindings get default status='ACTIVE'.
func TestIamExt_Migrations_6_5_0_AccessBindingStatusDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Проверяем что колонка status существует с NOT NULL + DEFAULT 'ACTIVE'.
	var isNullable, columnDefault string
	err := db.QueryRowContext(ctx, `
		SELECT is_nullable, COALESCE(column_default, '')
		 FROM information_schema.columns
		 WHERE table_schema = 'kacho_iam' AND table_name = 'access_bindings' AND column_name = 'status'
	`).Scan(&isNullable, &columnDefault)
	require.NoError(t, err)
	assert.Equal(t, "NO", isNullable, "access_bindings.status must be NOT NULL")
	assert.Contains(t, columnDefault, "ACTIVE", "default must be 'ACTIVE'")
}

// JIT eligibility CHECK tests removed: the access_bindings_jit_eligibility
// table was dropped alongside the JIT pipeline.
