// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0026_0027_role_rule_selectors_integration_test.go — RBAC rules-model
// schema migration (RED → GREEN).
//
// 0026 adds role_rule_selectors(role_id, rule_fp, object_types[], match_labels)
//      PK(role_id, rule_fp) — the per-rule ARM_LABELS selector spec the reconciler
//      drives (driven by role.rules, NOT binding.selector).
// 0027 rekeys access_binding_target_members: ADD role_id, rule_fp; PK →
//      (binding_id, role_id, rule_fp, object_type, object_id) so a member is
//      attributed to the RULE that produced it (per-rule eager-revoke), with
//      legacy rows backfilled to a sentinel rule coordinate (legacy binding.selector
//      arm — not a role.rule), so the legacy path keeps working unchanged.
//
// Run: `make test` (testcontainers Postgres 16). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedCustomRoleSQL inserts a minimal custom (account-scoped) role directly so the
// FK role_id targets are satisfiable in the schema-migration tests.
func seedCustomRoleSQL(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, is_system)
		VALUES ($1, $2, $3, $4, '["compute.instance.*.get"]'::jsonb, false)`,
		string(rid), string(accID), name, "custom "+name)
	require.NoError(t, err, "seed custom role")
	return rid
}

func TestMigration0026_RoleRuleSelectorsTable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// The table + its key columns exist.
	for _, col := range []string{"role_id", "rule_fp", "object_types", "match_labels"} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			 WHERE table_schema='kacho_iam' AND table_name='role_rule_selectors' AND column_name=$1`,
			col).Scan(&n))
		assert.Equal(t, 1, n, "role_rule_selectors.%s must exist", col)
	}

	// FK role_id → roles(id) ON DELETE CASCADE: deleting a role drops its selectors.
	owner := mustSeedUser(t, ctx, pool, "rrsowner")
	acc := seedAccount(t, ctx, repo, "rrs-acc", owner)
	roleID := seedCustomRoleSQL(t, ctx, pool, acc.ID, "rrs_role")

	// arm + resource_names are mandatory after migration 0034 (arm NOT NULL,
	// arm-aware shape CHECK). These rows use the ARM_LABELS shape — arm='labels',
	// match_labels non-empty object, resource_names empty (the labels-arm branch of
	// role_rule_selectors_arm_shape). The 0026/0027 invariants under test (column
	// existence, FK ON DELETE CASCADE, PK uniqueness) are unchanged.
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, arm, resource_names)
		VALUES ($1, 'fp_abc', ARRAY['compute.instance'], '{"env":"prod"}'::jsonb, 'labels', '{}')`,
		roleID)
	require.NoError(t, err, "insert role_rule_selectors row")

	// PK (role_id, rule_fp): duplicate → 23505.
	_, dErr := pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, object_types, match_labels, arm, resource_names)
		VALUES ($1, 'fp_abc', ARRAY['compute.disk'], '{"env":"dev"}'::jsonb, 'labels', '{}')`,
		roleID)
	require.Error(t, dErr, "duplicate (role_id, rule_fp) must violate PK")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, dErr, &pgErr)
	assert.Equal(t, "23505", pgErr.Code, "PK violation SQLSTATE")

	_, err = pool.Exec(ctx, `DELETE FROM kacho_iam.roles WHERE id=$1`, roleID)
	require.NoError(t, err, "delete role")
	var remaining int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id=$1`, roleID).Scan(&remaining))
	assert.Equal(t, 0, remaining, "FK ON DELETE CASCADE drops the role's selectors")
}

func TestMigration0027_TargetMembersRekey(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// New coordinate columns exist.
	for _, col := range []string{"role_id", "rule_fp"} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			 WHERE table_schema='kacho_iam' AND table_name='access_binding_target_members' AND column_name=$1`,
			col).Scan(&n))
		assert.Equal(t, 1, n, "access_binding_target_members.%s must exist after rekey", col)
	}

	// PK is now the 5-tuple (binding_id, role_id, rule_fp, object_type, object_id):
	// the SAME (binding, object) under two DIFFERENT rule_fp coexist (distinct rows).
	owner := mustSeedUser(t, ctx, pool, "tmrkowner")
	acc := seedAccount(t, ctx, repo, "tmrk-acc", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "tmrk-prj")
	roleID := seedCustomRoleSQL(t, ctx, pool, acc.ID, "tmrk_role")
	bindingID := "acb_tmrk_1"
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		bindingID, string(owner), string(roleID), string(prj.ID))
	require.NoError(t, err)

	insMember := func(ruleFP string) error {
		_, e := pool.Exec(ctx, `
			INSERT INTO kacho_iam.access_binding_target_members
				(binding_id, role_id, rule_fp, object_type, object_id, verification_status)
			VALUES ($1, $2, $3, 'compute.instance', 'inst-1', 'ACTIVE')`,
			bindingID, string(roleID), ruleFP)
		return e
	}
	require.NoError(t, insMember("fp_rule_A"), "member under rule A")
	require.NoError(t, insMember("fp_rule_B"), "SAME (binding,object) under rule B → distinct PK row")

	var members int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members
		  WHERE binding_id=$1 AND object_type='compute.instance' AND object_id='inst-1'`,
		bindingID).Scan(&members))
	assert.Equal(t, 2, members, "two rule_fp coordinates → two member rows for the same object")

	// Same (binding, role, rule_fp, object) twice → PK violation (idempotent UPSERT key).
	dErr := insMember("fp_rule_A")
	require.Error(t, dErr, "duplicate full coordinate must violate PK")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, dErr, &pgErr)
	assert.Equal(t, "23505", pgErr.Code)
}
