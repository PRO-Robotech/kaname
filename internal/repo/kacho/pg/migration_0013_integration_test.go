// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// migration_0013_integration_test.go — integration tests for the
// `0013_drop_jit_breakglass_condition_whitelist.sql` migration.
//
// After migration 0013 the `access_binding_conditions_expression_whitelist_ck`
// CHECK no longer admits the two deprecated condition kinds:
//
//   - `jit_window`         — no flow ever set its state, so it was never enforceable.
//   - `break_glass_window` — deprecated builtin-condition kind.
//
// The five live kinds (mfa_fresh / non_expired / source_ip_in_range /
// business_hours / device_compliant) still insert fine.
//
// access_binding_conditions.binding_id has an FK → access_bindings(id), so each
// case first inserts a minimal parent AccessBinding row.
package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho-corelib/db"
	pg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// insertParentBinding inserts a minimal valid access_bindings row and returns
// its id (so the FK on access_binding_conditions.binding_id is satisfiable).
func insertParentBinding(ctx context.Context, t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, id string) {
	t.Helper()
	// role_id has an FK → roles(id); use a seeded deterministic system role.
	// subject_id / resource_id are soft refs (no FK). resource_id is derived
	// from the binding id so each parent's active-grant 5-tuple is unique
	// (access_bindings_active_grant_uniq partial UNIQUE).
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', 'usr_jit_test', 'rol000000000sysadmin', 'project', $2, 'ACTIVE')`,
		id, "prj_"+id)
	require.NoError(t, err, "insert parent access_binding")
}

func TestMigration0013_WhitelistRejectsJITAndBreakGlass(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Dropped kinds must be rejected by the CHECK (SQLSTATE 23514).
	for i, kind := range []string{"jit_window", "break_glass_window"} {
		bindingID := fmt.Sprintf("acb_drop_%d", i)
		insertParentBinding(ctx, t, pool, bindingID)

		condID := fmt.Sprintf("cond_drop_%d", i)
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.access_binding_conditions (id, binding_id, expression, params)
			VALUES ($1, $2, $3, '{}'::jsonb)`,
			condID, bindingID, kind)
		require.Error(t, err, "expected CHECK rejection for kind %q", kind)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "expected a pg error for kind %q", kind)
		require.Equal(t, "23514", pgErr.Code,
			"expected check_violation (23514) for kind %q; got %s/%s", kind, pgErr.Code, pgErr.ConstraintName)
		require.Equal(t, "access_binding_conditions_expression_whitelist_ck", pgErr.ConstraintName,
			"expected whitelist CHECK to reject kind %q", kind)
	}
}

func TestMigration0013_WhitelistStillAdmitsLiveKinds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := pg.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	live := []string{"mfa_fresh", "non_expired", "source_ip_in_range", "business_hours", "device_compliant"}
	for i, kind := range live {
		bindingID := fmt.Sprintf("acb_live_%d", i)
		insertParentBinding(ctx, t, pool, bindingID)

		condID := fmt.Sprintf("cond_live_%d", i)
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.access_binding_conditions (id, binding_id, expression, params)
			VALUES ($1, $2, $3, '{}'::jsonb)`,
			condID, bindingID, kind)
		require.NoError(t, err, "live kind %q must still insert", kind)
	}
}
