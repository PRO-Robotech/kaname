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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	pg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// jitTestSubjectID / jitTestAccountID — the fixed subject seeded for the parent
// bindings below (migration 0049 enforces subject existence via the
// subject_ref_exists trigger, so the referenced user must be a live row).
const (
	jitTestSubjectID = "usr_jit_test"
	jitTestAccountID = "acc_jit_test"
)

// ensureJITSubject idempotently seeds the user (+ its account, deferred-FK
// chicken/egg) that the parent bindings reference. Safe to call repeatedly
// within one test (ON CONFLICT DO NOTHING).
func ensureJITSubject(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	// users.account_id → accounts(id) is DEFERRABLE INITIALLY DEFERRED, so the
	// user may be inserted before its account within one tx (same pattern as
	// mustSeedUser). invite_status='ACTIVE' requires a non-empty external_id.
	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, 'ext-jit-test', 'jit@example.com', 'JIT', 'ACTIVE')
		ON CONFLICT (id) DO NOTHING`, jitTestSubjectID, jitTestAccountID)
	require.NoError(t, err, "seed jit subject user")
	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, 'jit-test-acc', $2, '{}'::jsonb)
		ON CONFLICT (id) DO NOTHING`, jitTestAccountID, jitTestSubjectID)
	require.NoError(t, err, "seed jit subject account")
	require.NoError(t, tx.Commit(ctx), "commit jit subject seed")
}

// insertParentBinding inserts a minimal valid access_bindings row and returns
// its id (so the FK on access_binding_conditions.binding_id is satisfiable).
func insertParentBinding(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	// migration 0049: subject_id is now DB-enforced (subject_ref_exists trigger),
	// so the referenced subject must be a live user row — seed it first.
	ensureJITSubject(ctx, t, pool)
	// role_id has an FK → roles(id); use a seeded deterministic system role.
	// resource_id is a soft (cross-domain) ref (no FK), derived from the binding
	// id so each parent's active-grant 5-tuple is unique
	// (access_bindings_active_grant_uniq partial UNIQUE).
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, 'rol000000000sysadmin', 'project', $3, 'ACTIVE')`,
		id, jitTestSubjectID, "prj_"+id)
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
