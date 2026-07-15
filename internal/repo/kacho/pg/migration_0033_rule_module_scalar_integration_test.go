// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0033_rule_module_scalar_integration_test.go — RBAC rules-model 2026
// (testcontainers Postgres 16). Migration 0033 rewrites roles.rules
// JSONB from the array `modules:[m,...]` shape to the scalar `module:m` shape
// (splitting an N-module rule into N rules — defensive; live N=1) and replaces
// the iam_rules_valid PL/pgSQL function (referenced by the unchanged CHECK
// constraint roles_rules_valid) to validate the scalar shape.
//
// Scenarios:
//   - array→scalar rewrite (live N=1) — modules:["iam"] → module:"iam".
//   - defensive multi-module split (synthetic N→N) + idempotent re-run.
//   - function accepts scalar / rejects array + missing-module; reversible
//     Down (closed-default scalar→single-element-array) + Up→Down→Up round-trip.
//
// The harness migrates UP TO 0031 (the array-modules re-seed), seeds a fixture in
// the OLD array shape, then runs 0033 and asserts the rewrite + CHECK behaviour.
// Run with the full integration build (NOT -short).

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// migrate0033Env brings a fresh DB up to a target version with goose and returns
// a pool + the raw sql.DB (for further up/down). version 32 = pre-0033 (array
// shape live); 33 = post-0033 (scalar shape).
func migrate0033Env(t *testing.T, ctx context.Context, toVersion int64) (*pgxpool.Pool, *sql.DB, string) {
	t.Helper()
	dsn := setupTestDBNoUp(t)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", toVersion))

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })
	return pool, db, dsn
}

// seedCustomRoleRaw inserts a role row directly with a given rules JSONB literal
// (bypassing the use-case) — used to plant OLD-shape fixtures BEFORE 0033 runs.
func seedCustomRoleRaw(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rulesJSON string) string {
	t.Helper()
	accID := ids.NewID(domain.PrefixAccount)
	uid := mustSeedUser(t, ctx, pool, "m33"+accID[len(accID)-5:])
	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "m33-acc-"+accID[len(accID)-6:], string(uid))
	require.NoError(t, err)

	roleID := ids.NewID(domain.PrefixRole)
	_, err = pool.Exec(ctx, fmt.Sprintf(`
		INSERT INTO roles (id, account_id, name, description, permissions, rules, is_system)
		VALUES ($1, $2, $3, '', '["vpc.subnet.*.get"]'::jsonb, '%s'::jsonb, false)`, rulesJSON),
		roleID, accID, "m33_role_"+sanitizeName(roleID[len(roleID)-6:]))
	require.NoError(t, err)
	return roleID
}

func rulesOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) string {
	t.Helper()
	var raw string
	require.NoError(t, pool.QueryRow(ctx, `SELECT rules::text FROM roles WHERE id=$1`, roleID).Scan(&raw))
	return raw
}

// sanitizeName maps an id suffix to the custom-role name grammar [a-z0-9_]
// (roles_custom_name_check) — crockford-base32 ids can carry uppercase chars.
func sanitizeName(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			// ok
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// a live-shaped row [{"modules":["iam"],...}] rewrites to [{"module":"iam",...}].
func TestMigration0033_ArrayToScalarRewrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, db, _ := migrate0033Env(t, ctx, 32) // pre-0033: array shape

	roleID := seedCustomRoleRaw(t, ctx, pool,
		`[{"modules":["iam"],"resources":["account"],"verbs":["read","list","get"]}]`)

	// Apply 0033.
	require.NoError(t, goose.UpTo(db, ".", 33))

	got := rulesOf(t, ctx, pool, roleID)
	// modules key dropped; scalar module added; other keys preserved.
	require.NotContains(t, got, `"modules"`, "modules key must be dropped")
	require.Contains(t, got, `"module": "iam"`, "scalar module must be present")
	require.Contains(t, got, `"account"`, "resources preserved")

	// Every rule has a non-empty scalar module, no modules key (dump-analog check).
	var bad int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM roles r,
		     LATERAL jsonb_array_elements(r.rules) AS e
		 WHERE (e ? 'modules') OR NOT (e ? 'module')
		    OR jsonb_typeof(e->'module') <> 'string'
		    OR length(e->>'module') = 0`).Scan(&bad))
	require.Equal(t, 0, bad, "every rule must carry a non-empty scalar module and no modules key after 0033")
}

// a synthetic multi-module rule splits into N scalar rules; idempotent re-run.
func TestMigration0033_DefensiveSplit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, db, _ := migrate0033Env(t, ctx, 32)

	roleID := seedCustomRoleRaw(t, ctx, pool,
		`[{"modules":["iam","vpc"],"resources":["account"],"verbs":["get"]}]`)

	require.NoError(t, goose.UpTo(db, ".", 33))

	// 2 rules, one per module, same resources/verbs.
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT jsonb_array_length(rules) FROM roles WHERE id=$1`, roleID).Scan(&n))
	require.Equal(t, 2, n, "multi-module rule splits into N scalar rules")

	var modules []string
	rows, err := pool.Query(ctx, `
		SELECT e->>'module' FROM roles r, LATERAL jsonb_array_elements(r.rules) e
		 WHERE r.id=$1 ORDER BY e->>'module'`, roleID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var m string
		require.NoError(t, rows.Scan(&m))
		modules = append(modules, m)
	}
	require.Equal(t, []string{"iam", "vpc"}, modules)
}

func TestMigration0033_IdempotentRerun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, db, _ := migrate0033Env(t, ctx, 32)
	roleID := seedCustomRoleRaw(t, ctx, pool,
		`[{"modules":["iam"],"resources":["account"],"verbs":["get"]}]`)

	require.NoError(t, goose.UpTo(db, ".", 33))
	first := rulesOf(t, ctx, pool, roleID)

	// Re-apply the 0033 Up body verbatim — already-scalar rows must be a no-op.
	require.NoError(t, applyMigrationUpBody(t, db, "0033"))
	second := rulesOf(t, ctx, pool, roleID)
	require.JSONEq(t, first, second, "re-running 0033 Up on scalar rows is a no-op (idempotent)")
}

// post-0033, the function accepts scalar, rejects array-modules + missing-module.
func TestMigration0033_CheckScalarAcceptArrayReject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, _, _ := migrate0033Env(t, ctx, 33) // post-0033

	uid := mustSeedUser(t, ctx, pool, "m33chk")
	accID := ids.NewID(domain.PrefixAccount)
	_, err := pool.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, accID, "m33chk-acc-"+accID[len(accID)-6:], string(uid))
	require.NoError(t, err)

	insert := func(rules string) error {
		rid := ids.NewID(domain.PrefixRole)
		_, e := pool.Exec(ctx, fmt.Sprintf(`
			INSERT INTO roles (id, account_id, name, description, permissions, rules, is_system)
			VALUES ($1, $2, $3, '', '["vpc.subnet.*.get"]'::jsonb, '%s'::jsonb, false)`, rules),
			rid, accID, "m33chk_"+sanitizeName(rid[len(rid)-6:]))
		return e
	}

	// (a) scalar accepted.
	require.NoError(t, insert(`[{"module":"iam","resources":["account"],"verbs":["get"]}]`),
		"scalar module must be accepted by roles_rules_valid")
	// (b) old array-modules rejected.
	require.Error(t, insert(`[{"modules":["iam"],"resources":["account"],"verbs":["get"]}]`),
		"array modules must be rejected after 0033")
	// (c) missing module rejected.
	require.Error(t, insert(`[{"resources":["account"],"verbs":["get"]}]`),
		"rule without module must be rejected after 0033")
}

// Up→Down→Up round-trip preserves the live N=1 semantics (scalar↔single-element-array).
func TestMigration0033_UpDownUpRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, db, _ := migrate0033Env(t, ctx, 32)
	roleID := seedCustomRoleRaw(t, ctx, pool,
		`[{"modules":["vpc"],"resources":["subnet"],"verbs":["get","list"]}]`)

	require.NoError(t, goose.UpTo(db, ".", 33))
	require.Contains(t, rulesOf(t, ctx, pool, roleID), `"module": "vpc"`)

	// Down: scalar → single-element array; function back to array shape.
	require.NoError(t, goose.DownTo(db, ".", 32))
	down := rulesOf(t, ctx, pool, roleID)
	require.Contains(t, down, `"modules": ["vpc"]`, "Down restores single-element modules array")
	require.NotContains(t, down, `"module": "vpc"`, "Down drops the scalar module key")

	// Up again: scalar restored — N=1 round-trip is semantically identical.
	require.NoError(t, goose.UpTo(db, ".", 33))
	up := rulesOf(t, ctx, pool, roleID)
	require.Contains(t, up, `"module": "vpc"`, "Up→Down→Up restores scalar (N=1 idempotent)")
	require.NotContains(t, up, `"modules"`, "no array modules key after final Up")
}
