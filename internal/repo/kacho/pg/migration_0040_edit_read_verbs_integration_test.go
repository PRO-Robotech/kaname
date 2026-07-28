// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0040_edit_read_verbs_integration_test.go — RBAC Design-B flat-authz
// verb-bearing (testcontainers Postgres 16). Migration 0040 расширяет verb-набор
// системных «edit»-ролей с `["update"]` до `["get","list","update"]`, чтобы под
// развязанной v_*↔tier моделью (анти-#241) editor мог читать то, что редактирует
// (reconciler материализует v_get/v_list, а не только v_update).
//
// Сценарии:
//   - 0040-EDIT: глобальная `edit` (md5('edit')) и per-resource `*.edit` (e.g.
//     iam.project.edit, vpc.network.edit) после 0040 несут verbs [get,list,update].
//   - 0040-KEEP: admin (`["*"]`) и view (`["read","list","get"]`) НЕ затронуты.
//   - 0040-RT:   Up→Down→Up round-trip идемпотентен (edit↔[update]).
//
// Harness мигрирует до 39 (pre-0040: edit == ["update"]), проверяет RED-инвариант,
// затем до 40 и проверяет целевое состояние. Полный integration build (НЕ -short).

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// md5hex17 mirrors the migration/fixture role-id derivation `substr(md5(name),1,17)`.
func md5hex17(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // role-id derivation parity with migration SQL, not a security primitive
	return hex.EncodeToString(sum[:])[:17]
}

func roleRulesJSON(t *testing.T, ctx context.Context, dsn, roleID string) string {
	t.Helper()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	var rules string
	err = pool.QueryRow(ctx,
		`SELECT rules::text FROM kacho_iam.roles WHERE id = $1`, roleID).Scan(&rules)
	require.NoError(t, err, "role %s must exist", roleID)
	return rules
}

func TestMigration0040_EditRolesIncludeReadVerbs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDBNoUp(t)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	// System role ids (md5-derived) — same derivation as the fixtures + migration 0031.
	editGlobal := "rolde95b43bceeb4b998"  // md5('edit')[:17]
	adminGlobal := "rol21232f297a57a5a74" // md5('admin')[:17]
	viewGlobal := "rol1bda80f2be4d3658e"  // md5('view')[:17]

	// ── pre-0040 (version 39): edit == ["update"] (the RED state) ──────────────
	require.NoError(t, goose.UpTo(db, ".", 39))
	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["update"]}]`,
		roleRulesJSON(t, ctx, dsn, editGlobal),
		"pre-0040: global edit role carries ONLY [update] (Design-B RED: editor can't read)")

	// ── post-0040 (version 40): edit == [get,list,update] ─────────────────────
	require.NoError(t, goose.UpTo(db, ".", 40))

	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["get","list","update"]}]`,
		roleRulesJSON(t, ctx, dsn, editGlobal),
		"post-0040: global edit role carries [get,list,update] → reconciler materializes v_get/v_list/v_update")

	// admin (`*`) and view ([read,list,get]) are NOT touched.
	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["*"]}]`,
		roleRulesJSON(t, ctx, dsn, adminGlobal),
		"post-0040: admin role unchanged (`*` already expands to full CRUD)")
	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["read","list","get"]}]`,
		roleRulesJSON(t, ctx, dsn, viewGlobal),
		"post-0040: view role unchanged (read-only already carries v_get/v_list)")

	// Per-resource edit roles likewise get the read verbs (spot-check iam.project.edit
	// and vpc.network.edit — the narrow `*.edit` tier roles seeded by 0031).
	for name, id := range map[string]string{
		"iam.project.edit": "rol" + md5hex17("iam.project.edit"),
		"vpc.network.edit": "rol" + md5hex17("vpc.network.edit"),
		"iam.account.edit": "rol" + md5hex17("iam.account.edit"),
	} {
		rules := roleRulesJSON(t, ctx, dsn, id)
		assert.Contains(t, rules, `"get"`, "%s must include get after 0040", name)
		assert.Contains(t, rules, `"list"`, "%s must include list after 0040", name)
		assert.Contains(t, rules, `"update"`, "%s must include update after 0040", name)
	}

	// ── round-trip: Down (40→39) restores [update]; Up (39→40) re-applies ─────
	require.NoError(t, goose.DownTo(db, ".", 39))
	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["update"]}]`,
		roleRulesJSON(t, ctx, dsn, editGlobal),
		"0040 Down restores edit role to [update]")
	require.NoError(t, goose.UpTo(db, ".", 40))
	assert.JSONEq(t, `[{"module":"*","resources":["*"],"verbs":["get","list","update"]}]`,
		roleRulesJSON(t, ctx, dsn, editGlobal),
		"0040 Up re-applies [get,list,update] (idempotent round-trip)")
}
