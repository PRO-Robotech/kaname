// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_system_role_selectors_integration_test.go — keystone RBAC authz-fix:
// generalize owner-only role_rule_selectors seeding to ALL materializing system roles
// (RBAC explicit-model 2026, Contract-A FLAT INDEX).
//
// Root cause (verified): the generic system roles (`admin`/`edit`/`view`, per-domain
// `vpc.network.admin`…) carry rules[] but — unlike the owner role (migrations
// 0038/0039/0043) and custom roles (ReplaceRuleSelectors on Role.Create/Update) — have
// NO role_rule_selectors rows. Discovery (SelectorBindingsMatchingObject +
// ListSelectorBindingIDs) JOINs role_rule_selectors, so a project-scoped grantee
// (`edit`@PROJECT) never materializes v_* on a freshly-created object → 403 forever on
// its own resource + owner-tuple op-gate fails-closed.
//
// Coverage (RED → GREEN):
//   01 — project-editor forward-materializes v_update on a fresh project resource
//        (migration-seeded edit selector, no boot-backfill dependency).
//   02 — the generalized backfill projects EVERY system role (wildcard admin/edit/view
//        + per-domain vpc.network.admin).
//   03 — scope containment: a project-A editor does NOT over-grant onto project-B.
//   04 — idempotent UPSERT + stale-fp self-heal.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// systemRoleID computes the deterministic catalog-role id ('rol'||md5(name)[:17]) that
// migrations 0001/0031 seed — the same expression `'rol' || substr(md5(name),1,17)`.
func systemRoleID(name string) domain.RoleID {
	sum := md5.Sum([]byte(name))
	return domain.RoleID("rol" + hex.EncodeToString(sum[:])[:17])
}

// selectorRowCount counts role_rule_selectors rows for a role.
func selectorRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, string(roleID)).Scan(&n))
	return n
}

// selectorRowCountFP counts role_rule_selectors rows for a (role, rule_fp).
func selectorRowCountFP(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID domain.RoleID, fp string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1 AND rule_fp = $2`,
		string(roleID), fp).Scan(&n))
	return n
}

// selectorObjectTypes returns the union of object_types across a role's anchor selector
// rows (system roles carry a single anchor selector, so this is that row's types).
func selectorObjectTypes(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID domain.RoleID) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT unnest(object_types) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, string(roleID))
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ty string
		require.NoError(t, rows.Scan(&ty))
		out = append(out, ty)
	}
	require.NoError(t, rows.Err())
	return out
}

// Test 01 — a subject bound to the SYSTEM `edit` role @ PROJECT must forward-materialize
// v_update (+ editor tier) on a freshly-registered project resource, via the object-
// change fast-path (SelectorBindingsMatchingObject → ReconcileObject) — the migration-
// seeded edit selector, NOT the best-effort boot backfill.
//
// RED before the fix: `edit` has no role_rule_selectors row → the binding is invisible
// to SelectorBindingsMatchingObject → 0 tuples materialized → the editor 403s on its
// own resource forever.
func TestSysRoleSel_01_ProjectEditor_ForwardMaterializesVUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sr1o")
	member := mustSeedUser(t, ctx, pool, "sr1m")
	acc := seedAccount(t, ctx, repo, "acc-sr1", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-sr1")

	// Bind the SYSTEM `edit` role at PROJECT scope (the project-editor grant) —
	// WITHOUT running the boot backfill: the only source of the edit selector must be
	// the migration seed.
	bID := insertThinBindingScope(t, ctx, repo, member, systemRoleID("edit"),
		"project", string(prj.ID), domain.ScopeProject)

	// A vpc.network registered under the project (mirror-fed RegisterResource landing) →
	// drives the object-change forward fast-path.
	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nSR1", string(prj.ID), string(acc.ID), nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nSR1"))

	memberUser := "user:" + string(member)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, memberUser, "v_update", "vpc_network:nSR1"),
		"project-editor must forward-materialize v_update on a fresh project resource "+
			"(migration-seeded edit selector, keystone fix)")
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, memberUser, "editor", "vpc_network:nSR1"),
		"project-editor must carry the editor tier on the fresh resource")
}

// Test 02 — the generalized backfill (SyncAllSystemRoleSelectors) projects EVERY
// materializing system role's rules into role_rule_selectors: the wildcard catalog trio
// (admin/edit/view) AND a per-domain role (vpc.network.admin). The per-domain role is
// the discriminator — the migration seeds ONLY the wildcard trio, so vpc.network.admin
// is seeded EXCLUSIVELY by the generalized boot backfill.
//
// RED before the fix: SyncAllSystemRoleSelectors seeds ONLY owner → the generic system
// roles have no selector rows.
func TestSysRoleSel_02_Backfill_ProjectsAllSystemRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))

	for _, name := range []string{"admin", "edit", "view", "vpc.network.admin"} {
		assert.GreaterOrEqual(t, selectorRowCount(t, ctx, pool, systemRoleID(name)), 1,
			"system role %s must have a role_rule_selectors row after the generalized backfill", name)
	}

	// vpc.network.admin is a per-domain anchor role the MIGRATION never seeds — its
	// selector proves the generalized Go projection ran (arm-aware, dotted-type).
	types := selectorObjectTypes(t, ctx, pool, systemRoleID("vpc.network.admin"))
	assert.Contains(t, types, "vpc.network",
		"per-domain vpc.network.admin selector must select vpc.network (backfill projection)")

	// The wildcard `edit` selector expands to the full materializable type set.
	editTypes := selectorObjectTypes(t, ctx, pool, systemRoleID("edit"))
	assert.Contains(t, editTypes, "vpc.network")
	assert.Contains(t, editTypes, "compute.instance")
	assert.Contains(t, editTypes, "iam.project")
}

// Test 03 — scope containment (security, NOT over-grant): a subject bound `edit`@project-A
// materializes v_update on project-A resources but NOT on project-B resources. The
// reconciler's per-object IsContainedIn re-verify bounds the wildcard to the binding's
// scope; the project-A editor never leaks onto a sibling project.
//
// The positive arm (project-A) is RED before the fix (no edit selector → nothing
// materializes); the negative arm (project-B) is the containment guard.
func TestSysRoleSel_03_ProjectEditor_ScopeContainment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sr3o")
	member := mustSeedUser(t, ctx, pool, "sr3m") // S_A — project-A editor
	acc := seedAccount(t, ctx, repo, "acc-sr3", owner)
	prjA := seedProject(t, ctx, repo, acc.ID, "prj-a-sr3")
	prjB := seedProject(t, ctx, repo, acc.ID, "prj-b-sr3")

	bID := insertThinBindingScope(t, ctx, repo, member, systemRoleID("edit"),
		"project", string(prjA.ID), domain.ScopeProject)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "vpc.network", "nA_sr3", string(prjA.ID), string(acc.ID), nil, now)
	seedMirrorRow(t, ctx, pool, "vpc.network", "nB_sr3", string(prjB.ID), string(acc.ID), nil, now)
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nA_sr3"))
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "nB_sr3"))

	memberUser := "user:" + string(member)
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, bID, memberUser, "v_update", "vpc_network:nA_sr3"),
		"project-A editor materializes v_update on its own project's resource")
	assert.False(t,
		ledgerHasTuple(t, ctx, pool, bID, memberUser, "v_update", "vpc_network:nB_sr3"),
		"project-A editor must NOT over-grant onto project-B's resource (scope containment)")
}

// Test 04 — idempotency + stale-fp self-heal. Re-running the selector backfill is a
// no-op (UPSERT keyed by (role_id, rule_fp)); a stale selector fingerprint (one no
// current rule produces, e.g. after a rules[] edit changed the fingerprint) is
// self-healed away so discovery never matches a defunct selector.
//
// RED before the fix: SyncAllSystemRoleSelectors seeds only owner → edit has 0 selector
// rows (expected 1) and the stale row is never reaped.
func TestSysRoleSel_04_Idempotent_SelfHeal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	editRole := systemRoleID("edit")

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))
	require.Equal(t, 1, selectorRowCount(t, ctx, pool, editRole),
		"edit role carries exactly one anchor selector")

	// Idempotent: a second run makes no change.
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))
	assert.Equal(t, 1, selectorRowCount(t, ctx, pool, editRole),
		"re-running the selector backfill is a no-op (idempotent UPSERT)")

	// Self-heal: inject a STALE selector row (a fingerprint no current rule produces).
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, resource_names, match_labels)
		 VALUES ($1, 'deadbeefstalefp', 'anchor', ARRAY['vpc.network']::text[], '{}'::text[], '{}'::jsonb)`,
		string(editRole))
	require.NoError(t, err)
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))
	assert.Equal(t, 0, selectorRowCountFP(t, ctx, pool, editRole, "deadbeefstalefp"),
		"a stale selector fingerprint (no current rule) must be self-healed away")
	assert.Equal(t, 1, selectorRowCount(t, ctx, pool, editRole),
		"self-heal leaves exactly the current selector")
}
