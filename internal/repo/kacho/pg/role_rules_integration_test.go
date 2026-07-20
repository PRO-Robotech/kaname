// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_rules_integration_test.go — integration tests for the role.rules model
// (testcontainers Postgres 16):
//   - A-01: persist rules + compiled permissions → Get round-trip (rules survive).
//   - A-12: compiled ≤1024 accepted; the DB CHECK iam_permissions_valid does not
//           reject a 300-permission compiled set (cap-raise applied).
//   - A-13: direct INSERT bypassing the use-case still rejected by the
//           iam_rules_valid shape CHECK (within-DB invariant, ban #10).
//   - A-16: Role.Delete with a binding → FAILED_PRECONDITION via FK 23503
//           ("role is in use by access bindings"), without pgx leak; after the
//           binding is HARD-deleted (purged), Delete succeeds and Get → NotFound.
//           Plus a concurrent Role.Delete ∥ grant race (FK serializes one winner).
//
// Run with the full integration build (NOT -short).

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// A-01: a role authored with mixed-arm rules round-trips its rules[] AND its
// compiled permissions through Insert → Get.
func TestRole_A01_RulesRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ra01")
	acc := seedAccount(t, ctx, repo, "acc-ra01", uid)

	rules := domain.Rules{
		{Module: "compute", Resources: []string{"image"}, Verbs: []string{"get"}},
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, MatchLabels: map[string]string{"env": "prod"}},
		{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get", "update"}, ResourceNames: []string{"addr5k", "addr9m"}},
	}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("network_ops"),
		Rules:       rules,
		Permissions: compiled,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	require.Len(t, inserted.Rules, 3)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Roles().Get(ctx, inserted.ID)
	require.NoError(t, err)

	require.Len(t, got.Rules, 3, "rules[] must round-trip through the rules JSONB column")
	assert.Equal(t, "compute", got.Rules[0].Module)
	assert.Equal(t, map[string]string{"env": "prod"}, got.Rules[1].MatchLabels)
	assert.Equal(t, []string{"addr5k", "addr9m"}, got.Rules[2].ResourceNames)
	// Stored compiled set excludes the matchLabels arm.
	assert.Contains(t, got.Permissions, domain.Permission("compute.image.*.get"))
	assert.Contains(t, got.Permissions, domain.Permission("vpc.address.addr5k.update"))
	for _, p := range got.Permissions {
		assert.NotContains(t, string(p), "vpc.subnet.", "matchLabels arm must not compile")
	}
}

// A-12: a role whose rules compile to 300 permissions inserts cleanly — the DB
// CHECK iam_permissions_valid no longer rejects >256 (cap-raise to 1024).
func TestRole_A12_CapRaise300Compiled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ra12")
	acc := seedAccount(t, ctx, repo, "acc-ra12", uid)

	// One module per rule: 4 rules (one per real platform module) ×
	// 15 resources × 5 verbs = 300 anchor compiled permissions. Each list ≤16 so
	// the rules-shape CHECK (iam_rules_valid) is satisfied; the point is that 300
	// compiled permissions pass iam_permissions_valid after the cap-raise
	// (256→1024). Distinct modules keep the per-rule one-module invariant while
	// reaching the 300-permission compiled total.
	mods := []string{"iam", "vpc", "compute", "loadbalancer"}
	res := make([]string, 15)
	for i := range res {
		res[i] = "r" + string(rune('a'+i))
	}
	verbs := make([]string, 5)
	for i := range verbs {
		verbs[i] = "v" + string(rune('a'+i))
	}
	rules := make(domain.Rules, 0, len(mods))
	for _, m := range mods {
		rules = append(rules, domain.Rule{Module: m, Resources: res, Verbs: verbs})
	}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	require.Len(t, compiled, 300)

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("big_role"),
		Rules:       rules,
		Permissions: compiled,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.RolesW().Insert(ctx, r)
	require.NoError(t, err, "300 compiled permissions must pass iam_permissions_valid after cap-raise")
	require.NoError(t, w.Commit(ctx))
}

// A-13: a direct INSERT of a malformed rules array (empty verbs) bypassing the
// use-case is rejected by the DB CHECK iam_rules_valid (within-DB shape parity).
func TestRole_A13_DirectInsertMalformedRulesRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ra13")
	acc := seedAccount(t, ctx, repo, "acc-ra13", uid)

	cases := []struct {
		name  string
		rules string
	}{
		{"empty verbs", `[{"modules":["vpc"],"resources":["subnet"],"verbs":[]}]`},
		{"missing resources", `[{"modules":["vpc"],"verbs":["get"]}]`},
		{"names AND labels", `[{"modules":["vpc"],"resources":["subnet"],"verbs":["get"],"resource_names":["s1"],"match_labels":{"env":"prod"}}]`},
		{"too many rules (65)", "[" + repeatRuleJSON(65) + "]"},
		{"empty match_labels", `[{"modules":["vpc"],"resources":["subnet"],"verbs":["get"],"match_labels":{}}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `
				INSERT INTO roles (id, account_id, name, description, permissions, rules, created_at)
				VALUES ($1, $2, $3, '', '["vpc.subnet.*.get"]'::jsonb, $4::jsonb, now())`,
				ids.NewID(domain.PrefixRole), string(acc.ID), "bad_"+ids.NewID(domain.PrefixRole)[:8], c.rules,
			)
			require.Error(t, err, "iam_rules_valid CHECK must reject malformed rules at the DB level")
			assert.Contains(t, err.Error(), "roles_rules_valid")
		})
	}
}

// A-16: Role.Delete with an active access binding → FAILED_PRECONDITION via the
// FK 23503 (no software TOCTOU); after the binding is removed Delete succeeds and
// the role is gone. Also: a direct DELETE on the bound role is refused by the FK.
func TestRole_A16_DeleteRestrictByFK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ra16")
	acc := seedAccount(t, ctx, repo, "acc-ra16", uid)
	r := seedCustomRole(t, ctx, repo, acc.ID, "in_use_role")

	abID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id)
		VALUES ($1, 'user', $2, $3, 'account', $4)`,
		abID, string(uid), string(r.ID), string(acc.ID),
	)
	require.NoError(t, err)

	// (1) Delete via repo → FAILED_PRECONDITION with the A-16 text, no pgx leak.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.RolesW().Delete(ctx, r.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
	assert.Contains(t, err.Error(), "role is in use by access bindings")
	assert.NotContains(t, err.Error(), "SQLSTATE", "must not leak pgx/SQL text")
	assert.NotContains(t, err.Error(), "access_bindings_role_fk", "must not leak constraint name")

	// (2) direct DELETE on the bound role is refused by the FK RESTRICT (23503).
	_, derr := pool.Exec(ctx, `DELETE FROM roles WHERE id = $1`, string(r.ID))
	require.Error(t, derr, "FK access_bindings_role_fk RESTRICT must block a direct DELETE")

	// (3) remove the binding, then Delete succeeds and the role is gone.
	_, err = pool.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, abID)
	require.NoError(t, err)

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.RolesW().Delete(ctx, r.ID))
	require.NoError(t, w2.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	_, gerr := rd.Roles().Get(ctx, r.ID)
	require.Error(t, gerr)
	assert.True(t, stderrors.Is(gerr, iamerr.ErrNotFound))
}

// A-10 (label-only, positive): a role whose ONLY rule is ARM_LABELS compiles to an
// EMPTY permission set (matchLabels is not compiled). It MUST persist
// through Insert and round-trip its rules[] on Get. Before the fix the DB CHECK
// iam_permissions_valid rejected an empty permissions array even for a rules-role,
// falsely blocking the role.
func TestRole_A10_LabelOnlyRolePersists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ral0")
	acc := seedAccount(t, ctx, repo, "acc-ral0", uid)

	rules := domain.Rules{
		{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"tier": "gold"}},
	}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	require.Empty(t, compiled, "label-only rule must compile to an EMPTY permission set")

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("label_only"),
		Rules:       rules,
		Permissions: compiled, // empty
	}
	// (a) domain.Role.Validate accepts a rules-role with empty compiled permissions.
	require.NoError(t, r.Validate(), "label-only rules-role must pass domain.Role.Validate")

	// (b) Insert persists it (DB CHECK roles_permissions_valid must allow an empty
	// permissions array WHEN rules is non-empty).
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err, "label-only role must persist (empty permissions allowed for a rules-role)")
	require.NoError(t, w.Commit(ctx))
	require.Len(t, inserted.Rules, 1)
	require.Empty(t, inserted.Permissions)

	// (c) Get round-trips the rules[] (public authority) with empty permissions.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Roles().Get(ctx, inserted.ID)
	require.NoError(t, err)
	require.Len(t, got.Rules, 1)
	assert.Equal(t, map[string]string{"tier": "gold"}, got.Rules[0].MatchLabels)
	assert.Empty(t, got.Permissions, "label-only role carries no compiled permissions")
}

// A direct INSERT of a LEGACY permissions-only role (rules='[]') with an EMPTY
// permissions array must STILL be rejected by the DB CHECK — the empty-permissions
// relaxation is scoped to rules-roles only (rules non-empty). This pins that the
// cap-raise migration does not weaken the legacy invariant.
func TestRole_LegacyEmptyPermissionsRejectedByDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "rale")
	acc := seedAccount(t, ctx, repo, "acc-rale", uid)

	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions, rules, created_at)
		VALUES ($1, $2, $3, '', '[]'::jsonb, '[]'::jsonb, now())`,
		ids.NewID(domain.PrefixRole), string(acc.ID), "legacy_empty",
	)
	require.Error(t, err, "legacy permissions-only role with empty permissions AND empty rules must be rejected")
	assert.Contains(t, err.Error(), "roles_permissions_valid")
}

// A-16 concurrency: Role.Delete ∥ AccessBinding grant on the
// SAME role race. The FK access_bindings_role_fk (ON DELETE RESTRICT) + the row
// lock serialize the two writer-txs so exactly ONE wins:
//   - if the grant commits first → the DELETE trips the FK (23503 → FailedPrecondition);
//   - if the DELETE commits first → the grant's FK insert sees no role (23503 →
//     FailedPrecondition "Role not found").
//
// The losing goroutine never silently no-ops (second-writer-wins is impossible).
func TestRole_A16_ConcurrentDeleteVsGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ra16c")
	acc := seedAccount(t, ctx, repo, "acc-ra16c", uid)

	const iterations = 12
	var deleteWins, grantWins int
	for i := 0; i < iterations; i++ {
		r := seedCustomRole(t, ctx, repo, acc.ID, fmt.Sprintf("race_role_%d", i))

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		var delErr, grantErr error
		// goroutine 1 — Role.Delete in its own writer-tx.
		go func() {
			defer wg.Done()
			<-start
			w, werr := repo.Writer(ctx)
			if werr != nil {
				delErr = werr
				return
			}
			if derr := w.RolesW().Delete(ctx, r.ID); derr != nil {
				_ = w.Rollback(ctx)
				delErr = derr
				return
			}
			delErr = w.Commit(ctx)
		}()
		// goroutine 2 — AccessBinding grant (INSERT referencing the role) in its
		// own writer-tx.
		abID := ids.NewID(domain.PrefixAccessBinding)
		go func() {
			defer wg.Done()
			<-start
			w, werr := repo.Writer(ctx)
			if werr != nil {
				grantErr = werr
				return
			}
			_, gerr := w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
				ID:           domain.AccessBindingID(abID),
				SubjectType:  domain.SubjectTypeUser,
				SubjectID:    domain.SubjectID(uid),
				RoleID:       r.ID,
				ResourceType: "account",
				ResourceID:   string(acc.ID),
				Status:       domain.AccessBindingStatusActive,
			})
			if gerr != nil {
				_ = w.Rollback(ctx)
				grantErr = gerr
				return
			}
			grantErr = w.Commit(ctx)
		}()

		close(start)
		wg.Wait()

		// Exactly one side succeeds; the loser fails FAILED_PRECONDITION (FK 23503).
		switch {
		case delErr == nil && grantErr != nil:
			deleteWins++
			assert.True(t, stderrors.Is(grantErr, iamerr.ErrFailedPrecondition),
				"grant loser must be FailedPrecondition (FK on a deleted role), got %v", grantErr)
			// role is gone — grant must not have left a row.
			rd, _ := repo.Reader(ctx)
			_, gerr := rd.Roles().Get(ctx, r.ID)
			_ = rd.Rollback(ctx)
			assert.True(t, stderrors.Is(gerr, iamerr.ErrNotFound))
		case grantErr == nil && delErr != nil:
			grantWins++
			assert.True(t, stderrors.Is(delErr, iamerr.ErrFailedPrecondition),
				"delete loser must be FailedPrecondition (FK RESTRICT, role still bound), got %v", delErr)
			assert.Contains(t, delErr.Error(), "role is in use by access bindings")
			// clean up the surviving binding so the next iteration's role can be seeded.
			_, _ = pool.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, abID)
		default:
			t.Fatalf("expected exactly one winner: delErr=%v grantErr=%v", delErr, grantErr)
		}
	}
	t.Logf("race outcomes over %d iterations: deleteWins=%d grantWins=%d", iterations, deleteWins, grantWins)
}

func repeatRuleJSON(n int) string {
	const one = `{"modules":["vpc"],"resources":["subnet"],"verbs":["get"]}`
	out := one
	for i := 1; i < n; i++ {
		out += "," + one
	}
	return out
}
