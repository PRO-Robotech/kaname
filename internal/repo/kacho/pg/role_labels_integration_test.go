// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_labels_integration_test.go — unify IAM label-scope integration
// coverage for the Role resource: own-table labels round-trip через mask-driven
// Update, iam-direct ARM_LABELS materialization on iam.role (matching role-object
// set only), foreign-account containment rejection, eager fall-out on label
// removal, and concurrent UpdateLabels (last-writer-wins под row-lock, reconcile
// idempotent).
//
// Role.labels — tenant-facing метки САМОГО ресурса Role; их НЕ путать с
// Rule.MatchLabels (object-selector внутри грант-правила). Здесь грант-роль несет
// rule {resources:[role], matchLabels:{team:payments}}, а объект-роли несут
// own-resource labels {team:...} — материализуется именно объект-роль с matching
// own-labels.
//
// Scenarios: labels round-trip, label-grant → matching role set, foreign-account
// role not materialized, label removed → eager fall-out, concurrent UpdateLabels.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// setRoleLabels writes labels on a roles row directly (iam-direct feed source).
func setRoleLabels(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rid string, labels map[string]string) {
	t.Helper()
	payload := jsonObject(labels)
	_, err := pool.Exec(ctx,
		`UPDATE kacho_iam.roles SET labels = $2::jsonb WHERE id = $1`, rid, payload)
	require.NoError(t, err, "set role labels")
}

// ── labels round-trip through the repo mask-driven Update writer ────

func TestRoleLabels_T33UPD01_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rl-rt")
	acc := seedAccount(t, ctx, repo, "acc-rl-rt", owner)
	rid := domain.RoleID(seedNativeRole(t, ctx, pool, acc.ID, "rt_role"))

	// Fresh role row — empty labels (DEFAULT '{}').
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got0, err := rd.Roles().Get(ctx, rid)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	assert.Empty(t, got0.Labels, "fresh role row has empty labels")

	// Mask-driven Update applies labels (the sole mutable selector-facing field here).
	want := domain.Labels{"team": "payments", "tier": "gold"}
	target := got0
	target.Labels = want
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.RolesW().Update(ctx, target, []string{"labels"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, want, updated.Labels)

	// Get round-trips the persisted labels (own-table column).
	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd2.Roles().Get(ctx, rid)
	_ = rd2.Rollback(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, got.Labels, "labels round-trip through roles.labels column")

	// A labels-only update leaves the role's policy + identity fields untouched.
	assert.Equal(t, got0.Name, got.Name, "name untouched by labels update")
	assert.Equal(t, got0.AccountID, got.AccountID, "account_id untouched by labels update")
	assert.Equal(t, len(got0.Rules), len(got.Rules), "rules untouched by labels update")
}

// ── label-grant on iam.role materializes only the matching, in-scope role-object
// set (not the non-matching one, not the foreign-account one) via the iam-direct
// ARM_LABELS reconcile path. ─────────────

func TestRoleLabels_T33MAT01_LabelGrantMaterializesMatchingSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "rlmat01")
	rec, _ := newReconciler(pool)

	// Two object-roles in the granting account: rol1{team:payments}, rol2{team:billing}.
	rol1 := seedNativeRole(t, ctx, pool, fx.accID, "rlmat_a")
	rol2 := seedNativeRole(t, ctx, pool, fx.accID, "rlmat_b")
	setRoleLabels(t, ctx, pool, rol1, map[string]string{"team": "payments"})
	setRoleLabels(t, ctx, pool, rol2, map[string]string{"team": "billing"})

	// A foreign-account role that also matches by label but is out of scope.
	foreignOwner := mustSeedUser(t, ctx, pool, "rl-foreign-owner")
	foreignAcc := seedAccount(t, ctx, fx.repo, "acc-rl-foreign", foreignOwner)
	rolForeign := seedNativeRole(t, ctx, pool, foreignAcc.ID, "rlmat_f")
	setRoleLabels(t, ctx, pool, rolForeign, map[string]string{"team": "payments"})

	// Account-scoped rules-role granting iam.role.{get,list} by label team=payments.
	rule := domain.Rule{
		Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "rlmat01grant", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// rol1 matches {team:payments} under acc-A → ACTIVE member + visibility tuple.
	st1, ok1 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rol1)
	require.True(t, ok1, "rol1{team:payments} materialized as member (iam-direct ARM_LABELS)")
	assert.Equal(t, domain.VerificationActive, st1)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_role:"+rol1), 1,
		"materialized iam.role member emits the v_get/v_list tuple")

	// rol2 does NOT match {team:billing} → not a member.
	_, ok2 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rol2)
	assert.False(t, ok2, "rol2{team:billing} does not match the selector → not a member")

	// rolForeign matches by label/type but is under acc-OTHER → out of
	// scope → REJECTED member (containment audit, NO FGA write-tuple).
	stF, okF := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rolForeign)
	require.True(t, okF, "foreign-account candidate is recorded as a containment verdict")
	assert.Equal(t, domain.VerificationRejected, stF,
		"foreign-account role matches labels but is out of scope → REJECTED (containment)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_role:"+rolForeign),
		"REJECTED foreign-account role gains NO visibility tuple")
}

// ── label removed on the role → eager fall-out (member GONE,
// tuple-delete emitted) via the iam-direct fast-path ReconcileObject. ────────────

func TestRoleLabels_T33REVOKE01_LabelRemovedEagerFallout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "rlrev01")
	rec, _ := newReconciler(pool)

	rol1 := seedNativeRole(t, ctx, pool, fx.accID, "rlrev_a")
	setRoleLabels(t, ctx, pool, rol1, map[string]string{"team": "payments"})

	rule := domain.Rule{
		Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "rlrev01grant", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rol1)
	require.True(t, ok, "rol1 materialized before label removal")
	require.Equal(t, domain.VerificationActive, st)

	// When: the label is removed on the role (UpdateRole writes labels={} and the
	// use-case co-commits a reconcile event; here we drive the own-resource label
	// change + the fast-path ReconcileObject directly).
	setRoleLabels(t, ctx, pool, rol1, map[string]string{})
	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", rol1))

	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rol1)
	assert.False(t, stillMember, "label removed → member eager-revoked (iam-direct fast-path)")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "iam_role:"+rol1), 1,
		"label removed → FGA tuple-delete emitted (visibility revoked)")
}

// ── N concurrent mask-driven Update labels on one role row →
// deterministic final state under the row-lock (last-writer-wins, not TOCTOU);
// reconcile against the final label set is idempotent. ───────────────────────────

func TestRoleLabels_T33CONC01_ConcurrentUpdateLabels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "rlconc01")
	rec, _ := newReconciler(pool)

	rolC := seedNativeRole(t, ctx, pool, fx.accID, "rlconc_c")

	rule := domain.Rule{
		Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "rlconc01grant", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var labels domain.Labels
			if i%2 == 0 {
				labels = domain.Labels{"team": "payments"}
			} else {
				labels = domain.Labels{}
			}
			w, werr := fx.repo.Writer(ctx)
			if werr != nil {
				errs <- werr
				return
			}
			target := domain.Role{ID: domain.RoleID(rolC), Labels: labels}
			if _, uerr := w.RolesW().Update(ctx, target, []string{"labels"}); uerr != nil {
				_ = w.Rollback(ctx)
				errs <- uerr
				return
			}
			errs <- w.Commit(ctx)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "concurrent mask-driven Update labels must not error (row-lock serializes)")
	}

	rdr, err := fx.repo.Reader(ctx)
	require.NoError(t, err)
	final, err := rdr.Roles().Get(ctx, domain.RoleID(rolC))
	_ = rdr.Rollback(ctx)
	require.NoError(t, err)

	matched := len(final.Labels) == 1 && final.Labels["team"] == "payments"
	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", rolC))
	_, isMember := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rolC)
	assert.Equal(t, matched, isMember,
		"final membership deterministically matches the final label set (no stuck/stale membership)")

	require.NoError(t, rec.ReconcileObject(ctx, "iam.role", rolC))
	_, isMember2 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.role", rolC)
	assert.Equal(t, isMember, isMember2, "reconcile idempotent — second pass is a no-op")
}
