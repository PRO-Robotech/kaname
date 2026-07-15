// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_labels_integration_test.go — unify IAM label-scope
// integration coverage for the AccessBinding resource: own-table labels
// round-trip через repo UpdateLabels, iam-direct ARM_LABELS materialization on
// iam.accessBinding (matching binding-object set only), foreign-account
// containment rejection, eager fall-out on label removal, and concurrent
// UpdateLabels (last-writer-wins под row-lock, reconcile idempotent).
//
// AccessBinding.labels — tenant-facing метки САМОГО binding-ресурса; грант-роль
// несет rule {resources:[accessBinding], matchLabels:{stage:prod}}, а
// binding-объекты несут own-resource labels {stage:...} — материализуется именно
// binding-объект с matching own-labels (catalog-видимость через viewer ∪ v_list).
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
)

// setABLabels writes labels on an access_bindings row directly (iam-direct feed source).
func setABLabels(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid string, labels map[string]string) {
	t.Helper()
	payload := jsonObject(labels)
	_, err := pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings SET labels = $2::jsonb WHERE id = $1`, bid, payload)
	require.NoError(t, err, "set access_binding labels")
}

// ── labels round-trip through the repo UpdateLabels writer ──────────

func TestAccessBindingLabels_T33UPD01_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ablrt")

	// A binding-object to relabel (a thin account-scoped binding).
	subj := mustSeedUser(t, ctx, pool, "abl-subj")
	objBID := insertThinBindingScope(t, ctx, fx.repo, subj, fx.role, "project", string(fx.prj), domain.ScopeProject)

	// Fresh binding row — empty labels (DEFAULT '{}').
	rd, err := fx.repo.Reader(ctx)
	require.NoError(t, err)
	got0, err := rd.AccessBindings().Get(ctx, objBID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	assert.Empty(t, got0.Labels, "fresh binding row has empty labels")

	// UpdateLabels sets the tenant-facing labels (mutable, widened set).
	want := domain.Labels{"stage": "prod", "team": "payments"}
	w, err := fx.repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.AccessBindingsW().UpdateLabels(ctx, objBID, want)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, want, updated.Labels)

	// Get round-trips the persisted labels; immutable binding fields untouched.
	rd2, err := fx.repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd2.AccessBindings().Get(ctx, objBID)
	_ = rd2.Rollback(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, got.Labels, "labels round-trip through access_bindings.labels column")
	assert.Equal(t, got0.RoleID, got.RoleID, "role_id untouched by labels update")
	assert.Equal(t, got0.SubjectID, got.SubjectID, "subject_id untouched by labels update")
	assert.Equal(t, got0.ResourceID, got.ResourceID, "resource_id untouched by labels update")
}

// ── label-grant on iam.accessBinding
// materializes only the matching, in-scope binding-object set. ───────────────────

func TestAccessBindingLabels_T33MAT01_LabelGrantMaterializesMatchingSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ablmat01")
	rec, _ := newReconciler(pool)

	// Two binding-objects in the granting account: acb1{stage:prod}, acb2{stage:dev}.
	s1 := mustSeedUser(t, ctx, pool, "ablmat-s1")
	s2 := mustSeedUser(t, ctx, pool, "ablmat-s2")
	acb1 := insertThinBindingScope(t, ctx, fx.repo, s1, fx.role, "account", string(fx.accID), domain.ScopeAccount)
	acb2 := insertThinBindingScope(t, ctx, fx.repo, s2, fx.role, "account", string(fx.accID), domain.ScopeAccount)
	setABLabels(t, ctx, pool, string(acb1), map[string]string{"stage": "prod"})
	setABLabels(t, ctx, pool, string(acb2), map[string]string{"stage": "dev"})

	// A foreign-account binding-object matching by label but out of scope.
	foreignOwner := mustSeedUser(t, ctx, pool, "abl-foreign-owner")
	foreignAcc := seedAccount(t, ctx, fx.repo, "acc-abl-foreign", foreignOwner)
	sf := mustSeedUser(t, ctx, pool, "ablmat-sf")
	foreignRole := domain.RoleID(seedNativeRole(t, ctx, pool, foreignAcc.ID, "ablfrole"))
	acbForeign := insertThinBindingScope(t, ctx, fx.repo, sf, foreignRole, "account", string(foreignAcc.ID), domain.ScopeAccount)
	setABLabels(t, ctx, pool, string(acbForeign), map[string]string{"stage": "prod"})

	// Account-scoped rules-role granting iam.accessBinding.{get,list} by stage=prod.
	rule := domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"stage": "prod"},
	}
	fp := rule.Fingerprint()
	grantRole := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ablmat01grant", domain.Rules{rule})
	grantBID := insertThinBindingScope(t, ctx, fx.repo, fx.member, grantRole, "account", string(fx.accID), domain.ScopeAccount)

	require.NoError(t, rec.ReconcileBinding(ctx, grantBID))

	// acb1 matches {stage:prod} under acc-A → ACTIVE member + visibility tuple.
	st1, ok1 := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acb1))
	require.True(t, ok1, "acb1{stage:prod} materialized as member (iam-direct ARM_LABELS)")
	assert.Equal(t, domain.VerificationActive, st1)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_access_binding:"+string(acb1)), 1,
		"materialized iam.accessBinding member emits the v_get/v_list tuple")

	// acb2 does NOT match {stage:dev} → not a member.
	_, ok2 := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acb2))
	assert.False(t, ok2, "acb2{stage:dev} does not match the selector → not a member")

	// foreign-account binding matches by label/type but out of scope →
	// REJECTED member (containment audit, NO FGA write-tuple).
	stF, okF := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acbForeign))
	require.True(t, okF, "foreign-account candidate is recorded as a containment verdict")
	assert.Equal(t, domain.VerificationRejected, stF,
		"foreign-account binding matches labels but is out of scope → REJECTED (containment)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_access_binding:"+string(acbForeign)),
		"REJECTED foreign-account binding gains NO visibility tuple")
}

// ── label removed on the binding → eager fall-out. ───────────────

func TestAccessBindingLabels_T33REVOKE01_LabelRemovedEagerFallout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ablrev01")
	rec, _ := newReconciler(pool)

	s1 := mustSeedUser(t, ctx, pool, "ablrev-s1")
	acb1 := insertThinBindingScope(t, ctx, fx.repo, s1, fx.role, "account", string(fx.accID), domain.ScopeAccount)
	setABLabels(t, ctx, pool, string(acb1), map[string]string{"stage": "prod"})

	rule := domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"stage": "prod"},
	}
	fp := rule.Fingerprint()
	grantRole := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ablrev01grant", domain.Rules{rule})
	grantBID := insertThinBindingScope(t, ctx, fx.repo, fx.member, grantRole, "account", string(fx.accID), domain.ScopeAccount)

	require.NoError(t, rec.ReconcileBinding(ctx, grantBID))
	st, ok := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acb1))
	require.True(t, ok, "acb1 materialized before label removal")
	require.Equal(t, domain.VerificationActive, st)

	setABLabels(t, ctx, pool, string(acb1), map[string]string{})
	require.NoError(t, rec.ReconcileObject(ctx, "iam.accessBinding", string(acb1)))

	_, stillMember := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acb1))
	assert.False(t, stillMember, "label removed → member eager-revoked (iam-direct fast-path)")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "iam_access_binding:"+string(acb1)), 1,
		"label removed → FGA tuple-delete emitted (visibility revoked)")
}

// ── N concurrent UpdateLabels on one binding row → deterministic
// final state under the row-lock (last-writer-wins, not TOCTOU); reconcile
// idempotent against the final label set. ────────────────────────────────────────

func TestAccessBindingLabels_T33CONC01_ConcurrentUpdateLabels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ablconc01")
	rec, _ := newReconciler(pool)

	sc := mustSeedUser(t, ctx, pool, "ablconc-sc")
	acbC := insertThinBindingScope(t, ctx, fx.repo, sc, fx.role, "account", string(fx.accID), domain.ScopeAccount)

	rule := domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"stage": "prod"},
	}
	fp := rule.Fingerprint()
	grantRole := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ablconc01grant", domain.Rules{rule})
	grantBID := insertThinBindingScope(t, ctx, fx.repo, fx.member, grantRole, "account", string(fx.accID), domain.ScopeAccount)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var labels domain.Labels
			if i%2 == 0 {
				labels = domain.Labels{"stage": "prod"}
			} else {
				labels = domain.Labels{}
			}
			w, werr := fx.repo.Writer(ctx)
			if werr != nil {
				errs <- werr
				return
			}
			if _, uerr := w.AccessBindingsW().UpdateLabels(ctx, acbC, labels); uerr != nil {
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
		require.NoError(t, e, "concurrent UpdateLabels must not error (row-lock serializes)")
	}

	rdr, err := fx.repo.Reader(ctx)
	require.NoError(t, err)
	final, err := rdr.AccessBindings().Get(ctx, acbC)
	_ = rdr.Rollback(ctx)
	require.NoError(t, err)

	matched := len(final.Labels) == 1 && final.Labels["stage"] == "prod"
	require.NoError(t, rec.ReconcileObject(ctx, "iam.accessBinding", string(acbC)))
	_, isMember := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acbC))
	assert.Equal(t, matched, isMember,
		"final membership deterministically matches the final label set (no stuck/stale membership)")

	require.NoError(t, rec.ReconcileObject(ctx, "iam.accessBinding", string(acbC)))
	_, isMember2 := memberStatusByRule(t, ctx, pool, grantBID, fp, "iam.accessBinding", string(acbC))
	assert.Equal(t, isMember, isMember2, "reconcile idempotent — second pass is a no-op")
}
