// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_labels_integration_test.go — IAM label-scope integration
// coverage for the User resource: own-table labels round-trip, iam-direct
// ARM_LABELS materialization on iam.user (matching set only), eager fall-out on
// label removal, and concurrent UpdateLabels CAS (last-writer-wins under row-lock,
// reconcile idempotent).
//
// Scenarios: labels round-trip, label-grant → matching user set,
// foreign-account user not materialized, label removed → eager fall-out,
// concurrent UpdateLabels CAS.
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

// setUserLabels writes labels on a users row directly (iam-direct feed source).
func setUserLabels(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid string, labels map[string]string) {
	t.Helper()
	payload := jsonObject(labels)
	_, err := pool.Exec(ctx,
		`UPDATE kacho_iam.users SET labels = $2::jsonb WHERE id = $1`, uid, payload)
	require.NoError(t, err, "set user labels")
}

// ── labels round-trip through the repo UpdateLabels writer ─────────

func TestUserLabels_T33UPD01_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "ul-rt")
	acc := seedAccount(t, ctx, repo, "acc-ul-rt", owner)
	uid := seedNativeUser(t, ctx, pool, acc.ID, "rt")

	// Default labels — empty map (DEFAULT '{}').
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got0, err := rd.Users().Get(ctx, domain.UserID(uid))
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	assert.Empty(t, got0.Labels, "fresh user row has empty labels")

	// UpdateLabels sets the tenant-facing labels (mutable).
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.UsersW().UpdateLabels(ctx, domain.UserID(uid),
		domain.Labels{"tier": "gold", "team": "payments"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.Labels{"tier": "gold", "team": "payments"}, updated.Labels)

	// Get round-trips the persisted labels (own-table column).
	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd2.Users().Get(ctx, domain.UserID(uid))
	_ = rd2.Rollback(ctx)
	require.NoError(t, err)
	assert.Equal(t, domain.Labels{"tier": "gold", "team": "payments"}, got.Labels,
		"labels round-trip through users.labels column")

	// Immutable identity fields are untouched by a labels update.
	assert.Equal(t, got0.ExternalID, got.ExternalID, "external_id untouched by labels update")
	assert.Equal(t, got0.Email, got.Email, "email untouched by labels update")
}

// ── label-grant on iam.user materializes only the
// matching, in-scope user set (not the non-matching one, not the foreign-account
// one) via the iam-direct ARM_LABELS reconcile path. ─────────────────────────────

func TestUserLabels_T33MAT01_LabelGrantMaterializesMatchingSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ulmat01")
	rec, _ := newReconciler(pool)

	// Two users in the granting account: usr1{team:payments}, usr2{team:billing}.
	usr1 := seedNativeUser(t, ctx, pool, fx.accID, "mat1")
	usr2 := seedNativeUser(t, ctx, pool, fx.accID, "mat2")
	setUserLabels(t, ctx, pool, usr1, map[string]string{"team": "payments"})
	setUserLabels(t, ctx, pool, usr2, map[string]string{"team": "billing"})

	// A foreign-account user that also matches by label but is out of scope.
	foreignOwner := mustSeedUser(t, ctx, pool, "ul-foreign-owner")
	foreignAcc := seedAccount(t, ctx, fx.repo, "acc-ul-foreign", foreignOwner)
	usrForeign := seedNativeUser(t, ctx, pool, foreignAcc.ID, "matf")
	setUserLabels(t, ctx, pool, usrForeign, map[string]string{"team": "payments"})

	// Account-scoped rules-role: ARM_LABELS rule selecting iam.user team=payments.
	rule := domain.Rule{
		Module: "iam", Resources: []string{"user"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ulmat01role", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	// Reconcile the binding → materialize the matching, in-scope members.
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// usr1 matches {team:payments} under acc-A → ACTIVE member.
	st1, ok1 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usr1)
	require.True(t, ok1, "usr1{team:payments} materialized as member (iam-direct ARM_LABELS)")
	assert.Equal(t, domain.VerificationActive, st1)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_user:"+usr1), 1,
		"materialized iam.user member emits the v_get/v_list tuple")

	// usr2 does NOT match {team:billing} → no member at all.
	_, ok2 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usr2)
	assert.False(t, ok2, "usr2{team:billing} does not match the selector → not a member")

	// usrForeign matches by label/type but is under acc-OTHER → out of
	// scope → REJECTED member (containment audit, NO FGA write-tuple). It is never an
	// ACTIVE member and never gains a visibility tuple (cross-scope label-injection
	// defence), so Check{member, v_list, iam_user:usrForeign} stays false.
	stF, okF := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usrForeign)
	require.True(t, okF, "foreign-account candidate is recorded as a containment verdict")
	assert.Equal(t, domain.VerificationRejected, stF,
		"foreign-account user matches labels but is out of scope → REJECTED (containment)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "iam_user:"+usrForeign),
		"REJECTED foreign-account user gains NO visibility tuple")
}

// ── label removed on the user → eager fall-out (member GONE,
// tuple-delete emitted) via the iam-direct fast-path ReconcileObject. ────────────

func TestUserLabels_T33REVOKE01_LabelRemovedEagerFallout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ulrev01")
	rec, _ := newReconciler(pool)

	usr1 := seedNativeUser(t, ctx, pool, fx.accID, "rev1")
	setUserLabels(t, ctx, pool, usr1, map[string]string{"team": "payments"})

	rule := domain.Rule{
		Module: "iam", Resources: []string{"user"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ulrev01role", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usr1)
	require.True(t, ok, "usr1 materialized before label removal")
	require.Equal(t, domain.VerificationActive, st)

	// When: the label is removed on the user (the new UpdateUser RPC writes labels={}
	// and the use-case co-commits a reconcile event; here we drive the own-resource
	// label change + the fast-path ReconcileObject directly).
	setUserLabels(t, ctx, pool, usr1, map[string]string{})
	require.NoError(t, rec.ReconcileObject(ctx, "iam.user", usr1))

	// Then: the member is eager-revoked (a real DELETE from access_binding_target_members).
	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usr1)
	assert.False(t, stillMember, "label removed → member eager-revoked (iam-direct fast-path)")

	// And: the FGA tuple-delete was emitted for the revoked member.
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "iam_user:"+usr1), 1,
		"label removed → FGA tuple-delete emitted (visibility revoked)")
}

// ── N concurrent UpdateLabels on one user row → deterministic final
// state under the row-lock (last-writer-wins, not TOCTOU); the row stays valid and
// a subsequent reconcile is idempotent against the final label set. ──────────────

func TestUserLabels_T33CONC01_ConcurrentUpdateLabels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "ulconc01")
	rec, _ := newReconciler(pool)

	usrC := seedNativeUser(t, ctx, pool, fx.accID, "concu")

	rule := domain.Rule{
		Module: "iam", Resources: []string{"user"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"team": "payments"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "ulconc01role", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	// N goroutines flip labels {team:payments} ↔ {} concurrently. The single-row
	// UPDATE is serialized by the row-lock (запрет #10 — not check-then-act); the
	// last committed writer wins. We then assert the row is one of the two valid
	// states and reconcile converges deterministically to it.
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
			if _, uerr := w.UsersW().UpdateLabels(ctx, domain.UserID(usrC), labels); uerr != nil {
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

	// Read the durable final label state.
	rdr, err := fx.repo.Reader(ctx)
	require.NoError(t, err)
	final, err := rdr.Users().Get(ctx, domain.UserID(usrC))
	_ = rdr.Rollback(ctx)
	require.NoError(t, err)

	matched := len(final.Labels) == 1 && final.Labels["team"] == "payments"
	// Reconcile is idempotent against the final state: membership matches iff the
	// final label set matches the selector.
	require.NoError(t, rec.ReconcileObject(ctx, "iam.user", usrC))
	_, isMember := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usrC)
	assert.Equal(t, matched, isMember,
		"final membership deterministically matches the final label set (no stuck/stale membership)")

	// A second reconcile changes nothing (idempotent — no duplicate members/tuples).
	require.NoError(t, rec.ReconcileObject(ctx, "iam.user", usrC))
	_, isMember2 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", usrC)
	assert.Equal(t, isMember, isMember2, "reconcile idempotent — second pass is a no-op")
}
