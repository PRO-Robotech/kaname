// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_dual_member_revoke_integration_test.go — RBAC-2026 review fix #1
// (BLOCKER): two desired members of ONE binding that target the IDENTICAL FGA
// object with IDENTICAL tuples share a single ledger row (ledger PK is
// (binding_id, fga_user, relation, object) — NO rule_fp, migration 0024). When
// ONE member falls out (its rule removed on Role.Update) the eager-revoke reads
// the shared ledger row keyed only by (binding, object), revokes the LIVE FGA
// tuple, and forgets the shared row — silently stripping the SURVIVING member's
// access, with no re-convergence (applyDiff skips an unchanged-status survivor).
//
// The fix keeps a shared tuple ALIVE until the LAST owning member is gone: the
// revoke set is the member's ledger MINUS the union of tuples still claimed by
// OTHER surviving ACTIVE desired members on the same object (set-difference).
//
// Two reproductions:
//   - TestReview1_DualRuleSameObject_RevokeOne_SurvivorKeepsAccess: two ARM_LABELS
//     rules match the SAME compute.instance with IDENTICAL verbs → two members
//     (distinct rule_fp), identical tuples, one shared ledger row. Remove one rule
//     → the survivor's tuple MUST remain in the ledger and MUST NOT be revoked.
//   - TestReview1_OwnerScopeSelfAndContent_ShareLedgerRow: the central seeded owner
//     flow — an ACCOUNT-scoped `*.*` binding materializes a scope-self member AND a
//     wildcard-expanded iam.account content member, BOTH on account:<A> with
//     identical tuples → one shared ledger row (documents the collision class).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestReview1_DualRuleSameObject_RevokeOne_SurvivorKeepsAccess — review #1 BLOCKER.
// Two ARM_LABELS rules match the SAME object with IDENTICAL verbs → two members on
// compute_instance:i with IDENTICAL {v_get, viewer} tuples → one shared ledger row.
// Removing rule B (Role.Update) must eager-revoke ONLY rule B's exclusive
// contribution; rule A's identical tuples are STILL claimed → they must survive in
// the ledger (and no live-tuple delete may be emitted for them). RED before the fix
// (shared row deleted → survivor stripped), GREEN after.
func TestReview1_DualRuleSameObject_RevokeOne_SurvivorKeepsAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "rv1dual")
	rec, _ := newReconciler(pool)

	// Two rules, IDENTICAL verbs, DIFFERENT match_labels — so an object carrying BOTH
	// labels matches BOTH rules and yields two members on the same object with the
	// SAME {v_get, viewer} tuple set (the collision the ledger PK collapses).
	ruleKeep := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"}}
	ruleGone := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"}}
	fpKeep, fpGone := ruleKeep.Fingerprint(), ruleGone.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "rv1role", domain.Rules{ruleKeep, ruleGone})

	now := time.Now()
	// One instance carrying BOTH labels → matched by ruleKeep AND ruleGone.
	seedMirrorRow(t, ctx, pool, "compute.instance", "ishared", string(fx.prj), string(fx.accID),
		map[string]string{"team": "a", "env": "prod"}, now)

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// Both members ACTIVE on the SAME object under their own rule_fp.
	stKeep, okKeep := memberStatusByRule(t, ctx, pool, bid, fpKeep, "compute.instance", "ishared")
	stGone, okGone := memberStatusByRule(t, ctx, pool, bid, fpGone, "compute.instance", "ishared")
	require.True(t, okKeep)
	require.True(t, okGone)
	require.Equal(t, domain.VerificationActive, stKeep)
	require.Equal(t, domain.VerificationActive, stGone)

	subject := "user:" + string(fx.member)
	// The ledger collapses the two members' identical tuples to one row per relation.
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subject, "viewer", "compute_instance:ishared"),
		"both members recorded the shared viewer tuple")
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subject, "v_get", "compute_instance:ishared"),
		"both members recorded the shared v_get tuple")

	deletesBefore := countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "compute_instance:ishared")

	// Role.Update removes ruleGone (env=prod). ruleKeep (team=a) STILL matches ishared.
	w, err := fx.repo.Writer(ctx)
	require.NoError(t, err)
	updated := domain.Role{ID: roleID, ProjectID: fx.prj, Name: "rv1role",
		Rules: domain.Rules{ruleKeep}, Permissions: mustCompile(t, domain.Rules{ruleKeep}), IsSystem: false}
	_, err = w.RolesW().Update(ctx, updated, []string{"rules"})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, roleID, updated.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))

	// Reconcile picks up the new role.rules: ruleGone's member falls out, ruleKeep's
	// member stays ACTIVE — and its identical tuples must remain LIVE.
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// ruleGone's member row is gone.
	_, okGone2 := memberStatusByRule(t, ctx, pool, bid, fpGone, "compute.instance", "ishared")
	assert.False(t, okGone2, "removed-rule member purged")

	// ruleKeep's member is STILL ACTIVE.
	stKeep2, okKeep2 := memberStatusByRule(t, ctx, pool, bid, fpKeep, "compute.instance", "ishared")
	require.True(t, okKeep2, "kept-rule member survives")
	assert.Equal(t, domain.VerificationActive, stKeep2)

	// THE BUG: the survivor's tuples MUST remain in the ledger (shared tuple survives
	// until the LAST owning member is gone). Before the fix the shared row was deleted.
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subject, "viewer", "compute_instance:ishared"),
		"survivor's viewer tuple MUST remain in the ledger (shared tuple still claimed by ruleKeep)")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subject, "v_get", "compute_instance:ishared"),
		"survivor's v_get tuple MUST remain in the ledger (shared tuple still claimed by ruleKeep)")

	// And NO live-tuple delete may be emitted for the shared object (the survivor keeps
	// the live FGA tuple; eager-revoke must subtract the still-claimed set-difference).
	deletesAfter := countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "compute_instance:ishared")
	assert.Equal(t, deletesBefore, deletesAfter,
		"no FGA delete for the shared object: the survivor still claims the tuple (set-difference revoke)")
}

// TestReview1_OwnerScopeSelfAndContent_ShareLedgerRow — review #1, the central seeded
// owner flow. An ACCOUNT-scoped owner (`*.*`) binding materializes a scope-self member
// (RuleFP=scope_self) AND a wildcard-expanded iam.account content member (RuleFP=<fp>),
// BOTH on account:<A> with IDENTICAL {admin, v_*} tuples → ONE shared ledger row. This
// documents the collision class; the survivor-keeps-access invariant is proven by the
// dual-rule test above (same mechanism, deterministically forced fall-out).
func TestReview1_OwnerScopeSelfAndContent_ShareLedgerRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv1own")
	acc := seedAccount(t, ctx, repo, "acc-rv1-own", owner)
	ownerBID := insertThinBindingScope(t, ctx, repo, owner, domain.OwnerRoleID,
		"account", string(acc.ID), domain.ScopeAccount)

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBID))

	ownerUser := "user:" + string(owner)
	// Scope-self member on account:<A> (RuleFP=scope_self).
	stSelf, okSelf := memberStatusByRule(t, ctx, pool, ownerBID, "scope_self", "iam.account", string(acc.ID))
	require.True(t, okSelf, "scope-self member materialized on the account anchor")
	assert.Equal(t, domain.VerificationActive, stSelf)

	// Wildcard-expanded iam.account content member on the SAME account:<A> (distinct
	// rule_fp). Both write {admin, v_*} on account:<A> → the ledger collapses them.
	var contentMembers int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members
		  WHERE binding_id=$1 AND object_type='iam.account' AND object_id=$2
		    AND rule_fp <> 'scope_self' AND verification_status='ACTIVE'`,
		string(ownerBID), string(acc.ID)).Scan(&contentMembers))
	assert.GreaterOrEqual(t, contentMembers, 1,
		"wildcard-expanded iam.account content member also materialized on account:<A> (collision class)")

	// Both members → identical admin tuple → ONE shared ledger row on account:<A>.
	assert.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "account:"+string(acc.ID)),
		"owner admin tuple recorded on the account anchor (shared by scope-self + content)")
}
