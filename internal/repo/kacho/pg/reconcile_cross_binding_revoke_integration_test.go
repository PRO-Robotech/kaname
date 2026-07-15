// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_cross_binding_revoke_integration_test.go — cross-binding shared-tuple
// revoke (Design-B flat-authz verb-bearing). The emitted-tuple ledger PK is
// (binding_id, fga_user, relation, object) — keyed PER BINDING (migration 0024).
// The same subject can hold TWO different bindings (two roles) that each
// materialize the IDENTICAL FGA tuple on the SAME object — e.g. role-T (label
// treska) and role-O (label okun), both `[get,list]` on vpc.network, on a network
// that at different times carries either label. OpenFGA tuples are NOT
// refcounted: one `(sa, v_list, vpc_network:N)` tuple exists regardless of how
// many bindings claim it.
//
// THE BUG (label-revoke-vpc T31-LBLREVOKE-VPC-NETWORK-CHANGE-01 chg-both-post-allow):
// on a label swap treska→okun, ReconcileObject reconciles BOTH bindings in one
// pass — role-T's member falls out (eager-revoke its `v_list` tuple) while role-O's
// member materializes (emit the IDENTICAL `v_list` tuple). The per-binding
// survivingClaims set protected a shared tuple only WITHIN one binding; across two
// bindings the role-T revoke emits `fga.tuple.delete` for a tuple role-O still
// claims, and role-O's emit + the role-T delete race in the drainer → the tuple
// ends up DELETED → the subject loses v_list (DENY) though role-O legitimately
// grants it.
//
// THE FIX: before emitting a tuple-delete for a fell-out / downgraded member, the
// reconciler subtracts tuples STILL CLAIMED by an ACTIVE member of ANY OTHER
// active binding of the same subject on the same object (StillClaimedByOtherBindings,
// queried against the emitted-tuple ledger of OTHER active bindings). A shared
// cross-binding tuple is revoked exactly when the LAST owning binding releases it.
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
)

// TestCrossBinding_SwapLabel_SharedTupleSurvives — two bindings of ONE subject on
// the SAME network with IDENTICAL `[get,list]` verb-rules differing only in
// match_labels (treska vs okun). The network starts {network:treska} (role-T
// matches), then swaps to {network:okun} (role-O matches). A ReconcileObject pass
// over the changed network reconciles BOTH bindings: role-T's member falls out,
// role-O's materializes — the shared `v_list`/`v_get` tuple MUST remain live (no
// net delete), so the subject keeps visibility. RED before the cross-binding
// surviving-claims fix (role-T's revoke strips the shared tuple), GREEN after.
func TestCrossBinding_SwapLabel_SharedTupleSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "xbswap")
	rec, _ := newReconciler(pool)

	// Two roles: identical verbs [get,list] on vpc.network, differing ONLY by the
	// match-label. A network carrying treska matches role-T; okun matches role-O.
	ruleT := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"network": "treska"}}
	ruleO := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"network": "okun"}}
	fpT, fpO := ruleT.Fingerprint(), ruleO.Fingerprint()
	roleT := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "xb_rolet", domain.Rules{ruleT})
	roleO := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "xb_roleo", domain.Rules{ruleO})

	now := time.Now()
	// Network starts with the treska label — only role-T matches.
	seedMirrorRow(t, ctx, pool, "vpc.network", "netchg", string(fx.prj), string(fx.accID),
		map[string]string{"network": "treska"}, now)

	// Both bindings on the SAME subject (the member). role-T sees the net now;
	// role-O is bound but inert (no okun label yet).
	bidT := insertThinBinding(t, ctx, fx.repo, fx.member, roleT, fx.prj)
	bidO := insertThinBinding(t, ctx, fx.repo, fx.member, roleO, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bidT))
	require.NoError(t, rec.ReconcileBinding(ctx, bidO))

	subject := "user:" + string(fx.member)
	netObj := "vpc_network:netchg"

	// Initial: role-T's member ACTIVE, role-O's member absent (no okun match).
	stT, okT := memberStatusByRule(t, ctx, pool, bidT, fpT, "vpc.network", "netchg")
	require.True(t, okT)
	require.Equal(t, domain.VerificationActive, stT)
	_, okO := memberStatusByRule(t, ctx, pool, bidO, fpO, "vpc.network", "netchg")
	require.False(t, okO, "role-O has no member yet (network not labelled okun)")

	require.True(t, ledgerHasTuple(t, ctx, pool, bidT, subject, "v_list", netObj),
		"role-T recorded the v_list tuple in its ledger")

	deletesBefore := countFGAOutbox(t, ctx, pool, "fga.tuple.delete", netObj)

	// Swap the label treska → okun: role-T STOPS matching, role-O STARTS matching.
	seedMirrorRow(t, ctx, pool, "vpc.network", "netchg", string(fx.prj), string(fx.accID),
		map[string]string{"network": "okun"}, now.Add(time.Second))

	// ReconcileObject fans the change out to BOTH bindings (existing role-T member +
	// role-O selector-now-matches) in ONE pass — the cross-binding collision path.
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", "netchg"))

	// role-T's member fell out; role-O's member is now ACTIVE.
	_, okT2 := memberStatusByRule(t, ctx, pool, bidT, fpT, "vpc.network", "netchg")
	assert.False(t, okT2, "role-T member purged (network no longer treska)")
	stO2, okO2 := memberStatusByRule(t, ctx, pool, bidO, fpO, "vpc.network", "netchg")
	require.True(t, okO2, "role-O member materialized (network now okun)")
	assert.Equal(t, domain.VerificationActive, stO2)

	// role-O's ledger now holds the v_list tuple (it materialized the grant).
	assert.True(t, ledgerHasTuple(t, ctx, pool, bidO, subject, "v_list", netObj),
		"role-O recorded the v_list tuple — the subject still legitimately holds it")

	// THE BUG: the SHARED live FGA tuple must NOT be net-deleted. role-O re-emits
	// it (write) while role-T revokes it (delete); without the cross-binding
	// surviving-claims subtraction the delete strips role-O's still-valid tuple.
	// The fix suppresses the role-T delete because role-O still claims it →
	// no `fga.tuple.delete` for this object in the swap pass.
	deletesAfter := countFGAOutbox(t, ctx, pool, "fga.tuple.delete", netObj)
	assert.Equal(t, deletesBefore, deletesAfter,
		"no FGA delete for the shared cross-binding tuple: role-O still claims v_list (cross-binding surviving-claims)")
}
