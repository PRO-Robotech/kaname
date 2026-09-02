// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_iam_direct_anchor_scope_integration_test.go — the ANCHOR arm of the
// iam-direct fan-out is narrowed by the SAME containment predicate the mirror-fed
// arm already pushes into its JOIN.
//
// WHAT THIS IS ABOUT. The forward fast-path answers "which bindings must be
// re-derived because THIS object appeared?". For the mirror-fed feed the anchor arm
// carries the containment predicate in SQL, so the candidate set is O(bindings whose
// scope contains the object) — typically the owner plus the project admin. The
// iam-direct analogue carried no such predicate: `arm='anchor'` matched EVERY active
// anchor binding OF THE TYPE, in EVERY account of the cluster. Correctness never
// depended on it — the per-binding IsContainedIn re-verify is authoritative and
// rejects the foreign-scope candidates — so the only symptom was cost, and cost is
// invisible to a correctness suite.
//
// WHY IT IS WORTH A TEST OF ITS OWN. The cost is not a constant factor: it is
// O(accounts in the cluster) on the CREATE PATH of every iam-native object, and each
// surplus candidate is a separate binding load. Measured on a populated stand, one
// iam.project / iam.accessBinding / iam.serviceAccount create fanned out to ~1408
// candidate bindings where the narrowed mirror-fed path returned 13 for a comparable
// object. That is paid on every Project.Create and every AccessBinding.Create, and it
// grows with every tenant the platform gains.
//
// WHAT THE TEST ASSERTS — the OUTCOME, in BOTH directions, so it cannot pass by
// being merely restrictive:
//
//	(+) the binding whose scope DOES contain the object is still returned (no
//	    under-grant — a narrowing that dropped the legitimate candidate would starve
//	    the very materialization this path exists for);
//	(−) a binding of ANOTHER account, carrying an identical anchor rule over the same
//	    object type, is NOT returned.
//
// The negative alone would go green on a query that returns nothing at all, which is
// why the positive control sits in the same test.
//
// RED before the anchor-arm narrowing; GREEN after.
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// iamDirectAnchorCandidates runs the iam-direct fan-out for one object and returns
// the candidate binding ids, through the same adapter the forward path uses.
func iamDirectAnchorCandidates(
	t *testing.T, ctx context.Context, adapter *kachopg.ReconcileAdapter, objectType, objectID string,
) []domain.AccessBindingID {
	t.Helper()
	var got []domain.AccessBindingID
	require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		var err error
		got, err = s.IAMDirectSelectorBindingsMatchingObject(ctx, objectType, objectID)
		return err
	}))
	return got
}

func containsBinding(ids []domain.AccessBindingID, want domain.AccessBindingID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestIAMDirectAnchorArm_IsScopedToContainingAccount — a group created in account A
// must not put account B's anchor binding on the create path.
func TestIAMDirectAnchorArm_IsScopedToContainingAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Account A — the object's own account, with an account-scoped admin over groups.
	ownerA := mustSeedUser(t, ctx, pool, "anch-own-a")
	accA := seedAccount(t, ctx, repo, "acc-anchor-a", ownerA)
	adminA := mustSeedUser(t, ctx, pool, "anch-adm-a")
	roleA := seedAdminRulesRole(t, ctx, pool, repo, accA.ID, "anch_role_a", "group")
	bidA := insertThinBindingScope(t, ctx, repo, adminA, roleA,
		"account", string(accA.ID), domain.ScopeAccount)

	// Account B — a DIFFERENT tenant carrying the IDENTICAL anchor rule over the same
	// object type. It contains nothing of account A and must never be a candidate for
	// account A's objects.
	ownerB := mustSeedUser(t, ctx, pool, "anch-own-b")
	accB := seedAccount(t, ctx, repo, "acc-anchor-b", ownerB)
	adminB := mustSeedUser(t, ctx, pool, "anch-adm-b")
	roleB := seedAdminRulesRole(t, ctx, pool, repo, accB.ID, "anch_role_b", "group")
	bidB := insertThinBindingScope(t, ctx, repo, adminB, roleB,
		"account", string(accB.ID), domain.ScopeAccount)

	adapter := kachopg.NewReconcileAdapter(pool, catalogfixture.Source())

	gid := seedNativeGroup(t, ctx, pool, accA.ID, "anch-grp-a")
	got := iamDirectAnchorCandidates(t, ctx, adapter, "iam.group", gid)

	// (+) positive control — the containing account's binding is still a candidate.
	assert.True(t, containsBinding(got, bidA),
		"the anchor binding of the object's OWN account must remain a candidate "+
			"(narrowing must not drop the legitimate one)")
	// (−) the foreign tenant's identical anchor binding is not.
	assert.False(t, containsBinding(got, bidB),
		"an anchor binding of ANOTHER account must not be a candidate for this account's "+
			"object: it is rejected by the containment re-verify anyway, so carrying it "+
			"through the fan-out is O(accounts) of pure cost on the create path")
}

// TestIAMDirectAnchorArm_ProjectScopedBindingSeesOnlyItsOwnProject — the project arm
// of the same predicate: a project-scoped anchor binding is a candidate for objects of
// ITS project and not for a sibling project of the same account.
func TestIAMDirectAnchorArm_ProjectScopedBindingSeesOnlyItsOwnProject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "anch-prj-own")
	acc := seedAccount(t, ctx, repo, "acc-anchor-prj", owner)
	prjHome := seedProject(t, ctx, repo, acc.ID, "prj-anch-home")
	prjOther := seedProject(t, ctx, repo, acc.ID, "prj-anch-other")

	admin := mustSeedUser(t, ctx, pool, "anch-prj-adm")
	role := seedAdminRulesRole(t, ctx, pool, repo, acc.ID, "anch_role_prj", "project")
	// Bound at PROJECT scope on the home project only.
	bidHome := insertThinBindingScope(t, ctx, repo, admin, role,
		"project", string(prjHome.ID), domain.ScopeProject)

	adapter := kachopg.NewReconcileAdapter(pool, catalogfixture.Source())

	// (+) its own project is a candidate.
	gotHome := iamDirectAnchorCandidates(t, ctx, adapter, "iam.project", string(prjHome.ID))
	assert.True(t, containsBinding(gotHome, bidHome),
		"a project-scoped anchor binding must be a candidate for its OWN project object")

	// (−) a sibling project of the same account is not.
	gotOther := iamDirectAnchorCandidates(t, ctx, adapter, "iam.project", string(prjOther.ID))
	assert.False(t, containsBinding(gotOther, bidHome),
		"a project-scoped anchor binding must NOT be a candidate for a SIBLING project: "+
			"containment already rejects it, so it is pure fan-out cost")
}
