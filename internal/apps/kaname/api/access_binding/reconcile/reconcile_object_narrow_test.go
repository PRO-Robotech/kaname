// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// reconcile_object_narrow_test.go — the producer-cost contract of the OBJECT-triggered
// reconcile pass.
//
// A resource_mirror upsert/delete (a create, a re-register, a label UPDATE) changes
// EXACTLY ONE object. The pass it triggers must therefore cost O(1) in the size of the
// binding's scope: it may only re-derive that one object's membership and diff it against
// that one object's materialized members. Recomputing the binding's WHOLE desired set
// (MatchAllInScope over every mirror object of the scope) and reading the binding's WHOLE
// member set (CurrentMembers) is the O(mirror) recompute — on the measured stand the two
// hottest bindings carry 10 140 members each and one object change fans out to 3.2
// bindings on average, so a single label update read ~64 000 rows while holding the
// per-binding EXCLUSIVE advisory lock every sibling registration queues behind.
//
// These tests pin the cost at the observable level the fix is about — how much work ONE
// operation does — and, alongside it, that narrowing did not cost any of the correctness
// the full recompute was there for: delete-stale still revokes, and a re-grant after a
// revoke is still emitted.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// scopeWideBinding builds a fakeStore holding ONE account-scoped binding whose
// ARM_ANCHOR selector covers `n` already-materialized compute.instance objects — the
// shape of the hot e2e binding (one account-owner binding, thousands of members).
func scopeWideBinding(n int) (*fakeStore, string) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"},
		Verbs: []string{"get", "list", "update"},
	}.Fingerprint()

	objs := make([]domain.MirrorObject, 0, n)
	members := make([]domain.TargetMember, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("i-%04d", i)
		objs = append(objs, domain.MirrorObject{
			ObjectType: "compute.instance", ObjectID: id,
			ParentProjectID: "prj-1", ParentAccountIDs: []string{"acc-1"},
			Labels: map[string]string{"tier": "gold"},
		})
		members = append(members, domain.TargetMember{
			BindingID: "acb-1", RoleID: "rol-1", RuleFP: fp,
			ObjectType: "compute.instance", ObjectID: id,
			VerificationStatus: domain.VerificationActive,
		})
	}

	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "account", ID: "acc-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			Verbs:       []string{"get", "list", "update"},
		}},
		mirror:            map[string][]domain.MirrorObject{"compute.instance": objs},
		current:           members,
		bindingsForObject: []domain.AccessBindingID{"acb-1"},
		selectorBindings:  []domain.AccessBindingID{"acb-1"},
	}
	return f, fp
}

// TestReconcileObject_NarrowToChangedObject_DoesNotRescanScope — the core producer-cost
// contract. A change to ONE object must NOT trigger the binding's whole-scope desired
// recompute, nor the whole-binding materialized-member read.
//
// RED before the narrowing: ReconcileObject called reconcileBinding, which ran
// desiredMembers → MatchAllInScope (all 500 objects) + CurrentMembers (all 500 members)
// for a single changed object.
func TestReconcileObject_NarrowToChangedObject_DoesNotRescanScope(t *testing.T) {
	const n = 500
	f, _ := scopeWideBinding(n)

	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).
		ReconcileObject(context.Background(), "compute.instance", "i-0042"))

	assert.Equal(t, 0, f.matchAllCalls,
		"an object-triggered pass must not rescan the binding's whole scope (O(mirror) recompute)")
	assert.Equal(t, 0, f.matchAllObjectsScanned,
		"no whole-scope candidate objects may be read for a single-object change")
	assert.Equal(t, 0, f.currentMembersCalls,
		"an object-triggered pass must not read the binding's whole member set")
	assert.GreaterOrEqual(t, f.currentForObjectCalls, 1,
		"the diff base must be the narrow per-object member read")

	// Cost is O(1) in the scope size: the pass touches only the changed object.
	for _, m := range f.upserts {
		assert.Equal(t, "i-0042", m.ObjectID, "only the changed object may be re-materialized")
	}
	assert.Empty(t, f.deletes, "an unchanged, still-matching object set must not be disturbed")
	assert.Empty(t, f.tdeletes, "no tuple may be revoked when nothing fell out of the desired set")
}

// TestReconcileObject_CostIsIndependentOfScopeSize — the same contract expressed as a
// scaling property: growing the binding's scope 10× must not grow the work a single
// object change does. RED before the narrowing (work grew linearly with the scope).
func TestReconcileObject_CostIsIndependentOfScopeSize(t *testing.T) {
	small, _ := scopeWideBinding(50)
	large, _ := scopeWideBinding(500)

	rec := func(f *fakeStore) {
		require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).
			ReconcileObject(context.Background(), "compute.instance", "i-0001"))
	}
	rec(small)
	rec(large)

	assert.Equal(t, small.matchAllObjectsScanned, large.matchAllObjectsScanned,
		"objects scanned for one object change must not depend on scope size")
	assert.Equal(t, len(small.upserts), len(large.upserts),
		"members re-materialized for one object change must not depend on scope size")
	assert.Equal(t, len(allWrites(small)), len(allWrites(large)),
		"tuples emitted for one object change must not depend on scope size")
}

// TestReconcileObject_EmitsEachTupleOncePerPass — the second producer-cost contract:
// one pass enqueues each distinct tuple into fga_outbox AT MOST ONCE. Two selectors of
// the same binding matching the same object derive the same tuples; the synchronous FGA
// write already de-duplicates them (syncFGACollector.collect), but the outbox enqueue did
// not — the measured stand showed 27 outbox rows for 21 distinct tuples in one pass.
//
// RED before the fix: allWrites contained duplicates.
func TestReconcileObject_EmitsEachTupleOncePerPass(t *testing.T) {
	// Two DISTINCT rules (different verbs ⇒ different fingerprints, so two member rows)
	// whose tuple sets overlap on v_get/v_list — the duplicate-emission shape.
	fpA := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}}.Fingerprint()
	fpB := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list", "update"}}.Fingerprint()

	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{
			{Arm: domain.ArmAnchor, RuleFP: fpA, ObjectTypes: []string{"compute.instance"}, Verbs: []string{"get", "list"}},
			{Arm: domain.ArmAnchor, RuleFP: fpB, ObjectTypes: []string{"compute.instance"}, Verbs: []string{"get", "list", "update"}},
		},
		mirror: map[string][]domain.MirrorObject{"compute.instance": {
			{ObjectType: "compute.instance", ObjectID: "i-1", ParentProjectID: "prj-1"},
		}},
		selectorBindings: []domain.AccessBindingID{"acb-1"},
	}

	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).
		ReconcileObject(context.Background(), "compute.instance", "i-1"))

	seen := map[domain.MembershipTuple]int{}
	for _, tup := range allWrites(f) {
		seen[tup]++
	}
	require.NotEmpty(t, seen, "the pass must emit the object's tuples")
	for tup, c := range seen {
		assert.Equalf(t, 1, c, "tuple %s#%s@%s enqueued %d times in ONE pass — the outbox enqueue must be de-duplicated per pass",
			tup.Object, tup.Relation, tup.User, c)
	}
}

// TestReconcileObject_Narrow_StillRevokesOnLabelRemoval — the regression the narrowing
// must NOT cost: delete-stale. This is the closed label-revoke defect (a grant-matching
// label removed must revoke the standing grant). The narrow pass keeps the full path's
// diff — it only narrows WHAT is diffed — so a member that fell out of the desired set
// for the changed object is still revoked.
func TestReconcileObject_Narrow_StillRevokesOnLabelRemoval(t *testing.T) {
	fp := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}.Fingerprint()
	sub := domain.FGASubjectRef("user", "usr-1")

	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"tier": "gold"},
			Verbs:       []string{"get", "update"},
		}},
		// The object is STILL in the mirror but its grant-matching label is GONE.
		mirror: map[string][]domain.MirrorObject{"compute.instance": {
			{ObjectType: "compute.instance", ObjectID: "i-1", ParentProjectID: "prj-1",
				Labels: map[string]string{"tier": "bronze"}},
		}},
		current: []domain.TargetMember{{
			BindingID: "acb-1", RoleID: "rol-1", RuleFP: fp,
			ObjectType: "compute.instance", ObjectID: "i-1",
			VerificationStatus: domain.VerificationActive,
		}},
		// The standing grant's ledger lineage — the revoke source.
		ledger: []domain.MembershipTuple{
			{User: sub, Relation: "v_get", Object: "compute_instance:i-1"},
			{User: sub, Relation: "v_update", Object: "compute_instance:i-1"},
			{User: sub, Relation: "editor", Object: "compute_instance:i-1"},
		},
		bindingsForObject: []domain.AccessBindingID{"acb-1"},
	}

	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).
		ReconcileObject(context.Background(), "compute.instance", "i-1"))

	var revoked []domain.MembershipTuple
	for _, b := range f.tdeletes {
		revoked = append(revoked, b...)
	}
	assert.True(t, hasTuple(revoked, "v_get", "compute_instance:i-1"), "label removed ⇒ v_get revoked")
	assert.True(t, hasTuple(revoked, "v_update", "compute_instance:i-1"), "label removed ⇒ v_update revoked")
	assert.True(t, hasTuple(revoked, "editor", "compute_instance:i-1"), "label removed ⇒ tier revoked")
	assert.Contains(t, f.deletes, memberKey("compute.instance", "i-1"), "the fell-out member row is removed")
	require.NotEmpty(t, f.forgotten, "the ledger lineage is forgotten in lock-step with the revoke")
}

// TestReconcileObject_Narrow_ReGrantAfterRevokeIsEmitted — the anti-trap regression.
// De-duplicating the producer must never collapse grant → revoke → grant into
// grant → revoke: after a revoke has cleared the ledger, a matching label coming BACK
// must enqueue the tuple-write again. A dedup keyed on queue contents (event type +
// payload) would silently drop this re-emission; the per-pass dedup and the ledger gate
// are keyed on APPLIED state, which a revoke clears.
func TestReconcileObject_Narrow_ReGrantAfterRevokeIsEmitted(t *testing.T) {
	fp := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}.Fingerprint()

	newStore := func(labels map[string]string, current []domain.TargetMember, ledger []domain.MembershipTuple) *fakeStore {
		return &fakeStore{
			scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
			subjectType: "user", subjectID: "usr-1", active: true,
			selectors: []domain.RuleSelector{{
				Arm: domain.ArmLabels, RuleFP: fp,
				ObjectTypes: []string{"compute.instance"},
				MatchLabels: map[string]string{"tier": "gold"},
				Verbs:       []string{"get", "update"},
			}},
			mirror: map[string][]domain.MirrorObject{"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-1", ParentProjectID: "prj-1", Labels: labels},
			}},
			current:           current,
			ledger:            ledger,
			bindingsForObject: []domain.AccessBindingID{"acb-1"},
			selectorBindings:  []domain.AccessBindingID{"acb-1"},
		}
	}
	sub := domain.FGASubjectRef("user", "usr-1")
	activeMember := []domain.TargetMember{{
		BindingID: "acb-1", RoleID: "rol-1", RuleFP: fp,
		ObjectType: "compute.instance", ObjectID: "i-1",
		VerificationStatus: domain.VerificationActive,
	}}
	standingLedger := []domain.MembershipTuple{
		{User: sub, Relation: "v_get", Object: "compute_instance:i-1"},
		{User: sub, Relation: "v_update", Object: "compute_instance:i-1"},
		{User: sub, Relation: "editor", Object: "compute_instance:i-1"},
	}
	ctx := context.Background()

	// (1) GRANT — label matches, nothing materialized yet.
	grant := newStore(map[string]string{"tier": "gold"}, nil, nil)
	require.NoError(t, New(fakeRunner{s: grant}, nil, catalogfixture.Source()).ReconcileObject(ctx, "compute.instance", "i-1"))
	require.True(t, hasTuple(allWrites(grant), "v_get", "compute_instance:i-1"), "grant emits the tuple")

	// (2) REVOKE — label removed; the standing grant is revoked and the ledger cleared.
	revoke := newStore(map[string]string{"tier": "bronze"}, activeMember, standingLedger)
	require.NoError(t, New(fakeRunner{s: revoke}, nil, catalogfixture.Source()).ReconcileObject(ctx, "compute.instance", "i-1"))
	var revoked []domain.MembershipTuple
	for _, b := range revoke.tdeletes {
		revoked = append(revoked, b...)
	}
	require.True(t, hasTuple(revoked, "v_get", "compute_instance:i-1"), "revoke strips the tuple")

	// (3) RE-GRANT — the label comes back. The member row and the ledger were cleared by
	// (2), so the tuple MUST be enqueued again. A payload-keyed queue dedup would drop it.
	regrant := newStore(map[string]string{"tier": "gold"}, nil, nil)
	require.NoError(t, New(fakeRunner{s: regrant}, nil, catalogfixture.Source()).ReconcileObject(ctx, "compute.instance", "i-1"))
	assert.True(t, hasTuple(allWrites(regrant), "v_get", "compute_instance:i-1"),
		"a re-grant after a revoke must be re-emitted — the producer dedup must not swallow it")
	assert.True(t, hasTuple(allWrites(regrant), "editor", "compute_instance:i-1"),
		"the full tuple set is re-emitted on re-grant")
}

// TestReconcileObject_Narrow_ScopeSelfObjectStillMaterialized — the narrow desired
// derivation must not lose the scope-self member: when the CHANGED object IS the
// binding's own scope anchor (a project/account label update), the tier + v_* tuples on
// that anchor are part of the object's desired set and must still be materialized.
func TestReconcileObject_Narrow_ScopeSelfObjectStillMaterialized(t *testing.T) {
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		scopeSelfVerbs: []string{"get", "list", "update"},
		// A content selector that does NOT cover iam.project — the scope-self member is
		// the only thing this object can produce.
		selectors: []domain.RuleSelector{{
			Arm:         domain.ArmAnchor,
			RuleFP:      domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}.Fingerprint(),
			ObjectTypes: []string{"compute.instance"}, Verbs: []string{"get"},
		}},
		iamDirect: map[string][]domain.MirrorObject{"iam.project": {
			{ObjectType: "iam.project", ObjectID: "prj-1", ParentAccountIDs: []string{"acc-1"}},
		}},
		iamDirectSelectorBindings: []domain.AccessBindingID{"acb-1"},
		bindingsForObject:         []domain.AccessBindingID{"acb-1"},
	}

	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).
		ReconcileObject(context.Background(), "iam.project", "prj-1"))

	w := allWrites(f)
	assert.True(t, hasTuple(w, "v_get", "project:prj-1"), "scope-self v_get on the changed scope object")
	assert.True(t, hasTuple(w, "v_update", "project:prj-1"), "scope-self v_update on the changed scope object")
	require.Len(t, f.upserts, 1, "exactly the scope-self member is materialized")
	assert.Equal(t, scopeSelfRuleFP, f.upserts[0].RuleFP)
}
