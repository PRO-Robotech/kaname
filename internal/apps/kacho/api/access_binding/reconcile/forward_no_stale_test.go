// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// forward_known_new_test.go — the create-path must not defeat its OWN fast-path.
//
// THE DEFECT (measured against the Read API on a live stand). AccessBinding.Create
// runs two post-commit passes: ReconcileBindingForward (this binding's own members)
// and then ReconcileObjectForward for the binding-AS-OBJECT. The first pass writes a
// member row ON THAT VERY OBJECT (a `*.*`/anchor role in scope matches
// iam.accessBinding, including the row just created), so the second pass's
// delete-stale guard — "does this object already have members?" — sees a NON-EMPTY
// set and routes the object to the FULL EXCLUSIVE ReconcileObject. Every
// access_binding of an account shares the single account-admin binding, so those full
// passes queue on one advisory lock: the subject's own tuples landed in ~3s, the
// scope parent-pointer in ~61s and the account-admin's per-object verbs in ~67s,
// against a 25s client poll budget.
//
// Swapping the two calls only moves the starvation to the other side (the binding
// pass would then find members written by the object pass). What the guard actually
// needs is the one fact the create-path knows and the store cannot infer: the object
// is BRAND-NEW, its id minted in the writer-tx that just committed, so there is
// nothing stale on it by construction and every member row on it was written seconds
// ago by this same create.
//
// The guard itself stays for every caller that cannot prove otherwise (a RE-REGISTER /
// label-UPDATE that REPLACED the object's projection must still delete-stale — the T31
// label-revoke regression). Exempt is only a caller holding one of the two proofs named
// on ReconcileObjectForwardNoStale — here, the create-path's brand-new id — and the FULL
// ReconcileObject remains the async backstop either way.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// ownerAccessBindingStore builds the create-path shape: a brand-new
// iam.accessBinding object in an account carrying an owner `*.*` binding, where the
// object ALREADY has a member row — the one this same create's ReconcileBindingForward
// pass wrote moments ago for the new binding itself.
func ownerAccessBindingStore(sameCreateMembers []domain.AccessBindingID) *fakeStore {
	fp := domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"},
		Verbs: []string{"get", "list", "create", "update", "delete"},
	}.Fingerprint()
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "account", ID: "acc-1"},
		subjectType: "user", subjectID: "usr-owner", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: fp,
			ObjectTypes: []string{"iam.accessBinding"},
			Verbs:       []string{"get", "list", "create", "update", "delete"},
		}},
		iamDirect: map[string][]domain.MirrorObject{
			"iam.accessBinding": {
				{ObjectType: "iam.accessBinding", ObjectID: "acb-new", ParentAccountIDs: []string{"acc-1"}},
			},
		},
		iamDirectSelectorBindings: []domain.AccessBindingID{"acb-owner"},
		// Members written by THIS create (ReconcileBindingForward materialized the new
		// binding's own grant, which covers the binding-object itself).
		bindingsForObject: sameCreateMembers,
	}
}

// TestReconcileObjectForwardNoStale_MembersOfSameCreate_StayOnAdditivePath — a
// PROVEN-NEW object stays on the additive SHARE path even though it already carries
// member rows: those rows were written by the same create, and a never-before-existing
// id can have nothing stale on it.
//
// RED (before the nothing-stale signal): the delete-stale guard saw len(members)>0 and
// delegated to the FULL ReconcileObject → f.locks>0, the EXCLUSIVE lock every
// access_binding of the account queues on.
func TestReconcileObjectForwardNoStale_MembersOfSameCreate_StayOnAdditivePath(t *testing.T) {
	f := ownerAccessBindingStore([]domain.AccessBindingID{"acb-new"})
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())

	require.NoError(t, rec.ReconcileObjectForwardNoStale(context.Background(), "iam.accessBinding", "acb-new"))

	assert.Equal(t, 0, f.locks,
		"a PROVEN-NEW object must stay on the additive fast-path — members written by the same "+
			"create must not push it onto the FULL EXCLUSIVE recompute (the create-path starvation)")
	assert.GreaterOrEqual(t, f.unlockedLoads, 1, "аддитивный путь исполнился (unlocked-load), и без advisory-блокировки")

	// And it must actually MATERIALIZE: the account-owner's per-object verb-set on the
	// new binding-object, byte-identical to what the full path would emit.
	require.Len(t, f.upserts, 1, "the new object is materialized for the matching owner binding")
	assert.Equal(t, "acb-new", f.upserts[0].ObjectID)
	w := allWrites(f)
	// The set is read from the type, not re-listed: "byte-identical to the full path"
	// is an assertion ABOUT the emitter, and a literal cannot follow it. This one named
	// `v_create`, which `iam_access_binding` stopped declaring once the relation was
	// left to `registry_registry` alone — so the literal would have gone on demanding a
	// tuple the full path no longer writes either.
	wantVerbs := authzmap.VerbRelationsOfType("iam_access_binding")
	require.NotEmpty(t, wantVerbs, "iam_access_binding declares no verb relation — the assertion below would be vacuous")
	for _, v := range wantVerbs {
		assert.True(t, hasTuple(w, v, "iam_access_binding:acb-new"), "%s on the new access_binding", v)
	}
	assert.True(t, hasTuple(w, "admin", "iam_access_binding:acb-new"), "admin tier on the new access_binding")

	// Additive-only, exactly like the ordinary forward: nothing revoked or audited.
	assert.Empty(t, f.tdeletes, "the known-new forward never revokes")
	assert.Empty(t, f.deletes, "the known-new forward never deletes a member")
	assert.Empty(t, f.audits, "the async full backstop still owns REJECTED-containment audit")
}

// TestReconcileObjectForward_WithoutProof_KeepsDeleteStaleGuard — the exemption is
// NARROW, and this is its paired positive control. The ordinary entry point (a
// re-register / label-UPDATE, where the caller holds neither proof) keeps routing to the
// FULL EXCLUSIVE path when the object already has members, because only that path can
// revoke a now-unmatched grant. Weakening this would re-introduce the T31 label-revoke
// `post-revoke-deny` defect.
func TestReconcileObjectForward_WithoutProof_KeepsDeleteStaleGuard(t *testing.T) {
	f := ownerAccessBindingStore([]domain.AccessBindingID{"acb-owner"})
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())

	require.NoError(t, rec.ReconcileObjectForward(context.Background(), "iam.accessBinding", "acb-new"))

	assert.Greater(t, f.locks, 0,
		"an object with pre-existing members and NO proof must still take the FULL "+
			"delete-stale path (EXCLUSIVE lock) — the guard is lifted only where the caller "+
			"has established that nothing stale can exist")
}
