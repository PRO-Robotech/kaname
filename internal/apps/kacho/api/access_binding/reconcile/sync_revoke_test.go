// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// sync_revoke_test.go — the direction contract of the post-commit fast path.
//
// A reconcile pass produces BOTH directions: tuples to add (a grant materialised) and
// tuples to remove (a grant that fell out of the desired set — a label cleared, a rule
// dropped, the object gone from its feed). Both are durably enqueued into fga_outbox in
// the writer-tx, and both were meant to be applied to the store right after that tx
// commits, so the caller's next question is answered by the new state rather than by the
// depth of a queue.
//
// Only ONE direction was wired. The post-commit apply carried the additions and left the
// removals to the queue, so an addition took effect in the same request while the matching
// removal waited for the drainer. Measured on the stand (one storage volume, boevaya
// posadka): the object's grants appeared in a single batch at T+0, and the removals for the
// SAME object were spread over the following 22 seconds — the resource had already been
// gone (404) for 12 of them.
//
// A one-directional fast path is worse than none: it makes the permissive direction fast
// and the restrictive direction slow, which is exactly backwards for a control that exists
// to say "no".
//
// These tests pin the property at the observable level — what reached the store by the
// time the pass returned — and pin the durable enqueue alongside it, so the fast path can
// never be mistaken for a replacement of the at-least-once backstop.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeSyncFGA records what the pass applied DIRECTLY to the store after its writer-tx
// committed — separately per direction, so a test can state which direction was carried.
type fakeSyncFGA struct {
	written  []SyncFGATuple
	deleted  []SyncFGATuple
	writeErr error
	delErr   error
}

func (w *fakeSyncFGA) WriteTuples(_ context.Context, tuples []SyncFGATuple) error {
	w.written = append(w.written, tuples...)
	return w.writeErr
}

func (w *fakeSyncFGA) DeleteTuples(_ context.Context, tuples []SyncFGATuple) error {
	w.deleted = append(w.deleted, tuples...)
	return w.delErr
}

func hasSyncTuple(ts []SyncFGATuple, relation, object string) bool {
	for _, t := range ts {
		if t.Relation == relation && t.Object == object {
			return true
		}
	}
	return false
}

// revokeStore builds the delete-stale shape: the object is still in its feed but the
// grant-matching label is gone, so every tuple of the standing grant falls out of the
// desired set. Same fixture the narrowing regression uses — here the question is not
// WHETHER the revoke is derived but WHEN it reaches the store.
func revokeStore() *fakeStore {
	fp := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "update"}}.Fingerprint()
	sub := domain.FGASubjectRef("user", "usr-1")
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
			{ObjectType: "compute.instance", ObjectID: "i-1", ParentProjectID: "prj-1",
				Labels: map[string]string{"tier": "bronze"}},
		}},
		current: []domain.TargetMember{{
			BindingID: "acb-1", RoleID: "rol-1", RuleFP: fp,
			ObjectType: "compute.instance", ObjectID: "i-1",
			VerificationStatus: domain.VerificationActive,
		}},
		ledger: []domain.MembershipTuple{
			{User: sub, Relation: "v_get", Object: "compute_instance:i-1"},
			{User: sub, Relation: "v_update", Object: "compute_instance:i-1"},
			{User: sub, Relation: "editor", Object: "compute_instance:i-1"},
		},
		bindingsForObject: []domain.AccessBindingID{"acb-1"},
	}
}

// TestReconcileObject_RevokeReachesTheStoreInTheSamePass — the property the fast path
// was built for, stated for the RESTRICTIVE direction: when the pass returns, the tuples
// it revoked are gone from the store, not merely queued for removal.
//
// RED before the fix: nothing was ever handed to the store for deletion — the removals
// existed only as fga_outbox rows.
func TestReconcileObject_RevokeReachesTheStoreInTheSamePass(t *testing.T) {
	f := revokeStore()
	w := &fakeSyncFGA{}

	require.NoError(t, New(fakeRunner{s: f}, nil).WithSyncFGA(w).
		ReconcileObject(context.Background(), "compute.instance", "i-1"))

	assert.True(t, hasSyncTuple(w.deleted, "v_get", "compute_instance:i-1"),
		"the revoked v_get must be removed from the store by the time the pass returns, not left to the queue")
	assert.True(t, hasSyncTuple(w.deleted, "v_update", "compute_instance:i-1"),
		"every revoked verb travels the same path — a partial revoke is a standing grant")
	assert.True(t, hasSyncTuple(w.deleted, "editor", "compute_instance:i-1"),
		"the tier tuple is part of the same grant and must go with it")
}

// TestReconcileObject_RevokeStillEnqueuedForTheBackstop — the fast path ADDS a
// same-request apply; it never replaces the durable at-least-once enqueue. Without this
// the previous test could be satisfied by moving the revoke off the outbox, which would
// trade a slow revoke for a lost one.
func TestReconcileObject_RevokeStillEnqueuedForTheBackstop(t *testing.T) {
	f := revokeStore()
	w := &fakeSyncFGA{}

	require.NoError(t, New(fakeRunner{s: f}, nil).WithSyncFGA(w).
		ReconcileObject(context.Background(), "compute.instance", "i-1"))

	var enqueued []domain.MembershipTuple
	for _, b := range f.tdeletes {
		enqueued = append(enqueued, b...)
	}
	assert.True(t, hasTuple(enqueued, "v_get", "compute_instance:i-1"),
		"the durable fga_outbox enqueue must survive the fast path (at-least-once backstop)")
	require.NotEmpty(t, f.forgotten,
		"the ledger lineage is still forgotten in lock-step with the revoke")
}

// TestReconcileObject_RevokeNeverTouchesATupleThePassRewrote — the disjointness the
// same-pass apply relies on. flushDeletes already subtracts tuples this pass (re)wrote
// and tuples another active binding still claims; the direct apply inherits exactly that
// set, so ordering the two directions cannot strip a live grant.
func TestReconcileObject_RevokeNeverTouchesATupleThePassRewrote(t *testing.T) {
	f := revokeStore()
	// The object matches again (label restored), so the pass REWRITES the same tuples it
	// would otherwise have revoked.
	f.mirror["compute.instance"][0].Labels = map[string]string{"tier": "gold"}
	w := &fakeSyncFGA{}

	require.NoError(t, New(fakeRunner{s: f}, nil).WithSyncFGA(w).
		ReconcileObject(context.Background(), "compute.instance", "i-1"))

	assert.Empty(t, w.deleted,
		"a tuple the pass re-derived must never be handed to the store for deletion")
	assert.Empty(t, f.tdeletes,
		"nothing fell out of the desired set, so nothing may be enqueued for removal either")
}

// TestReconcileObject_SyncRevokeUnwired_IsANoOp — an unwired direct writer leaves the
// pass async-only (the pre-existing behaviour), never an error.
func TestReconcileObject_SyncRevokeUnwired_IsANoOp(t *testing.T) {
	f := revokeStore()
	require.NoError(t, New(fakeRunner{s: f}, nil).
		ReconcileObject(context.Background(), "compute.instance", "i-1"),
		"no direct writer wired ⇒ the pass still succeeds on the durable enqueue alone")
	var enqueued []domain.MembershipTuple
	for _, b := range f.tdeletes {
		enqueued = append(enqueued, b...)
	}
	assert.True(t, hasTuple(enqueued, "v_get", "compute_instance:i-1"))
}

// TestReconcileObject_SyncRevokeError_IsNonFatal — the direct apply is an accelerator
// over a durable queue, so its failure degrades to the queue rather than failing a pass
// whose writer-tx already committed.
func TestReconcileObject_SyncRevokeError_IsNonFatal(t *testing.T) {
	f := revokeStore()
	w := &fakeSyncFGA{delErr: errors.New("store unreachable")}

	require.NoError(t, New(fakeRunner{s: f}, nil).WithSyncFGA(w).
		ReconcileObject(context.Background(), "compute.instance", "i-1"),
		"a failed direct revoke must not fail the committed pass — the drainer is the backstop")
	assert.NotEmpty(t, w.deleted, "the attempt was made")
}
