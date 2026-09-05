// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// unregister_resource_sync_revoke_test.go — the withdrawal half of the registration
// contract.
//
// Register does three things in one writer-tx (mirror row, owner tuple, reconcile event)
// and then, after the commit, drives the materialisation in-process so the caller's next
// question is answered by the new state. Unregister did the symmetric three (mirror row
// removed, tuple-delete enqueued, reconcile event) and then stopped: the materialisation
// it needs — the pass that strips the object's per-object verbs now that its projection
// is gone — was left entirely to whatever depth the reconcile queue happened to have.
//
// The asymmetry is not cosmetic. It means granting is bounded by one in-process pass and
// withdrawing is bounded by a queue, i.e. the product is fast at saying yes and slow at
// saying no. Measured on the stand (boevaya posadka, one storage volume): its verbs were
// present within the create request and were still answered ALLOW for twelve seconds
// after the resource itself had begun answering 404.
//
// The forward entry point is the right one to call: it hands an object that ALREADY has
// materialised members to the full pass, whose delete-stale diff is exactly the removal
// wanted here (see ReconcileObjectForward's delete-stale guard). The co-committed
// reconcile event remains the at-least-once backstop.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnregisterResource_DrivesTheRevokeInTheSameRequest — withdrawal starts its
// materialisation in-process, exactly as registration does.
//
// RED before the fix: zero post-commit passes — the revoke began only when the reconcile
// queue reached the co-committed event.
func TestUnregisterResource_DrivesTheRevokeInTheSameRequest(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, txb := newRegUC(t, rec)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject:  "project:prj_owner",
		relation: "project",
		object:   "storage_volume:vol_gone",
	}))
	require.NotNil(t, txb.tx)
	require.True(t, txb.tx.committed, "unregister must commit the writer-tx")

	calls := rec.snapshot()
	require.Len(t, calls, 1,
		"withdrawal must drive exactly one post-commit pass on the withdrawn object — "+
			"otherwise the revoke waits out the reconcile queue while the grant never did")
	assert.Equal(t, [2]string{"storage.volumes", "vol_gone"}, calls[0],
		"the pass must target the withdrawn object (dotted type)")
}

// TestUnregisterResource_NilReconciler_NonFatal — an unwired reconciler leaves the
// withdrawal on the queue-only path (the pre-existing behaviour), never an error.
func TestUnregisterResource_NilReconciler_NonFatal(t *testing.T) {
	uc, txb := newRegUC(t, nil)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_gone",
	}), "nil reconciler must be a non-fatal no-op")
	require.True(t, txb.tx.committed)
}

// TestUnregisterResource_ReconcileError_NonFatal — the withdrawal is already durable when
// the pass runs (mirror row deleted, tuple-delete enqueued, event co-committed), so a
// failed pass must not turn a completed withdrawal into an error the caller retries.
func TestUnregisterResource_ReconcileError_NonFatal(t *testing.T) {
	rec := &smObjectReconciler{err: errors.New("reconcile transient")}
	uc, txb := newRegUC(t, rec)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_gone",
	}), "a post-commit reconcile error must not fail a committed withdrawal (queue is the backstop)")
	require.True(t, txb.tx.committed)
	require.Len(t, rec.snapshot(), 1)
}

// TestUnregisterResource_PureGrantWithdrawal_LeavesTheObjectAlone — withdrawing the
// public wildcard grant says nothing about the object's own projection, so it must not
// drive an object pass. Without this the previous tests could be satisfied by
// reconciling unconditionally, which would re-derive membership for an object that is
// still alive and untouched.
func TestUnregisterResource_PureGrantWithdrawal_LeavesTheObjectAlone(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, _ := newRegUC(t, rec)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject:  "user:*",
		relation: "v_get",
		object:   "geo_region:reg_ru_central",
	}))
	assert.Empty(t, rec.snapshot(),
		"a pure-grant withdrawal touches no projection, so it must drive no object pass")
}
