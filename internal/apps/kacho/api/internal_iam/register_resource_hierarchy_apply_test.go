// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// register_resource_hierarchy_apply_test.go — the structural pointer that outlives the
// resource.
//
// A registration writes TWO kinds of relationship. The per-object verbs are derived from
// grants and materialised by the reconciler. The pointer from the object to its owning
// project is written here, and it is not decoration: the account's administrator reaches
// every object inside the account THROUGH it. Remove every verb of a deleted object and
// leave that pointer behind, and the administrator is still answered ALLOW on a resource
// the product reports as gone.
//
// Both directions of the pointer travelled the queue only. That made the whole withdrawal
// exactly as fast as the slowest of two independent queues, and it made the shorter of the
// two fixes look complete while an entire class of subject kept its access.
//
// Measured on the stand (boevaya posadka, one storage volume, the account's administrator
// as the subject): the two removals landed twelve seconds apart, and either one of them
// alone still answered ALLOW.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeHierarchyApplier records what the use-case applied directly to the store after its
// writer-tx committed, per direction.
type fakeHierarchyApplier struct {
	written  []service.RelationTuple
	deleted  []service.RelationTuple
	writeErr error
	delErr   error
}

func (a *fakeHierarchyApplier) WriteTuples(_ context.Context, t []service.RelationTuple) error {
	a.written = append(a.written, t...)
	return a.writeErr
}

func (a *fakeHierarchyApplier) DeleteTuples(_ context.Context, t []service.RelationTuple) error {
	a.deleted = append(a.deleted, t...)
	return a.delErr
}

func newRegUCWithApplier(t *testing.T, a *fakeHierarchyApplier) (*RegisterResourceUseCase, *smTxBeginner) {
	t.Helper()
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb).WithTupleApplier(a, nil)
	return uc, txb
}

// TestUnregisterResource_RemovesTheContainmentPointerInTheSameRequest — the pointer that
// carries the account-administrator's reach must be gone when the withdrawal returns.
//
// RED before the fix: the pointer was only enqueued, so the administrator kept ALLOW on a
// deleted resource for as long as that queue was behind.
func TestUnregisterResource_RemovesTheContainmentPointerInTheSameRequest(t *testing.T) {
	a := &fakeHierarchyApplier{}
	uc, txb := newRegUCWithApplier(t, a)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject:  "project:prj_owner",
		relation: "project",
		object:   "storage_volume:vol_gone",
	}))
	require.True(t, txb.tx.committed)

	require.Len(t, a.deleted, 1,
		"the containment pointer must be removed from the store by the time the withdrawal returns")
	assert.Equal(t, service.RelationTuple{
		User: "project:prj_owner", Relation: "project", Object: "storage_volume:vol_gone",
	}, a.deleted[0])
	assert.Empty(t, a.written, "a withdrawal writes nothing")
}

// TestRegisterResource_AppliesTheContainmentPointerInTheSameRequest — the same treatment
// in the permissive direction, so the two stay symmetric. An asymmetric pair is how the
// original defect arose: whichever direction is left on the queue becomes the one the
// system is slow at.
func TestRegisterResource_AppliesTheContainmentPointerInTheSameRequest(t *testing.T) {
	a := &fakeHierarchyApplier{}
	uc, _ := newRegUCWithApplier(t, a)

	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_new",
	}))

	require.Len(t, a.written, 1, "the containment pointer must be applied, not only enqueued")
	assert.Equal(t, service.RelationTuple{
		User: "project:prj_owner", Relation: "project", Object: "storage_volume:vol_new",
	}, a.written[0])
	assert.Empty(t, a.deleted)
}

// TestUnregisterResource_PureGrantWithdrawal_IsAppliedInTheSameRequest — withdrawing the
// public read grant is a revocation like any other and must not be the one case left on
// the queue.
func TestUnregisterResource_PureGrantWithdrawal_IsAppliedInTheSameRequest(t *testing.T) {
	a := &fakeHierarchyApplier{}
	uc, _ := newRegUCWithApplier(t, a)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "user:*", relation: "v_get", object: "geo_region:reg_ru_central",
	}))

	require.Len(t, a.deleted, 1, "the public grant withdrawal must be applied in the same request")
	assert.Equal(t, "user:*", a.deleted[0].User)
}

// TestRegisterResource_TupleApplierUnwired_IsANoOp — an unwired applier leaves both
// directions on the queue-only path (the pre-existing behaviour), never an error.
func TestRegisterResource_TupleApplierUnwired_IsANoOp(t *testing.T) {
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb) // no WithTupleApplier
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_new",
	}))
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_new",
	}))
}

// TestUnregisterResource_TupleApplyError_IsNonFatal — the withdrawal is durable before
// the apply runs, so a store blip must degrade to the queue, not turn a completed
// withdrawal into an error the caller retries (which would re-run it forever).
func TestUnregisterResource_TupleApplyError_IsNonFatal(t *testing.T) {
	a := &fakeHierarchyApplier{delErr: errors.New("store unreachable")}
	uc, txb := newRegUCWithApplier(t, a)

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_owner", relation: "project", object: "storage_volume:vol_gone",
	}), "a failed direct apply must not fail a committed withdrawal — the drainer is the backstop")
	require.True(t, txb.tx.committed)
	assert.NotEmpty(t, a.deleted, "the attempt was made")
}
