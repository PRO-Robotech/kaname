// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// register_resource_sync_materialize_test.go — Design-B (flat-authz verb-bearing
// complete) acceptance VBC-15 (instant visibility). RegisterResource (the
// vpc/compute/nlb fgaproxy create path) co-commits the owner-tuple + mirror row +
// reconcile event, then drives a SYNCHRONOUS post-commit ReconcileObject so the
// owner's per-object v_get materializes BEFORE the consumer's create-Operation
// reports done — a create→immediate-GET resolves ALLOW without waiting for the
// async reconcile-outbox drain. nil-safe + non-fatal: an unwired reconciler (or a
// reconcile error) does not fail Register (the outbox drain + periodic sweep are
// the backstop).
//
// RED until RegisterResourceUseCase.WithObjectReconciler drives a post-commit
// ReconcileObject.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── unit fakes (Tx / emitter / mirror / object-reconciler) ──────────────────

type smTx struct{ committed bool }

func (t *smTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *smTx) Rollback(context.Context) error { return nil }

type smTxBeginner struct{ tx *smTx }

func (b *smTxBeginner) Begin(context.Context) (service.Tx, error) {
	b.tx = &smTx{}
	return b.tx, nil
}

type smEmitter struct{}

func (smEmitter) EmitWriteTx(context.Context, service.Tx, []service.RelationTuple) error  { return nil }
func (smEmitter) EmitDeleteTx(context.Context, service.Tx, []service.RelationTuple) error { return nil }

type mirrorAdapter struct{}

func (mirrorAdapter) UpsertTx(context.Context, service.Tx, service.ResourceMirrorRow) error {
	return nil
}
func (mirrorAdapter) DeleteTx(context.Context, service.Tx, string, string, time.Time) error {
	return nil
}

// regReq satisfies the registerInput interface (tupleInput + versionedInput +
// labels + parent-scope) the use-case consumes at the handler boundary.
type regReq struct {
	subject  string
	relation string
	object   string
}

func (r *regReq) GetSubjectId() string                     { return r.subject }
func (r *regReq) GetRelation() string                      { return r.relation }
func (r *regReq) GetObject() string                        { return r.object }
func (r *regReq) GetSourceVersion() *timestamppb.Timestamp { return nil }
func (r *regReq) GetLabels() map[string]string             { return nil }
func (r *regReq) GetParentProjectId() string               { return "" }
func (r *regReq) GetParentAccountId() string               { return "" }

// smObjectReconciler records ReconcileObjectForward calls (the create-path additive
// fast-path the register use-case now drives post-commit).
type smObjectReconciler struct {
	mu    sync.Mutex
	calls [][2]string // (objectType, objectID)
	err   error
}

func (r *smObjectReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [2]string{objectType, objectID})
	return r.err
}
func (r *smObjectReconciler) snapshot() [][2]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([][2]string, len(r.calls))
	copy(cp, r.calls)
	return cp
}

func newRegUC(t *testing.T, rec *smObjectReconciler) (*RegisterResourceUseCase, *smTxBeginner) {
	t.Helper()
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb)
	if rec != nil {
		uc = uc.WithObjectReconciler(rec, nil)
	}
	return uc, txb
}

// TestRegisterResource_VBC15_SyncReconcileAfterCommit — a successful Register drives
// a SYNCHRONOUS ReconcileObject on the registered object AFTER commit (instant
// visibility: owner v_get materializes before the consumer's Operation reports done).
func TestRegisterResource_VBC15_SyncReconcileAfterCommit(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, txb := newRegUC(t, rec)

	err := uc.Register(context.Background(), &regReq{
		subject: "user:usr_creator",
		// vpc fgaproxy register: creator gets v_get on the freshly-created network.
		relation: "v_get",
		object:   "vpc_network:vpcn_new",
	})
	require.NoError(t, err)
	require.NotNil(t, txb.tx)
	require.True(t, txb.tx.committed, "register must commit the writer-tx")

	calls := rec.snapshot()
	require.Len(t, calls, 1, "VBC-15: exactly one post-commit ReconcileObjectForward on the registered object")
	assert.Equal(t, [2]string{"vpc.network", "vpcn_new"}, calls[0],
		"VBC-15: post-commit ReconcileObjectForward must target the registered object (dotted type)")
}

// TestRegisterResource_VBC15_NilReconciler_NonFatal — an unwired reconciler does
// not fail Register (async outbox drain is the backstop).
func TestRegisterResource_VBC15_NilReconciler_NonFatal(t *testing.T) {
	uc, txb := newRegUC(t, nil) // no WithObjectReconciler
	err := uc.Register(context.Background(), &regReq{
		subject: "user:usr_creator", relation: "v_get", object: "vpc_network:vpcn_new",
	})
	require.NoError(t, err, "VBC-15: nil reconciler must be a non-fatal no-op")
	require.True(t, txb.tx.committed)
}

// TestRegisterResource_VBC15_ReconcileError_NonFatal — a reconcile error after a
// committed register is NON-fatal (the resource is durably registered; the drain
// + sweep retry). Register still returns success.
func TestRegisterResource_VBC15_ReconcileError_NonFatal(t *testing.T) {
	rec := &smObjectReconciler{err: errors.New("reconcile transient")}
	uc, txb := newRegUC(t, rec)
	err := uc.Register(context.Background(), &regReq{
		subject: "user:usr_creator", relation: "v_get", object: "vpc_network:vpcn_new",
	})
	require.NoError(t, err,
		"VBC-15: a post-commit reconcile error must NOT fail Register (outbox/sweep backstop)")
	require.True(t, txb.tx.committed)
	require.Len(t, rec.snapshot(), 1)
}
