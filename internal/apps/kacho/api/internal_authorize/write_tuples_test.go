// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// write_tuples_test.go — handler-level unit coverage for
// InternalAuthorizeService.WriteTuples, which previously had ZERO functional
// tests (the opaque-INTERNAL errleak hardening on the operation-create failure
// paths landed untested).
//
// WriteTuples is internal-only (:9091, ban #6) with no public REST route, so
// coverage is handler-unit via a fake service.RelationWriter (the tuple writer
// port — no live OpenFGA) and a fake operations.Repo. The async application is
// drained deterministically through operations.Wait (no time.Sleep).
package internal_authorize

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// capturingRelWriter — service.RelationWriter that records the last
// WriteConditionalTuples call and optionally injects an error.
type capturingRelWriter struct {
	mu         sync.Mutex
	gotWrites  []clients.ConditionalTuple
	gotDeletes []clients.ConditionalTuple
	writeErr   error
}

func (f *capturingRelWriter) WriteConditionalTuples(_ context.Context, writes, deletes []clients.ConditionalTuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.gotWrites = append([]clients.ConditionalTuple(nil), writes...)
	f.gotDeletes = append([]clients.ConditionalTuple(nil), deletes...)
	return nil
}

func (f *capturingRelWriter) ReadTuples(_ context.Context, _, _, _ string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

func (f *capturingRelWriter) GetStoreInfo(_ context.Context) (clients.StoreInfo, error) {
	return clients.StoreInfo{}, nil
}

// wtFakeOps — in-memory operations.Repo. createErr, when set, makes Create fail
// (exercising the opaque-INTERNAL errleak path).
type wtFakeOps struct {
	mu        sync.Mutex
	ops       map[string]*operations.Operation
	createErr error
}

func newWTFakeOps() *wtFakeOps { return &wtFakeOps{ops: map[string]*operations.Operation{}} }

func (r *wtFakeOps) Create(_ context.Context, op operations.Operation) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}
func (r *wtFakeOps) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}
func (r *wtFakeOps) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (r *wtFakeOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *wtFakeOps) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}
func (r *wtFakeOps) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}
func (r *wtFakeOps) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

func tuple(subject, relation, object string) *iamv1.Tuple {
	return &iamv1.Tuple{Subject: subject, Relation: relation, Object: object}
}

// TestWriteTuples_BatchTooLarge_InvalidArgument — >100 writes (or deletes) is
// rejected synchronously with InvalidArgument before any Operation is created.
func TestWriteTuples_BatchTooLarge_InvalidArgument(t *testing.T) {
	ops := newWTFakeOps()
	h := NewHandler(service.NewRelationProjector(&capturingRelWriter{}), ops, "model-x")

	writes := make([]*iamv1.Tuple, 101)
	for i := range writes {
		writes[i] = tuple("user:usr_x", "owner", "account:acc_x")
	}

	op, err := h.WriteTuples(context.Background(), &iamv1.WriteTuplesRequest{Writes: writes})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	// No Operation must have been created for a rejected batch.
	ops.mu.Lock()
	assert.Empty(t, ops.ops, "no Operation should be created on sync rejection")
	ops.mu.Unlock()
}

// TestWriteTuples_CombinedBatchTooLarge_InvalidArgument — OpenFGA's
// maxTuplesPerWrite (100) caps writes+deletes COMBINED per /write request, and
// the admin WriteRaw path (WriteConditionalTuples) does NOT chunk. A batch that
// stays ≤100 in each direction but exceeds 100 combined (here 60 writes + 60
// deletes = 120) must therefore be rejected synchronously — otherwise it is sent
// as one over-limit request that OpenFGA rejects wholesale (400 validation_error),
// applying NONE of the tuples, and the Operation fails opaquely.
func TestWriteTuples_CombinedBatchTooLarge_InvalidArgument(t *testing.T) {
	ops := newWTFakeOps()
	h := NewHandler(service.NewRelationProjector(&capturingRelWriter{}), ops, "model-x")

	writes := make([]*iamv1.Tuple, 60)
	for i := range writes {
		writes[i] = tuple("user:usr_x", "owner", "account:acc_x")
	}
	deletes := make([]*iamv1.Tuple, 60)
	for i := range deletes {
		deletes[i] = tuple("user:usr_y", "viewer", "account:acc_x")
	}

	op, err := h.WriteTuples(context.Background(), &iamv1.WriteTuplesRequest{
		Writes:  writes,
		Deletes: deletes,
	})

	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	// No Operation must have been created for a rejected batch.
	ops.mu.Lock()
	assert.Empty(t, ops.ops, "no Operation should be created on sync rejection")
	ops.mu.Unlock()
}

// TestWriteTuples_OpsCreateFails_OpaqueInternal — when the operations.Repo
// Create fails, the handler must return a FIXED opaque INTERNAL message and
// never echo the underlying error text (which could carry pgx/DB driver detail).
func TestWriteTuples_OpsCreateFails_OpaqueInternal(t *testing.T) {
	const secret = `pq: FATAL host=10.0.0.5 port=5432 user=iam db=kacho_iam password leak`
	ops := newWTFakeOps()
	ops.createErr = stderrors.New(secret)
	h := NewHandler(service.NewRelationProjector(&capturingRelWriter{}), ops, "model-x")

	op, err := h.WriteTuples(context.Background(), &iamv1.WriteTuplesRequest{
		Writes: []*iamv1.Tuple{tuple("user:usr_x", "owner", "account:acc_x")},
	})

	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "create operation failed", st.Message(), "message must be the fixed opaque text")
	assert.NotContains(t, st.Message(), secret, "the raw ops-repo error must not leak to the client")
}

// TestWriteTuples_HappyPath_AppliesTuples — a well-formed batch returns an
// in-flight Operation synchronously; the async worker applies the writes/deletes
// through the tuple writer and records the WriteTuplesResult counts.
func TestWriteTuples_HappyPath_AppliesTuples(t *testing.T) {
	ctx := context.Background()
	writer := &capturingRelWriter{}
	ops := newWTFakeOps()
	h := NewHandler(service.NewRelationProjector(writer), ops, "model-x")

	op, err := h.WriteTuples(ctx, &iamv1.WriteTuplesRequest{
		Writes: []*iamv1.Tuple{
			tuple("user:usr_a", "owner", "account:acc_a"),
			tuple("user:usr_b", "viewer", "account:acc_a"),
		},
		Deletes:        []*iamv1.Tuple{tuple("user:usr_c", "editor", "account:acc_a")},
		IdempotencyKey: "idem-1",
	})

	require.NoError(t, err)
	require.NotNil(t, op)
	assert.NotEmpty(t, op.GetId())
	assert.False(t, op.GetDone(), "Operation is returned in-flight (async)")

	// Drain the async worker deterministically.
	require.NoError(t, operations.Wait(ctx))

	// The writer received exactly the converted writes/deletes.
	writer.mu.Lock()
	gotW, gotD := writer.gotWrites, writer.gotDeletes
	writer.mu.Unlock()
	require.Len(t, gotW, 2)
	require.Len(t, gotD, 1)
	assert.Equal(t, "user:usr_a", gotW[0].User)
	assert.Equal(t, "account:acc_a", gotW[0].Object)
	assert.Equal(t, "user:usr_c", gotD[0].User)

	// The Operation completed with the WriteTuplesResult counts.
	stored, gerr := ops.Get(ctx, op.GetId())
	require.NoError(t, gerr)
	require.True(t, stored.Done, "operation must be marked done after apply")
	require.Nil(t, stored.Error, "operation must not carry an error on the happy path")
	require.NotNil(t, stored.Response)
	var res iamv1.WriteTuplesResult
	require.NoError(t, stored.Response.UnmarshalTo(&res))
	assert.EqualValues(t, 2, res.GetInserted())
	assert.EqualValues(t, 1, res.GetDeleted())
}
