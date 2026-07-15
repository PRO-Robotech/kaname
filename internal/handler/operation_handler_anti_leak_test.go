// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// operation_handler_w1_6_test.go — regression tests for the OperationHandler
// authorization guard: anonymous principals must be rejected BEFORE the
// IsSelf check, otherwise `!IsAnonymous(ctx) && !IsSelf(...)` short-circuits
// to `false` and anyone can GET / Cancel any operation by id. Covers Get and
// Cancel for the three principal flavours (anonymous, cross-user, self).
package handler

import (
	"context"
	"testing"
	"time"

	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// fakeOpsRepoW16 — minimal operations.Repo for the authz-guard regression
// tests. Only Get / Cancel are exercised; the rest are no-op stubs.
type fakeOpsRepoW16 struct {
	store map[string]*operations.Operation
}

func newFakeRepoW16(op *operations.Operation) *fakeOpsRepoW16 {
	return &fakeOpsRepoW16{store: map[string]*operations.Operation{op.ID: op}}
}

func (r *fakeOpsRepoW16) Create(_ context.Context, op operations.Operation) error {
	r.store[op.ID] = &op
	return nil
}
func (r *fakeOpsRepoW16) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	r.store[op.ID] = &op
	return nil
}
func (r *fakeOpsRepoW16) Get(_ context.Context, id string) (*operations.Operation, error) {
	o, ok := r.store[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	return o, nil
}
func (r *fakeOpsRepoW16) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (r *fakeOpsRepoW16) MarkDone(_ context.Context, _ string, _ *anypb.Any) error { return nil }
func (r *fakeOpsRepoW16) MarkError(_ context.Context, _ string, _ *gstatus.Status) error {
	return nil
}
func (r *fakeOpsRepoW16) Cancel(_ context.Context, id string) error {
	if _, ok := r.store[id]; !ok {
		return operations.ErrNotFound
	}
	return nil
}

func sampleOp() *operations.Operation {
	return &operations.Operation{
		ID:        "iop_alice_op_1234567890ab",
		CreatedAt: time.Now(),
		Principal: operations.Principal{Type: "user", ID: "usr_alice"},
	}
}

func TestW1_6_09_OperationGet_AnonymousReturnsNotFound(t *testing.T) {
	h := NewOperationHandler(newFakeRepoW16(sampleOp()))
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})

	_, err := h.Get(ctx, &operationpb.GetOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("anonymous Get must return NotFound (anti-info-leak), got %v", err)
	}
}

func TestW1_6_09_OperationGet_OtherPrincipalReturnsNotFound(t *testing.T) {
	h := NewOperationHandler(newFakeRepoW16(sampleOp()))
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_bob"})

	_, err := h.Get(ctx, &operationpb.GetOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("cross-user Get must return NotFound, got %v", err)
	}
}

func TestW1_6_09_OperationGet_SelfPrincipalReturnsOK(t *testing.T) {
	h := NewOperationHandler(newFakeRepoW16(sampleOp()))
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})

	op, err := h.Get(ctx, &operationpb.GetOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if err != nil {
		t.Fatalf("owner Get must succeed, got %v", err)
	}
	if op.GetId() != "iop_alice_op_1234567890ab" {
		t.Fatalf("returned wrong op id: %v", op.GetId())
	}
}

func TestW1_6_09_OperationCancel_AnonymousReturnsNotFound(t *testing.T) {
	h := NewOperationHandler(newFakeRepoW16(sampleOp()))
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})

	_, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("anonymous Cancel must return NotFound, got %v", err)
	}
}

func TestW1_6_09_OperationCancel_OtherPrincipalReturnsNotFound(t *testing.T) {
	h := NewOperationHandler(newFakeRepoW16(sampleOp()))
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_bob"})

	_, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("cross-user Cancel must return NotFound, got %v", err)
	}
}
