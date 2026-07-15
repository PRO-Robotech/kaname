// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_operations_test.go — unit test for RoleService.ListOperations.
//
// Verifies the fix for the no-op handler (was `return &ListRoleOperationsResponse{}`):
// ListOperations must return the operations recorded for the given role id,
// and reject a malformed role id with InvalidArgument.
package role_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

type fakeOpsList struct {
	ops  []operations.Operation
	next string
}

func (r *fakeOpsList) Create(context.Context, operations.Operation) error { return nil }
func (r *fakeOpsList) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *fakeOpsList) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *fakeOpsList) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return r.ops, r.next, nil
}
func (r *fakeOpsList) MarkDone(context.Context, string, *anypb.Any) error      { return nil }
func (r *fakeOpsList) MarkError(context.Context, string, *status.Status) error { return nil }
func (r *fakeOpsList) Cancel(context.Context, string) error                    { return nil }

func TestRole_ListOperations_ReturnsRecordedOps(t *testing.T) {
	repo := &fakeOpsList{ops: []operations.Operation{
		{ID: "iop00000000000000001", Description: "Create role x", CreatedAt: time.Unix(1, 0)},
	}, next: "tok"}
	h := role.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(context.Background(),
		&iamv1.ListRoleOperationsRequest{RoleId: "rol00000000000000001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOperations()) != 1 {
		t.Fatalf("want 1 operation (no-op returned 0 — the bug), got %d", len(resp.GetOperations()))
	}
	if resp.GetOperations()[0].GetId() != "iop00000000000000001" {
		t.Fatalf("operation id mismatch: %s", resp.GetOperations()[0].GetId())
	}
	if resp.GetNextPageToken() != "tok" {
		t.Fatalf("next_page_token must pass through, got %q", resp.GetNextPageToken())
	}
}

func TestRole_ListOperations_MalformedID_InvalidArgument(t *testing.T) {
	h := role.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(&fakeOpsList{}))

	_, err := h.ListOperations(context.Background(),
		&iamv1.ListRoleOperationsRequest{RoleId: "not-a-role-id"})
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("malformed role id must be InvalidArgument, got %s", got)
	}
}
