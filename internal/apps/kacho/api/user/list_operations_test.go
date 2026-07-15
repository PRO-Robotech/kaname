// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_operations_test.go — unit test for UserService.ListOperations.
//
// Mirrors the existing per-resource ListOperations of Account/Project/Role/
// Group/ServiceAccount: the handler validates the user id (malformed →
// InvalidArgument, first statement), then delegates to the shared
// ListOperationsUseCase which filters the common `operations` table by the
// denormalized resource_id column. Well-formed-but-no-ops → empty list, not
// NotFound (parity with the existing five).
package user_test

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

	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// fakeOpsList — minimal operations.Repo stub that echoes a canned page.
type fakeOpsList struct {
	ops        []operations.Operation
	next       string
	gotFilter  operations.ListFilter
	listCalled bool
}

func (r *fakeOpsList) Create(context.Context, operations.Operation) error { return nil }
func (r *fakeOpsList) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *fakeOpsList) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *fakeOpsList) List(_ context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	r.listCalled = true
	r.gotFilter = f
	return r.ops, r.next, nil
}
func (r *fakeOpsList) MarkDone(context.Context, string, *anypb.Any) error      { return nil }
func (r *fakeOpsList) MarkError(context.Context, string, *status.Status) error { return nil }
func (r *fakeOpsList) Cancel(context.Context, string) error                    { return nil }

func TestUser_ListOperations_ReturnsRecordedOps(t *testing.T) {
	repo := &fakeOpsList{ops: []operations.Operation{
		{ID: "iop00000000000000001", Description: "Delete user x", CreatedAt: time.Unix(1, 0)},
	}, next: "tok"}
	h := userapp.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(context.Background(),
		&iamv1.ListUserOperationsRequest{UserId: "usr00000000000000001", PageSize: 50})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOperations()) != 1 {
		t.Fatalf("want 1 operation, got %d", len(resp.GetOperations()))
	}
	if resp.GetNextPageToken() != "tok" {
		t.Fatalf("next_page_token must pass through, got %q", resp.GetNextPageToken())
	}
	// Filter must scope by resource_id = user_id (1.2-01 isolation).
	if repo.gotFilter.ResourceID != "usr00000000000000001" {
		t.Fatalf("filter must scope by resource_id=user_id, got %q", repo.gotFilter.ResourceID)
	}
	if repo.gotFilter.PageSize != 50 {
		t.Fatalf("page_size must pass through, got %d", repo.gotFilter.PageSize)
	}
}

func TestUser_ListOperations_MalformedID_InvalidArgument(t *testing.T) {
	repo := &fakeOpsList{}
	h := userapp.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	_, err := h.ListOperations(context.Background(),
		&iamv1.ListUserOperationsRequest{UserId: "not-a-user-id"})
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("malformed user id must be InvalidArgument, got %s", got)
	}
	if repo.listCalled {
		t.Fatalf("malformed id must be rejected before hitting the repo (first statement)")
	}
}

func TestUser_ListOperations_WellFormedMissing_EmptyList(t *testing.T) {
	// Parity with the existing five: no pre-Get, so a well-formed-but-missing
	// user id yields OK with an empty list, never NotFound (1.2-04).
	repo := &fakeOpsList{ops: nil, next: ""}
	h := userapp.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(context.Background(),
		&iamv1.ListUserOperationsRequest{UserId: "usr0000000000000miss"})
	if err != nil {
		t.Fatalf("well-formed-but-missing must be OK empty, got err %v", err)
	}
	if len(resp.GetOperations()) != 0 || resp.GetNextPageToken() != "" {
		t.Fatalf("expected empty list, got %d ops / token %q", len(resp.GetOperations()), resp.GetNextPageToken())
	}
}
