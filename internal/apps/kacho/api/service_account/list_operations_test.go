// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_operations_test.go — unit test for ServiceAccountService.ListOperations.
//
// Verifies the fix for the no-op handler: ListOperations must return the
// operations recorded for the given service account id, and reject a malformed id.
package service_account_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	serviceaccount "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/service_account"
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

func TestServiceAccount_ListOperations_ReturnsRecordedOps(t *testing.T) {
	repo := &fakeOpsList{ops: []operations.Operation{
		{ID: "iop00000000000000001", Description: "Create service account x", CreatedAt: time.Unix(1, 0)},
	}, next: "tok"}
	h := serviceaccount.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(context.Background(),
		&iamv1.ListServiceAccountOperationsRequest{ServiceAccountId: "sva00000000000000001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOperations()) != 1 {
		t.Fatalf("want 1 operation (no-op returned 0 — the bug), got %d", len(resp.GetOperations()))
	}
	if resp.GetNextPageToken() != "tok" {
		t.Fatalf("next_page_token must pass through, got %q", resp.GetNextPageToken())
	}
}

func TestServiceAccount_ListOperations_MalformedID_InvalidArgument(t *testing.T) {
	h := serviceaccount.NewHandler(nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(&fakeOpsList{}))

	_, err := h.ListOperations(context.Background(),
		&iamv1.ListServiceAccountOperationsRequest{ServiceAccountId: "not-a-sa-id"})
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("malformed service account id must be InvalidArgument, got %s", got)
	}
}
