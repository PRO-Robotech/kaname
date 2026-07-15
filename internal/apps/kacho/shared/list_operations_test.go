// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_operations_test.go — unit tests for the shared ListOperationsUseCase
// (the per-resource ListOperations RPC backing logic).
//
// Covers:
//   - happy path: resource_id filter → ops returned + next_page_token passed through;
//   - resource isolation: filter passes resource_id to the repo verbatim;
//   - bad page_token: repo error after a non-empty page_token → InvalidArgument
//     (api-conventions.md: garbage token → InvalidArgument, never INTERNAL);
//   - server error with empty page_token → Internal (not leaked as 400).
//
// No Postgres: uses an in-memory fake operations.Repo (parity with
// account/create_test.go fakeOpsRepo).
package shared_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// recordingOpsRepo implements operations.Repo, capturing the ListFilter it was
// called with and returning a canned result (or error).
type recordingOpsRepo struct {
	gotFilter operations.ListFilter
	ops       []operations.Operation
	next      string
	listErr   error
}

func (r *recordingOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (r *recordingOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *recordingOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *recordingOpsRepo) List(_ context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	r.gotFilter = f
	if r.listErr != nil {
		return nil, "", r.listErr
	}
	return r.ops, r.next, nil
}
func (r *recordingOpsRepo) MarkDone(context.Context, string, *anypb.Any) error      { return nil }
func (r *recordingOpsRepo) MarkError(context.Context, string, *status.Status) error { return nil }
func (r *recordingOpsRepo) Cancel(context.Context, string) error                    { return nil }

func TestListOperationsUseCase_HappyPath_PassesResourceFilter(t *testing.T) {
	repo := &recordingOpsRepo{
		ops: []operations.Operation{
			{ID: "iop00000000000000001", CreatedAt: time.Unix(1, 0)},
			{ID: "iop00000000000000002", CreatedAt: time.Unix(2, 0)},
		},
		next: "nexttoken",
	}
	uc := shared.NewListOperationsUseCase(repo)

	ops, next, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("want 2 ops (the no-op returned 0 — that's the bug), got %d", len(ops))
	}
	if next != "nexttoken" {
		t.Fatalf("next_page_token must pass through, got %q", next)
	}
	if repo.gotFilter.ResourceID != "rol00000000000000001" {
		t.Fatalf("resource_id must be forwarded to repo, got %q", repo.gotFilter.ResourceID)
	}
	if repo.gotFilter.PageSize != 25 {
		t.Fatalf("page_size must be forwarded, got %d", repo.gotFilter.PageSize)
	}
}

func TestListOperationsUseCase_BadPageToken_InvalidArgument(t *testing.T) {
	repo := &recordingOpsRepo{listErr: errors.New("repo.List: invalid page_token: illegal base64")}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "garbage-token")
	if err == nil {
		t.Fatal("want error for bad page_token, got nil")
	}
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("bad page_token must map to InvalidArgument, got %s", got)
	}
}

func TestListOperationsUseCase_ServerErrorEmptyToken_Internal(t *testing.T) {
	repo := &recordingOpsRepo{listErr: errors.New("repo.List: dial tcp: connection refused")}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "")
	if err == nil {
		t.Fatal("want error for server failure, got nil")
	}
	if got := grpcstatus.Code(err); got != codes.Internal {
		t.Fatalf("server error with empty token must map to Internal, got %s", got)
	}
}
