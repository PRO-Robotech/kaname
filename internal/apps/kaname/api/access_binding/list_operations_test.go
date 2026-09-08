// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_operations_test.go — unit test for AccessBindingService.ListOperations.
//
// Mirrors the existing per-resource ListOperations of the core resources: the
// handler validates the access-binding id (malformed → InvalidArgument, first
// statement) then delegates to the shared ListOperationsUseCase filtering the
// common `operations` table by the denormalized resource_id column. Create +
// Delete operations of one binding both carry resource_id=acb-… so both are
// returned; well-formed-but-no-ops → empty list (parity).
package access_binding_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	abapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
)

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

func TestAccessBinding_ListOperations_ReturnsCreateAndDelete(t *testing.T) {
	repo := &fakeOpsList{ops: []operations.Operation{
		{ID: "iop00000000000000001", Description: "Create access binding", CreatedAt: time.Unix(1, 0), Principal: opsCaller},
		{ID: "iop00000000000000002", Description: "Delete access binding", CreatedAt: time.Unix(2, 0), Principal: opsCaller},
	}, next: ""}
	h := abapp.NewHandler(nil, nil, nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(opsCallerCtx(),
		&iamv1.ListAccessBindingOperationsRequest{AccessBindingId: "acb00000000000000001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOperations()) != 2 {
		t.Fatalf("want 2 operations (create+delete), got %d", len(resp.GetOperations()))
	}
	if resp.GetNextPageToken() != "" {
		t.Fatalf("single page expected, got token %q", resp.GetNextPageToken())
	}
	if repo.gotFilter.ResourceID != "acb00000000000000001" {
		t.Fatalf("filter must scope by resource_id=access_binding_id, got %q", repo.gotFilter.ResourceID)
	}
}

func TestAccessBinding_ListOperations_MalformedID_InvalidArgument(t *testing.T) {
	repo := &fakeOpsList{}
	h := abapp.NewHandler(nil, nil, nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	_, err := h.ListOperations(context.Background(),
		&iamv1.ListAccessBindingOperationsRequest{AccessBindingId: "garbage"})
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("malformed access binding id must be InvalidArgument, got %s", got)
	}
	if repo.listCalled {
		t.Fatalf("malformed id must be rejected before hitting the repo (first statement)")
	}
}

func TestAccessBinding_ListOperations_WellFormedMissing_EmptyList(t *testing.T) {
	repo := &fakeOpsList{ops: nil, next: ""}
	h := abapp.NewHandler(nil, nil, nil, nil, nil, nil, nil).
		WithListOperations(shared.NewListOperationsUseCase(repo))

	resp, err := h.ListOperations(opsCallerCtx(),
		&iamv1.ListAccessBindingOperationsRequest{AccessBindingId: "acb0000000000000miss"})
	if err != nil {
		t.Fatalf("well-formed-but-missing must be OK empty, got err %v", err)
	}
	if len(resp.GetOperations()) != 0 {
		t.Fatalf("expected empty list, got %d ops", len(resp.GetOperations()))
	}
}

// ---- operations.OwnedOperationRepo ----
//
// Список операций теперь ownership-scoped: фейк обязан нести и суженный путь,
// иначе use-case честно откажет (несуженного отката нет). ListOwned фильтрует
// по владельцу — ровно то, что делает предикат в SQL WHERE.

var opsCaller = operations.Principal{Type: "user", ID: "usr-caller", DisplayName: "caller@kacho.local"}

func opsCallerCtx() context.Context {
	return operations.WithPrincipal(context.Background(), opsCaller)
}

func (r *fakeOpsList) GetOwned(context.Context, string, operations.Owner) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}

func (r *fakeOpsList) CancelOwned(context.Context, string, operations.Owner) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}

func (r *fakeOpsList) ListOwned(_ context.Context, f operations.ListFilter, owner operations.Owner) ([]operations.Operation, string, error) {
	r.listCalled = true
	r.gotFilter = f
	var out []operations.Operation
	for _, op := range r.ops {
		if op.Principal.Type == owner.PrincipalType && op.Principal.ID == owner.PrincipalID {
			out = append(out, op)
		}
	}
	return out, r.next, nil
}

var _ operations.OwnedOperationRepo = (*fakeOpsList)(nil)
