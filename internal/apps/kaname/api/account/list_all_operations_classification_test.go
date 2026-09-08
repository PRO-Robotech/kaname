// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// list_all_operations_classification_test.go — the account-scoped operations
// feed must report WHAT FAILED, not WHAT THE CALLER SENT.
//
// Same class as the per-resource feed and the cluster-wide one: the store
// answers a caller-format problem as a gRPC InvalidArgument naming the field,
// and everything else it returns is a store failure. Choosing between the two by
// "was a page_token supplied" mislabels both directions.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	coreerrors "github.com/PRO-Robotech/kacho/pkg/errors"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"
)

// acctFailingOpsRepo — operations.Repo whose List always fails.
type acctFailingOpsRepo struct{ err error }

func (r *acctFailingOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (r *acctFailingOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *acctFailingOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *acctFailingOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", r.err
}
func (r *acctFailingOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (r *acctFailingOpsRepo) MarkError(context.Context, string, *gstatuspb.Status) error {
	return nil
}
func (r *acctFailingOpsRepo) Cancel(context.Context, string) error { return nil }

func acctOwnedUC(ops operations.Repo) (*ListAllOperationsUseCase, context.Context, string) {
	repo := newAcctListFakeRepo()
	const acctID = "acc0000000000000clsf"
	seedAcct(repo, acctID, "usr-owner")
	return newListAllUC(repo, nil, ops), ctxUser("usr-owner"), acctID
}

func TestListAllOperations_StoreFailureWithPageToken_IsNotACursorError(t *testing.T) {
	uc, ctx, acctID := acctOwnedUC(&acctFailingOpsRepo{
		err: errors.New("repo.List: dial tcp: connection refused"),
	})

	_, _, err := uc.Execute(ctx, acctID, 100, "Q3JlYXRlZEF0fGlvcDE=")

	require.Error(t, err)
	assert.Equal(t, codes.Internal, grpcstatus.Code(err),
		"an unreachable store is a store failure, not a malformed cursor")
	assert.Equal(t, "list operations failed", grpcstatus.Convert(err).Message())
}

func TestListAllOperations_MalformedPageToken_InvalidArgument(t *testing.T) {
	uc, ctx, acctID := acctOwnedUC(&acctFailingOpsRepo{
		err: coreerrors.InvalidArgument().
			AddFieldViolation("page_token", "page_token is invalid or malformed").
			Err(),
	})

	_, _, err := uc.Execute(ctx, acctID, 100, "not-a-cursor")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
}

func TestListAllOperations_PageSizeRejected_StaysInvalidArgument(t *testing.T) {
	_, pageSizeErr := corevalidate.PageSize("page_size", 5000)
	uc, ctx, acctID := acctOwnedUC(&acctFailingOpsRepo{err: pageSizeErr})

	_, _, err := uc.Execute(ctx, acctID, 5000, "")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"page_size out of range is the caller's error on the FIRST page too")
}
