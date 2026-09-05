// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_operations

// list_error_classification_test.go — what the cluster administrator is told
// when the listing fails.
//
// The store answers a caller-format problem as a gRPC InvalidArgument naming the
// field (page_token / page_size); everything else it reports is a store failure.
// A classifier that keys on "was a page_token supplied" instead of on what the
// store said sends the operator to the wrong place twice over: a database that
// is down reads as a malformed cursor (retry with a different token, forever),
// and a page_size out of range reads as an internal fault (a client's mistake
// filed as an outage).

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

// failingOpsRepo — operations.Repo whose List always fails with a canned error.
type failingOpsRepo struct {
	err error
}

func (r *failingOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (r *failingOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *failingOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *failingOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", r.err
}
func (r *failingOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (r *failingOpsRepo) MarkError(context.Context, string, *gstatuspb.Status) error {
	return nil
}
func (r *failingOpsRepo) Cancel(context.Context, string) error { return nil }

// admittedAdmin — a checker that lets the cluster administrator through, so the
// cases below exercise the listing itself rather than the gate.
func admittedAdmin() *clusterCheckStub {
	return &clusterCheckStub{allow: map[string]bool{
		"user:usr-admin|system_admin|" + clusterObj(): true,
	}}
}

// repoPageTokenErr — byte-for-byte what pkg/operations returns for a cursor it
// cannot decode.
func repoPageTokenErr() error {
	return coreerrors.InvalidArgument().
		AddFieldViolation("page_token", "page_token is invalid or malformed").
		Err()
}

// repoPageSizeErr — what pkg/operations returns for a page_size out of range
// (corevalidate.PageSize, the very call the repo makes).
func repoPageSizeErr() error {
	_, err := corevalidate.PageSize("page_size", 5000)
	return err
}

// A store that is unreachable must be reported as a store failure — even when a
// page_token was supplied. Naming the caller's cursor here is a false accusation:
// the cursor was never read.
func TestListIamOperations_StoreFailureWithPageToken_IsNotACursorError(t *testing.T) {
	uc := NewListIamOperationsUseCase(&failingOpsRepo{
		err: errors.New("repo.List: dial tcp 10.0.0.1:5432: connect: connection refused"),
	}).WithAdminChecker(admittedAdmin())

	_, _, err := uc.Execute(adminCtx("usr-admin"), "", 100, "Q3JlYXRlZEF0fGlvcDE=")

	require.Error(t, err)
	assert.Equal(t, codes.Internal, grpcstatus.Code(err),
		"an unreachable store is a store failure; reporting it as a bad cursor sends the operator to fix the client")
	assert.Equal(t, "list operations failed", grpcstatus.Convert(err).Message(),
		"the store's own text must never reach the caller")
}

// A cursor the store rejected keeps its classification.
func TestListIamOperations_MalformedPageToken_InvalidArgument(t *testing.T) {
	uc := NewListIamOperationsUseCase(&failingOpsRepo{err: repoPageTokenErr()}).
		WithAdminChecker(admittedAdmin())

	_, _, err := uc.Execute(adminCtx("usr-admin"), "", 100, "not-a-cursor")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
	assert.Contains(t, grpcstatus.Convert(err).Message(), "invalid argument")
}

// page_size out of range is the caller's error whether or not a cursor was sent.
// Keying on the presence of a token turns the first page of an oversized request
// into an internal fault.
func TestListIamOperations_PageSizeRejected_StaysInvalidArgument(t *testing.T) {
	uc := NewListIamOperationsUseCase(&failingOpsRepo{err: repoPageSizeErr()}).
		WithAdminChecker(admittedAdmin())

	_, _, err := uc.Execute(adminCtx("usr-admin"), "", 5000, "")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"page_size out of range is the caller's error on the FIRST page too")
}
