// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_operations_classification_test.go — the per-resource ListOperations feed
// must report WHAT FAILED, not WHAT THE CALLER SENT.
//
// The operations store answers a caller-format problem as a gRPC InvalidArgument
// naming the field; anything else it returns is a store failure. Deciding
// between the two by "was a page_token supplied" mislabels both directions: a
// database outage becomes a malformed cursor, and an out-of-range page_size on
// the first page becomes an internal fault.
package shared_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	coreerrors "github.com/PRO-Robotech/kacho/pkg/errors"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// storePageTokenErr / storePageSizeErr — byte-for-byte what pkg/operations
// returns for those two caller-format problems.
func storePageTokenErr() error {
	return coreerrors.InvalidArgument().
		AddFieldViolation("page_token", "page_token is invalid or malformed").
		Err()
}

func storePageSizeErr() error {
	_, err := corevalidate.PageSize("page_size", 5000)
	return err
}

func TestListOperations_StoreFailureWithPageToken_IsNotACursorError(t *testing.T) {
	repo := &recordingOpsRepo{listErr: errors.New("repo.List: dial tcp: connection refused")}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "Q3JlYXRlZEF0fGlvcDE=")

	require.Error(t, err)
	assert.Equal(t, codes.Internal, grpcstatus.Code(err),
		"an unreachable store is a store failure; blaming the cursor sends the caller to fix nothing")
	assert.Equal(t, "list operations failed", grpcstatus.Convert(err).Message())
}

func TestListOperations_MalformedPageToken_InvalidArgument(t *testing.T) {
	repo := &recordingOpsRepo{listErr: storePageTokenErr()}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "not-a-cursor")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
}

func TestListOperations_PageSizeRejected_StaysInvalidArgument(t *testing.T) {
	repo := &recordingOpsRepo{listErr: storePageSizeErr()}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 5000, "")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"page_size out of range is the caller's error on the FIRST page too")
}
