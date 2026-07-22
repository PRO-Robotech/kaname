// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler_seed_test.go — #60: an acr-exempt system_admin ServiceAccount caller
// (the #58 bootstrap-admin SA) seeds a per-subject user token. The SA principal
// id (`sva…`) is not a users(id) row, so it CANNOT be the created_by — the
// handler records created_by = the TARGET user (self), satisfying the
// user_oauth_clients created_by FK. This is what unblocks the non-interactive
// production-mode seed of per-subject user tokens (issue #60). A `user` caller
// keeps the anti-spoofing rule (created_by == principal).
package user_tokens

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

func TestHandlerIssue_SAPrincipal_CreatedByIsTargetUser(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	issue := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)
	h := NewHandler(issue, nil, nil)

	// Caller is the bootstrap-admin SA (service_account principal).
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000009"})

	_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{UserId: "usr00000000000000001"})
	require.NoError(t, err, "an SA caller must be able to seed a user token (no FK code-9)")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr, "the async op must not error (created_by is a valid user)")
	require.Equal(t, "usr00000000000000001", string(repo.inserted.CreatedByUserID),
		"SA caller records created_by = the target user (self), never the SA id")
	require.Equal(t, "usr00000000000000001", string(repo.inserted.UserID))
}

func TestHandlerIssue_UserPrincipal_CreatedByIsPrincipal(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	issue := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)
	h := NewHandler(issue, nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{UserId: "usr00000000000000001"})
	require.NoError(t, err)
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000007", string(repo.inserted.CreatedByUserID),
		"a user caller records created_by = its own principal id (anti-spoofing)")
}

func TestHandlerIssue_UserPrincipal_SpoofedCreatedBy_Rejected(t *testing.T) {
	issue := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
	h := NewHandler(issue, nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	// A user caller trying to attribute the token to ANOTHER user → rejected sync.
	_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{
		UserId:          "usr00000000000000001",
		CreatedByUserId: "usr00000000000000042",
	})
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"a user caller must not spoof created_by to another principal")
}
