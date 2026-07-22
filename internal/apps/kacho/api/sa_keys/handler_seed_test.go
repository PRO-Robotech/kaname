// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler_seed_test.go — #60 (SA-key analog): an acr-exempt system_admin
// ServiceAccount caller (the #58 bootstrap-admin SA) seeds an SA-key for another
// ServiceAccount during the non-interactive production-mode e2e seed. The SA
// principal id (`sva…`) is NOT a users(id) row, so it cannot be the created_by —
// forcing created_by=principal fails the service_account_oauth_clients created_by
// FK (23503) as an opaque async code-9. The use-case records created_by = the
// target SA's account OWNER (a valid users row, resolved deterministically —
// never a request-body value), which is what unblocks minting SA tokens for the
// production-mode seed. A `user` caller keeps the anti-spoofing rule
// (created_by == principal, or empty).
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// newSeedIssueUC builds an IssueSAKeyUseCase over the unit stubs.
func newSeedIssueUC(repo *stubSAClientRepo, ops *stubOpsRepo) *IssueSAKeyUseCase {
	return NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)
}

func TestHandlerIssue_SAPrincipal_CreatedByIsAccountOwner(t *testing.T) {
	repo := &stubSAClientRepo{ownerUserID: domain.UserID("usr00000000000000042")}
	ops := &stubOpsRepo{}
	h := NewHandler(newSeedIssueUC(repo, ops), nil, nil)

	// Caller is the bootstrap-admin SA (service_account principal).
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000009"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
	})
	require.NoError(t, err, "an SA caller must be able to seed an SA key (no created_by FK code-9)")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr, "the async op must not error (created_by is a valid user row)")
	require.Equal(t, "usr00000000000000042", string(repo.inserted.CreatedByUserID),
		"SA caller records created_by = the SA's account owner, never the SA principal id")
}

func TestHandlerIssue_UserPrincipal_CreatedByIsPrincipal(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(newSeedIssueUC(repo, ops), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
	})
	require.NoError(t, err)
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000007", string(repo.inserted.CreatedByUserID),
		"a user caller records created_by = its own principal id (anti-spoofing)")
}

func TestHandlerIssue_UserPrincipal_SpoofedCreatedBy_Rejected(t *testing.T) {
	h := NewHandler(newSeedIssueUC(&stubSAClientRepo{}, &stubOpsRepo{}), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	// A user caller trying to attribute the key to ANOTHER user → rejected sync.
	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
		CreatedByUserId:  "usr00000000000000099",
	})
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"a user caller must not spoof created_by to another principal")
}
