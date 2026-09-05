// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_sa_lane_no_silent_drop_test.go — a request field the service does not
// honour must not be accepted in silence (api-conventions.md, «Принято-и-
// проигнорировано — ЗАПРЕЩЕНО»: the three lawful outcomes are implement, reject
// explicitly, or take off the contract; accepting and discarding is not one).
//
// The anti-spoofing rule on `created_by_user_id` used to sit entirely inside the
// `user`-caller branch. On the service-account lane the field was therefore read
// by nobody: the value went in, `created_by` was resolved from the target SA's
// account owner, and the caller got 200 believing its value had been applied.
// That is worse than a refusal — a refusal is visible at once, while a dropped
// field shows up only in someone else's audit trail, months later, as a
// `created_by` that nobody set.
//
// The paired positive is here on purpose: a rule that only ever refuses is
// indistinguishable from a lane that is dead. The seed path — an SA caller
// issuing a key with NO `created_by_user_id` — must keep working, and the
// matching-value case must keep working too, or this guard would break the
// production-mode seed it shares a file with.
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// TestHandlerIssue_SAPrincipal_SpoofedCreatedBy_IsRejectedNotDropped — the
// negative half. An SA caller naming a created_by the service will not record
// must be told so, synchronously, with the field named.
func TestHandlerIssue_SAPrincipal_SpoofedCreatedBy_IsRejectedNotDropped(t *testing.T) {
	repo := &stubSAClientRepo{ownerUserID: domain.UserID("usr00000000000000042")}
	ops := &stubOpsRepo{}
	h := NewHandler(newSeedIssueUC(repo, ops), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000009"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
		// Neither the caller's own id nor the owner the service will record.
		CreatedByUserId: "usr00000000000000099",
	})
	require.Error(t, err,
		"a created_by the service will not honour must be refused, not accepted and discarded")
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"an unusable request field is INVALID_ARGUMENT")
	require.Contains(t, grpcstatus.Convert(err).Message(), "created_by_user_id",
		"the refusal must name the field, or the caller cannot tell what to change")
	// `inserted` is a value, not a pointer — it is never nil, so nil-ness would be a
	// vacuous assertion that passes whatever happened. Its zero id is the observable
	// that actually distinguishes "nothing was written" from "something was".
	require.Empty(t, string(repo.inserted.CreatedByUserID),
		"a refused Issue must not have written anything")
}

// TestHandlerIssue_SAPrincipal_OmittedCreatedBy_StillSeeds — positive control #1.
// The production-mode seed sends no created_by at all; that path must stay open,
// otherwise the guard above would be indistinguishable from a broken lane.
func TestHandlerIssue_SAPrincipal_OmittedCreatedBy_StillSeeds(t *testing.T) {
	repo := &stubSAClientRepo{ownerUserID: domain.UserID("usr00000000000000042")}
	ops := &stubOpsRepo{}
	h := NewHandler(newSeedIssueUC(repo, ops), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva00000000000000009"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
	})
	require.NoError(t, err, "the seed path sends no created_by and must keep working")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000042", string(repo.inserted.CreatedByUserID),
		"created_by is still resolved from the target SA's account owner")
}

// TestHandlerIssue_UserPrincipal_OwnCreatedBy_StillAccepted — positive control #2,
// on the OTHER lane. The refusal added above is deliberately narrow: it applies to
// service-account callers, where the field has no reader. A user caller naming its
// own principal is still lawful, and this pins that the new branch did not widen
// into the lane it was never about.
//
// Why an SA caller naming exactly the owner the service WILL record is refused too:
// it would have to be plumbed (the owner is resolved inside the use-case, from the
// repository — the handler does not know it), and it buys the caller nothing it
// cannot get by omitting the field. One rule per lane, both stated, neither guessed.
func TestHandlerIssue_UserPrincipal_OwnCreatedBy_StillAccepted(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(newSeedIssueUC(repo, ops), nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
		CreatedByUserId:  "usr00000000000000007",
	})
	require.NoError(t, err,
		"a user caller naming its own principal is not spoofing and must stay accepted")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, "usr00000000000000007", string(repo.inserted.CreatedByUserID))
}
