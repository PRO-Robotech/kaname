// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler_w1_6_test.go — SAKey.Issue takes created_by_user_id from the
// authenticated principal — not from the request body. Body field accepted
// only if it matches the principal (strict reject per OQ-3).
//
// Tests are handler-level — they exercise the guard that runs before the
// usecase Execute. The handler tests don't need a real usecase for the
// deny-path branches; they're fed an unconfigured Handler{}.
package sa_keys

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

func userCtxSAK(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

func TestSAKey_Issue_SpoofRejected(t *testing.T) {
	// HANDLER-level enforcement: body field set to non-principal value is
	// rejected before any service-layer execution. Unconfigured Handler
	// short-circuits at the guard.
	h := &Handler{}
	ctx := userCtxSAK("usr_actual")

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva_xxx",
		CreatedByUserId:  "usr_someone_else",
		TtlSeconds:       0,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("spoofed created_by_user_id must InvalidArgument, got %v", err)
	}
}

func TestSAKey_Issue_AnonymousDenied(t *testing.T) {
	h := &Handler{}
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva_xxx",
		CreatedByUserId:  "",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("anonymous Issue must 403, got %v", err)
	}
}
