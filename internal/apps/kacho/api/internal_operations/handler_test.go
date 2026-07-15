// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_operations

// handler_test.go — unit tests for InternalOperationsService.ListIamOperations.
//
// Cluster-wide Internal admin feed: returns ALL IAM operations of the cluster
// (optional account_id filter), gated admin-tier. The backend iam internal
// listener is NOT exempt (security.md "AuthN+AuthZ ВЕЗДЕ"): the handler runs a
// per-user ReBAC Check (system_admin @ cluster:cluster_kacho_root) so a caller
// that bypasses the api-gateway and dials :9091 directly is rejected without
// system_admin. nil checker / backend error / explicit deny → PermissionDenied
// (fail-closed; mirrors cluster.requireClusterSystemAdmin).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ── ReBAC Check stub ────────────────────────────────────────────────────────
type clusterCheckStub struct {
	allow map[string]bool
	err   error
}

func (s *clusterCheckStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allow[subject+"|"+relation+"|"+object], nil
}

// ── ops repo capturing the ListFilter ───────────────────────────────────────
type internalOpsRepo struct {
	ops       []operations.Operation
	next      string
	gotFilter operations.ListFilter
	listCalls int
}

func (r *internalOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (r *internalOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *internalOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *internalOpsRepo) List(_ context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	r.listCalls++
	r.gotFilter = f
	return r.ops, r.next, nil
}
func (r *internalOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (r *internalOpsRepo) MarkError(context.Context, string, *gstatuspb.Status) error {
	return nil
}
func (r *internalOpsRepo) Cancel(context.Context, string) error { return nil }

func adminCtx(uid string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: uid})
}

func newHandler(ops operations.Repo, checker *clusterCheckStub) *Handler {
	uc := NewListIamOperationsUseCase(ops)
	if checker != nil {
		uc = uc.WithAdminChecker(checker)
	}
	return NewHandler(uc)
}

func clusterObj() string { return "cluster:" + domain.ClusterSingletonID }

func TestListIamOperations_Admin_ClusterWide(t *testing.T) {
	ops := &internalOpsRepo{ops: []operations.Operation{
		{ID: "iop00000000000000001", CreatedAt: time.Unix(1, 0)},
		{ID: "iop00000000000000002", CreatedAt: time.Unix(2, 0)},
	}, next: "tok"}
	checker := &clusterCheckStub{allow: map[string]bool{
		"user:usr-admin|system_admin|" + clusterObj(): true,
	}}
	h := newHandler(ops, checker)

	resp, err := h.ListIamOperations(adminCtx("usr-admin"),
		&iamv1.ListIamOperationsRequest{PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, resp.GetOperations(), 2)
	assert.Equal(t, "tok", resp.GetNextPageToken())
	// No account_id filter → cluster-wide (empty AccountID).
	assert.Empty(t, ops.gotFilter.AccountID, "no account filter → cluster-wide list")
}

func TestListIamOperations_Admin_OptionalAccountFilter(t *testing.T) {
	ops := &internalOpsRepo{ops: []operations.Operation{{ID: "iop00000000000000001"}}}
	checker := &clusterCheckStub{allow: map[string]bool{
		"user:usr-admin|system_admin|" + clusterObj(): true,
	}}
	h := newHandler(ops, checker)

	_, err := h.ListIamOperations(adminCtx("usr-admin"),
		&iamv1.ListIamOperationsRequest{PageSize: 100, AccountId: "acc0000000000000abcd"})
	require.NoError(t, err)
	assert.Equal(t, "acc0000000000000abcd", ops.gotFilter.AccountID,
		"optional account_id filter must reach the repo")
}

func TestListIamOperations_NonAdmin_PermissionDenied(t *testing.T) {
	// A user the api-gateway lets through but who lacks system_admin@cluster.
	ops := &internalOpsRepo{}
	checker := &clusterCheckStub{allow: map[string]bool{}} // holds nothing
	h := newHandler(ops, checker)

	_, err := h.ListIamOperations(adminCtx("usr-nonadmin"),
		&iamv1.ListIamOperationsRequest{PageSize: 100})
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("non-admin must be PermissionDenied, got %s", got)
	}
	if ops.listCalls != 0 {
		t.Fatalf("repo must NOT be queried when authz fails (defense-in-depth)")
	}
}

func TestListIamOperations_NilChecker_FailClosed(t *testing.T) {
	// Backend listener authz must NEVER silently allow if the checker is unwired.
	ops := &internalOpsRepo{}
	h := newHandler(ops, nil)

	_, err := h.ListIamOperations(adminCtx("usr-admin"),
		&iamv1.ListIamOperationsRequest{PageSize: 100})
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("nil checker must fail closed → PermissionDenied, got %s", got)
	}
}

func TestListIamOperations_CheckerError_FailClosed(t *testing.T) {
	ops := &internalOpsRepo{}
	checker := &clusterCheckStub{err: errors.New("fga down")}
	h := newHandler(ops, checker)

	_, err := h.ListIamOperations(adminCtx("usr-admin"),
		&iamv1.ListIamOperationsRequest{PageSize: 100})
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("checker backend error must fail closed → PermissionDenied, got %s", got)
	}
}

func TestListIamOperations_Anonymous_PermissionDenied(t *testing.T) {
	ops := &internalOpsRepo{}
	checker := &clusterCheckStub{allow: map[string]bool{
		"user:|system_admin|" + clusterObj(): true, // would match empty principal
	}}
	h := newHandler(ops, checker)

	_, err := h.ListIamOperations(context.Background(), // no principal → anonymous
		&iamv1.ListIamOperationsRequest{PageSize: 100})
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("anonymous must be PermissionDenied, got %s", got)
	}
}
