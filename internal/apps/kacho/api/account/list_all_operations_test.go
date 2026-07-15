// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// list_all_operations_test.go — unit tests for AccountService.ListAllOperations.
//
// Account-scoped public feed: returns ALL IAM operations whose denormalized
// operations.account_id == the given account (corelib ListFilter.AccountID),
// gated "self (account owner) OR account-admin (FGA admin@account)" — mirrors
// access_binding.requireAccountAdmin. Cursor pagination passes through; a
// cross-account caller without authority → PermissionDenied; malformed id →
// InvalidArgument (first statement); well-formed-but-missing → empty list.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// ── FGA Check stub (admin@account) — embeds clients.RelationStore so only Check
// is overridden (the use-case only calls Check; WriteTuples/DeleteTuples are
// never invoked on the read path). ───────────────────────────────────────────
type acctAdminCheckStub struct {
	clients.RelationStore
	allow map[string]bool // key = subject|relation|object
}

func (s *acctAdminCheckStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	return s.allow[subject+"|"+relation+"|"+object], nil
}

// ── ops repo capturing the ListFilter ───────────────────────────────────────
type acctAllOpsRepo struct {
	ops       []operations.Operation
	next      string
	gotFilter operations.ListFilter
}

func (r *acctAllOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (r *acctAllOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (r *acctAllOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (r *acctAllOpsRepo) List(_ context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	r.gotFilter = f
	return r.ops, r.next, nil
}
func (r *acctAllOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (r *acctAllOpsRepo) MarkError(context.Context, string, *gstatuspb.Status) error {
	return nil
}
func (r *acctAllOpsRepo) Cancel(context.Context, string) error { return nil }

func newListAllUC(repo Repo, fga *acctAdminCheckStub, ops operations.Repo) *ListAllOperationsUseCase {
	uc := NewListAllOperationsUseCase(repo, ops)
	if fga != nil {
		uc = uc.WithRelationStore(fga, nil)
	}
	return uc
}

func TestListAllOperations_Owner_FiltersByAccountID(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000ownr", "usr-owner")
	ops := &acctAllOpsRepo{ops: []operations.Operation{
		{ID: "iop00000000000000001", CreatedAt: time.Unix(1, 0)},
		{ID: "iop00000000000000002", CreatedAt: time.Unix(2, 0)},
	}, next: "tok"}

	uc := newListAllUC(repo, nil, ops)
	got, next, err := uc.Execute(ctxUser("usr-owner"), "acc0000000000000ownr", 100, "")
	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Equal(t, "tok", next)
	assert.Equal(t, "acc0000000000000ownr", ops.gotFilter.AccountID,
		"must filter by account_id column, not resource_id")
	assert.Empty(t, ops.gotFilter.ResourceID, "account-scoped feed never filters by resource_id")
	assert.EqualValues(t, 100, ops.gotFilter.PageSize)
}

func TestListAllOperations_AccountAdmin_OK(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000acct", "usr-owner")
	fga := &acctAdminCheckStub{allow: map[string]bool{
		"user:usr-admin|admin|account:acc0000000000000acct": true,
	}}
	ops := &acctAllOpsRepo{ops: []operations.Operation{{ID: "iop00000000000000001"}}}

	uc := newListAllUC(repo, fga, ops)
	got, _, err := uc.Execute(ctxUser("usr-admin"), "acc0000000000000acct", 50, "")
	require.NoError(t, err)
	assert.Len(t, got, 1, "delegated account-admin may list account operations")
}

func TestListAllOperations_CrossAccount_PermissionDenied(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000acct", "usr-owner")
	fga := &acctAdminCheckStub{allow: map[string]bool{}} // stranger holds nothing
	ops := &acctAllOpsRepo{}

	uc := newListAllUC(repo, fga, ops)
	_, _, err := uc.Execute(ctxUser("usr-stranger"), "acc0000000000000acct", 50, "")
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("cross-account caller must be PermissionDenied, got %s", got)
	}
}

func TestListAllOperations_MalformedID_InvalidArgument(t *testing.T) {
	uc := newListAllUC(newAcctListFakeRepo(), nil, &acctAllOpsRepo{})
	_, _, err := uc.Execute(ctxUser("usr-x"), "not-an-account", 50, "")
	if got := grpcstatus.Code(err); got != codes.InvalidArgument {
		t.Fatalf("malformed account id must be InvalidArgument, got %s", got)
	}
}

func TestListAllOperations_WellFormedMissing_EmptyOrDenied(t *testing.T) {
	// Missing account → requireAccountAdmin returns PermissionDenied (existence
	// hiding, parity with requireAccountAdmin / ListByAccount). The point: not a
	// 5xx and not NotFound-leak.
	repo := newAcctListFakeRepo()
	uc := newListAllUC(repo, &acctAdminCheckStub{allow: map[string]bool{}}, &acctAllOpsRepo{})
	_, _, err := uc.Execute(ctxUser("usr-x"), "acc0000000000000miss", 50, "")
	if got := grpcstatus.Code(err); got != codes.PermissionDenied {
		t.Fatalf("missing account → PermissionDenied (existence hiding), got %s", got)
	}
}

func TestListAllOperations_Pagination_PassThrough(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc0000000000000ownr", "usr-owner")
	ops := &acctAllOpsRepo{ops: []operations.Operation{{ID: "iop00000000000000003"}}, next: "next-tok"}

	uc := newListAllUC(repo, nil, ops)
	_, next, err := uc.Execute(ctxUser("usr-owner"), "acc0000000000000ownr", 100, "page-tok")
	require.NoError(t, err)
	assert.Equal(t, "next-tok", next)
	assert.Equal(t, "page-tok", ops.gotFilter.PageToken, "page_token must pass through to the repo")
}
