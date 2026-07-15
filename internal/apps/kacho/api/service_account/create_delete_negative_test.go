// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// create_delete_negative_test.go — sync-phase negative/boundary coverage for
// CreateServiceAccountUseCase and DeleteServiceAccountUseCase (project hard-rule
// #12: every RPC carries ≥1 negative case). These guards short-circuit BEFORE
// the Operation/async worker, so they are asserted purely on the sync return of
// Execute — no Postgres, reusing the in-package fakes (lcsRepo/lcsOps from
// update_labelclear_test.go) plus a tiny not-found reader for the Delete
// not-found branch.
//
// This is coverage of already-correct guards (test-only; prod code untouched),
// pinning the anti-anonymous backdoor guard, account_id format validation,
// domain self-validation, and the malformed-id / not-found error mapping so a
// future regression that weakens any of them is caught here.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
)

const (
	negActor  = "usr0000000000000neg4"
	negAcctID = "acc0000000000000neg4"
	negSaID   = "sva0000000000000neg4"
)

func negAuthedCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: negActor})
}

// ── Create: sync-phase guards ───────────────────────────────────────────────
//
// Every case returns an error BEFORE opsRepo.Create / the async worker, so the
// (never-touched) repo is the happy-path fake.
func TestCreateServiceAccount_Sync_Negative(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		sa   domain.ServiceAccount
		code codes.Code
	}{
		{
			// Anti-anonymous: anonymous SA.Create is a persistent backdoor.
			name: "anonymous_permission_denied",
			ctx:  context.Background(), // no principal ⇒ fallback = anonymous
			sa:   domain.ServiceAccount{AccountID: negAcctID, Name: "neg-sa"},
			code: codes.PermissionDenied,
		},
		{
			name: "empty_account_id_invalid_argument",
			ctx:  negAuthedCtx(),
			sa:   domain.ServiceAccount{Name: "neg-sa"},
			code: codes.InvalidArgument,
		},
		{
			name: "malformed_account_id_invalid_argument",
			ctx:  negAuthedCtx(),
			sa:   domain.ServiceAccount{AccountID: "not-an-acc-id", Name: "neg-sa"},
			code: codes.InvalidArgument,
		},
		{
			// sa.Validate() failure (illegal name) → InvalidArgument.
			name: "invalid_name_invalid_argument",
			ctx:  negAuthedCtx(),
			sa:   domain.ServiceAccount{AccountID: negAcctID, Name: "Bad_Name"},
			code: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewCreateServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
			op, err := uc.Execute(tc.ctx, tc.sa)
			require.Error(t, err)
			assert.Nil(t, op, "no Operation may be minted on a sync-phase rejection")
			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status; got %v", err)
			assert.Equal(t, tc.code, st.Code())
		})
	}
}

// ── Delete: sync-phase guards ───────────────────────────────────────────────

// Anonymous DeleteServiceAccount → PermissionDenied (before any repo touch).
func TestDeleteServiceAccount_Sync_Anonymous(t *testing.T) {
	uc := NewDeleteServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
	op, err := uc.Execute(context.Background(), negSaID)
	require.Error(t, err)
	assert.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status; got %v", err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// Malformed service-account id → InvalidArgument (first statement after authn).
func TestDeleteServiceAccount_Sync_MalformedID(t *testing.T) {
	uc := NewDeleteServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
	op, err := uc.Execute(negAuthedCtx(), "not-a-valid-id")
	require.Error(t, err)
	assert.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status; got %v", err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// Well-formed-but-absent id → NotFound (repo.Get ErrNotFound → MapRepoErr).
func TestDeleteServiceAccount_Sync_NotFound(t *testing.T) {
	repo := &negDelRepo{getErr: iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", negSaID)}
	uc := NewDeleteServiceAccountUseCase(repo, newLcsOps())
	op, err := uc.Execute(negAuthedCtx(), negSaID)
	require.Error(t, err)
	assert.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status; got %v", err)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ── minimal not-found repo (Delete reads the SA before minting the op) ──────
//
// Only Reader().ServiceAccounts().Get + Rollback are exercised on the not-found
// path; the nil-embedded kachorepo.Reader promotes the rest and fail-loud
// (nil-panic) if an unexpected method is ever called on this path.

type negDelRepo struct{ getErr error }

func (r *negDelRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &negDelReader{getErr: r.getErr}, nil
}
func (r *negDelRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (r *negDelRepo) Close()                                           {}

type negDelReader struct {
	kachorepo.Reader // nil-embed: only ServiceAccounts + Rollback are used here
	getErr           error
}

func (r *negDelReader) ServiceAccounts() reposa.ReaderIface { return &negDelSaRdr{err: r.getErr} }
func (r *negDelReader) Rollback(context.Context) error      { return nil }

type negDelSaRdr struct{ err error }

func (r *negDelSaRdr) Get(context.Context, domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{}, r.err
}
func (r *negDelSaRdr) List(context.Context, reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	return nil, "", nil
}
