// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// set_enabled_negative_test.go — sync-phase contract of the Disable / Enable
// actions (hard-rule #12: every RPC carries ≥1 negative case).
//
// These guards short-circuit BEFORE the Operation is minted, so they are
// asserted on the sync return of Execute — no Postgres. The observable outcome
// (the issuance gate stops answering yes) is pinned in the audit-package
// integration test; what is pinned here is the shape of the refusals, which is
// where a contract quietly drifts: a malformed id answered NotFound, or an
// unauthenticated caller reaching the writer at all.
//
// Both directions get the same cases on purpose. An asymmetry between Disable
// and Enable is not a saving — it is the door an operator finds locked at the
// worst moment.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// setEnabledExec — the pair under test, addressed uniformly so every case runs
// against both directions without being written twice. The two are DISTINCT
// types (a swap at the composition root must not compile); this map exists to
// share the cases, not to make them interchangeable.
func setEnabledExec(t *testing.T, repo Repo) map[string]func(context.Context, domain.ServiceAccountID) (*operations.Operation, error) {
	t.Helper()
	return map[string]func(context.Context, domain.ServiceAccountID) (*operations.Operation, error){
		"disable": NewDisableServiceAccountUseCase(repo, newLcsOps()).Execute,
		"enable":  NewEnableServiceAccountUseCase(repo, newLcsOps()).Execute,
	}
}

// Anonymous → PermissionDenied, before any repo touch. Disabling a machine
// identity nobody can be named for is not an operation anyone should be able to
// order, and neither is handing one back its ability to authenticate.
func TestSetEnabledServiceAccount_Sync_Anonymous(t *testing.T) {
	for name, exec := range setEnabledExec(t, newLcsRepo(nil)) {
		t.Run(name, func(t *testing.T) {
			op, err := exec(context.Background(), negSaID)
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status; got %v", err)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// Malformed id → InvalidArgument, and it is terminal. Answering NotFound here
// would be this service claiming a resource is absent when the string it was
// handed could never name one.
func TestSetEnabledServiceAccount_Sync_MalformedID(t *testing.T) {
	for name, exec := range setEnabledExec(t, newLcsRepo(nil)) {
		t.Run(name, func(t *testing.T) {
			op, err := exec(negAuthedCtx(), "not-a-valid-id")
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status; got %v", err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})
	}
}

// Well-formed but absent → NotFound with the contract tone. This is the own-read
// lane: the id names something this service owns, and it does not have it.
func TestSetEnabledServiceAccount_Sync_NotFound(t *testing.T) {
	repo := &negDelRepo{getErr: iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", negSaID)}
	for name, exec := range setEnabledExec(t, repo) {
		t.Run(name, func(t *testing.T) {
			op, err := exec(negAuthedCtx(), negSaID)
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status; got %v", err)
			assert.Equal(t, codes.NotFound, st.Code())
			assert.Contains(t, st.Message(), "ServiceAccount "+negSaID+" not found")
		})
	}
}
