// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// maperr_test.go — unit coverage for the ConditionsService handler mapErr,
// specifically the hardened Internal fallback: any UNMAPPED (non-sentinel,
// non-status, non-"Illegal argument") error must collapse to a FIXED opaque
// codes.Internal "internal error" and never echo the raw error text — an
// un-sentineled pgx/DB error would otherwise leak driver/connection detail
// (host/port/user/db) to the tenant (api-conventions.md / SEC audit r2).
package conditions

import (
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// TestMapErr_UnmappedError_OpaqueInternal — the Internal branch: an unmapped
// error maps to codes.Internal with the fixed "internal error" message and does
// not leak the raw (potentially pgx) text.
func TestMapErr_UnmappedError_OpaqueInternal(t *testing.T) {
	const secret = `pq: SSL connection host=10.1.2.3 port=5432 user=iam dbname=kacho_iam`
	err := mapErr(stderrors.New(secret))

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "internal error", st.Message())
	assert.NotContains(t, st.Message(), secret, "raw error text must not leak to the client")
}

// TestMapErr_NilPassesThrough — nil in, nil out (happy path).
func TestMapErr_NilPassesThrough(t *testing.T) {
	assert.NoError(t, mapErr(nil))
}

// TestMapErr_SentinelBranches — the sentinel families map to their gRPC codes
// (guards against a future refactor accidentally routing them through the
// Internal fallback).
func TestMapErr_SentinelBranches(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not-found", iamerr.Wrapf(iamerr.ErrNotFound, "Condition cnd_x not found"), codes.NotFound},
		{"already-exists", iamerr.Wrapf(iamerr.ErrAlreadyExists, "already"), codes.AlreadyExists},
		{"failed-precondition", iamerr.Wrapf(iamerr.ErrFailedPrecondition, "in use"), codes.FailedPrecondition},
		{"invalid-arg", iamerr.Wrapf(iamerr.ErrInvalidArg, "bad"), codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, status.Code(mapErr(c.err)))
		})
	}
}

// TestMapErr_ExistingStatusPassesThrough — an error that already carries a gRPC
// status (e.g. the in-service authz guard's PermissionDenied) is returned
// unchanged rather than re-wrapped as Internal.
func TestMapErr_ExistingStatusPassesThrough(t *testing.T) {
	orig := status.Error(codes.PermissionDenied, "denied")
	got := mapErr(orig)
	assert.Equal(t, codes.PermissionDenied, status.Code(got))
	assert.Equal(t, "denied", status.Convert(got).Message())
}
