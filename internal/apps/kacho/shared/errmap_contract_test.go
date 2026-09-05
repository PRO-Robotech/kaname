// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared_test

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	coreerrors "github.com/PRO-Robotech/kacho/pkg/errors"
)

// TestMapRepoErrFailureBandsCharacterization records the code AND the exact wire
// text MapRepoErr produces on every failure band, for a bare sentinel and for a
// sentinel carrying the caller's contract text.
//
// The message tone is part of the Kachō contract ("<Resource> %s not found" and
// friends), and hide-existence needs a deny to read byte-for-byte like a real
// miss, so drift here is an existence oracle rather than a cosmetic change. This
// test exists so that reordering the mapper has to prove it moved nothing.
func TestMapRepoErrFailureBandsCharacterization(t *testing.T) {
	cases := []struct {
		name     string
		in       error
		wantCode codes.Code
		wantMsg  string
	}{
		{"not_found/bare", iamerr.ErrNotFound, codes.NotFound, "not found"},
		{"not_found/wrapped", iamerr.Wrapf(iamerr.ErrNotFound, "Account acc-1 not found"), codes.NotFound, "Account acc-1 not found"},

		{"already_exists/bare", iamerr.ErrAlreadyExists, codes.AlreadyExists, "already exists"},
		{"already_exists/wrapped", iamerr.Wrapf(iamerr.ErrAlreadyExists, "Account acc-1 already exists"), codes.AlreadyExists, "Account acc-1 already exists"},

		{"permission_denied/bare", iamerr.ErrPermissionDenied, codes.PermissionDenied, "permission denied"},
		{"permission_denied/wrapped", iamerr.Wrapf(iamerr.ErrPermissionDenied, "caller is not the designated approver"), codes.PermissionDenied, "caller is not the designated approver"},

		{"unauthenticated/bare", iamerr.ErrUnauthenticated, codes.Unauthenticated, "unauthenticated"},
		{"unauthenticated/wrapped", iamerr.Wrapf(iamerr.ErrUnauthenticated, "step-up required"), codes.Unauthenticated, "step-up required"},

		{"failed_precondition/bare", iamerr.ErrFailedPrecondition, codes.FailedPrecondition, "failed precondition"},
		{"failed_precondition/wrapped", iamerr.Wrapf(iamerr.ErrFailedPrecondition, "account is not empty"), codes.FailedPrecondition, "account is not empty"},

		{"invalid_argument/bare", iamerr.ErrInvalidArg, codes.InvalidArgument, "invalid argument"},
		{"invalid_argument/wrapped", iamerr.Wrapf(iamerr.ErrInvalidArg, "invalid account id 'zzz'"), codes.InvalidArgument, "invalid account id 'zzz'"},

		{"aborted/bare", iamerr.ErrAborted, codes.Aborted, "aborted"},
		{"aborted/wrapped", iamerr.Wrapf(iamerr.ErrAborted, "serialization failure"), codes.Aborted, "serialization failure"},

		// Текст недоступности ФИКСИРОВАН, как у INTERNAL, и по той же причине:
		// цепочка ведёт к драйверу и может нести адрес узла, имя базы и учётную
		// запись. Прежде здесь стоял `StripSentinel`, и строка `"authz
		// unavailable"` в этой же таблице показывала механизм: текст обёртки
		// вызывающего доезжал до провода дословно. Утечки не случалось лишь
		// потому, что все производители признака в сервисе опаковы сами, — то
		// есть «by construction» в godoc означало «пока никто не обернул».
		{"unavailable/bare", iamerr.ErrUnavailable, codes.Unavailable, "service unavailable"},
		{"unavailable/wrapped", iamerr.Wrapf(iamerr.ErrUnavailable, "authz unavailable"), codes.Unavailable, "service unavailable"},

		{"internal/bare", iamerr.ErrInternal, codes.Internal, "internal error"},
		{"internal/wrapped", iamerr.Wrapf(iamerr.ErrInternal, "pgx: dial tcp 10.0.0.7:5432"), codes.Internal, "internal error"},

		{"passthrough/status", status.Error(codes.ResourceExhausted, "too many keys"), codes.ResourceExhausted, "too many keys"},

		{"invalid_argument/illegal_argument_prefix", errors.New("Illegal argument object: required"), codes.InvalidArgument, "Illegal argument object: required"},

		{"unclassified/raw", errors.New("dial tcp 10.0.0.7:5432: connect: connection refused"), codes.Internal, "internal error"},
		{"unclassified/unknown_coded_status", status.Error(codes.Unknown, "boom"), codes.Internal, "internal error"},

		// ErrSelfRevoke / ErrLastAdmin are NOT in this switch — the cluster
		// revoke-admin use-case classifies them itself. Recorded as-is so the
		// reorder is measured against real behaviour, not against intent.
		{"unclassified/self_revoke", iamerr.Wrapf(iamerr.ErrSelfRevoke, "cannot revoke own cluster admin grant"), codes.Internal, "internal error"},
		{"unclassified/last_admin", iamerr.Wrapf(iamerr.ErrLastAdmin, "cannot revoke last active cluster admin"), codes.Internal, "internal error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shared.MapRepoErr(tc.in)
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("MapRepoErr returned a non-status error: %v", got)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v", st.Code(), tc.wantCode)
			}
			if st.Message() != tc.wantMsg {
				t.Errorf("message = %q, want %q", st.Message(), tc.wantMsg)
			}
		})
	}

	t.Run("nil", func(t *testing.T) {
		if got := shared.MapRepoErr(nil); got != nil {
			t.Errorf("MapRepoErr(nil) = %v, want nil", got)
		}
	})
}

// TestMapRepoErrPreservesDetailsThroughSentinelWrap locks the property itself:
// a rich validator error wrapped onto a service sentinel with %w must reach the
// client with its google.rpc.BadRequest field violation intact.
//
// pkg/validate puts the offending field name ONLY in the details — the message
// stays the generic "invalid argument" — so a mapper that recognises the sentinel
// and rebuilds a fresh status.Error(code, text) silently drops the one
// machine-readable part of the answer. That has to be a property of the mapper,
// not something every future author is expected to remember.
func TestMapRepoErrPreservesDetailsThroughSentinelWrap(t *testing.T) {
	rich := coreerrors.InvalidArgument().
		AddFieldViolation("email", "email must be a valid address").
		Err()
	wrapped := fmt.Errorf("%w: %w", iamerr.ErrInvalidArg, rich)

	got := shared.MapRepoErr(wrapped)

	st, ok := status.FromError(got)
	if !ok {
		t.Fatalf("MapRepoErr returned a non-status error: %v", got)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", st.Code())
	}

	var fields []string
	for _, d := range st.Details() {
		br, ok := d.(*errdetails.BadRequest)
		if !ok {
			continue
		}
		for _, v := range br.GetFieldViolations() {
			fields = append(fields, v.GetField())
		}
	}
	if len(fields) != 1 || fields[0] != "email" {
		t.Fatalf("field violations = %v, want exactly [email]", fields)
	}
}
