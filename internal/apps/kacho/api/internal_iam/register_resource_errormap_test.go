// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// register_resource_errormap_test.go — handler-level error-mapping locks for the
// FGA-proxy RegisterResource / UnregisterResource RPCs (audit r6, leak/MEDIUM).
//
// The use-case emit() returns bare fmt.Errorf("begin tx: %w", err) /
// "upsert resource mirror" / "commit" wrapping raw pgx errors. Before the fix the
// handler returned them verbatim → gRPC codes.Unknown carrying the full pgx
// driver text (host/port/user/db). These tests lock the OBSERVABLE behaviour:
//   - un-sentineled error → codes.Internal with the fixed opaque "internal error"
//     (never codes.Unknown, never echoes the raw pgx text) — hardening-invariant #1;
//   - iamerr.ErrUnavailable sentinel → codes.Unavailable (retriable fail-closed);
//   - a validation status error (InvalidArgument) passes through unchanged.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// failBeginTxBeginner fails at connection acquisition (Begin), simulating a
// DB-down. Its error text carries pgx driver detail that must never reach a
// caller.
type failBeginTxBeginner struct{ err error }

func (b failBeginTxBeginner) Begin(context.Context) (service.Tx, error) { return nil, b.err }

// TestRegisterResourceUseCase_BeginFailure_MapsUnavailable — root-cause lock:
// a backend-down at tx.Begin must surface the typed iamerr.ErrUnavailable
// sentinel (not a bare fmt.Errorf), so the handler maps it to retriable
// codes.Unavailable with an opaque message (no pgx driver-text leak).
func TestRegisterResourceUseCase_BeginFailure_MapsUnavailable(t *testing.T) {
	uc := NewRegisterResourceUseCase(
		smEmitter{}, mirrorAdapter{},
		failBeginTxBeginner{err: errors.New("failed to connect to `host=iamdb port=5432 user=kacho_iam`: connection refused")},
	)

	err := uc.Register(context.Background(), &regReq{
		subject: "user:usr_x", relation: "owner", object: "vpc_network:enp_1",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, iamerr.ErrUnavailable, "backend-down must carry the retriable sentinel")

	mapped := shared.MapRepoErr(err)
	assert.Equal(t, codes.Unavailable, status.Code(mapped))
	msg := status.Convert(mapped).Message()
	assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
	assert.NotContains(t, msg, "host=", "must not leak DB host")
}

// fakeRegistrar implements the resourceRegistrar port. Both methods return the
// configured error verbatim (simulating the raw use-case emit() failure).
type fakeRegistrar struct {
	registerErr   error
	unregisterErr error
}

func (f *fakeRegistrar) Register(_ context.Context, _ registerInput) error {
	return f.registerErr
}

func (f *fakeRegistrar) Unregister(_ context.Context, _ unregisterInput) error {
	return f.unregisterErr
}

// rawPgxErr mimics a bare fmt.Errorf-wrapped pgx connection failure — exactly the
// shape emit() produces on a DB fault. Its text carries driver detail that must
// NEVER reach the caller.
var rawPgxErr = errors.New("begin tx: failed to connect to `host=iamdb port=5432 user=kacho_iam database=kacho_iam`: connection refused")

func registrarErrorCases() []struct {
	name    string
	err     error
	want    codes.Code
	wantMsg string // exact opaque message when non-empty (leak-lock)
} {
	return []struct {
		name    string
		err     error
		want    codes.Code
		wantMsg string
	}{
		// Leak-lock: un-sentineled pgx error → opaque Internal, never Unknown,
		// never echoes host/port/user/db.
		{"raw pgx — opaque Internal", rawPgxErr, codes.Internal, "internal error"},
		// Backend-down → retriable Unavailable via the typed sentinel.
		{"unavailable sentinel", iamerr.Wrapf(iamerr.ErrUnavailable, "fga proxy backend unavailable"), codes.Unavailable, ""},
		// Validation status error passes through unchanged.
		{"invalid-arg passthrough", shared.InvalidArg("labels", "too many labels (max 64)"), codes.InvalidArgument, ""},
	}
}

func newRegistrarHandler(reg resourceRegistrar) *Handler {
	// gate allows (domain "" passes ValidateProxyTuple for the owner-tuple below).
	return NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithResourceRegistrar(reg, &fakeGate{})
}

func TestInternalIAM_RegisterResource_ErrorMapping(t *testing.T) {
	for _, tc := range registrarErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegistrarHandler(&fakeRegistrar{registerErr: tc.err})

			_, err := h.RegisterResource(context.Background(), &iamv1.RegisterResourceRequest{
				SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
			})
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err))
			assert.NotEqual(t, codes.Unknown, status.Code(err),
				"raw use-case error must be mapped, never leak as codes.Unknown")
			msg := status.Convert(err).Message()
			assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
			assert.NotContains(t, msg, "host=", "must not leak DB host")
			assert.NotContains(t, msg, "kacho_iam", "must not leak DB user/name")
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, msg)
			}
		})
	}
}

func TestInternalIAM_UnregisterResource_ErrorMapping(t *testing.T) {
	for _, tc := range registrarErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegistrarHandler(&fakeRegistrar{unregisterErr: tc.err})

			_, err := h.UnregisterResource(context.Background(), &iamv1.UnregisterResourceRequest{
				SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
			})
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err))
			assert.NotEqual(t, codes.Unknown, status.Code(err),
				"raw use-case error must be mapped, never leak as codes.Unknown")
			msg := status.Convert(err).Message()
			assert.NotContains(t, msg, "connection refused", "must not leak pgx driver text")
			assert.NotContains(t, msg, "host=", "must not leak DB host")
			assert.NotContains(t, msg, "kacho_iam", "must not leak DB user/name")
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, msg)
			}
		})
	}
}

// TestValidateRelationString_RejectsSecondColon — audit r6 (readability/LOW):
// validateRelationString's contract (and objectType()'s first-colon split) assume
// exactly one ':'. A two-colon object silently passed validation, then objectType()
// split on the FIRST colon so the mirror/reconcile key diverged from the FGA tuple
// object string. Lock the documented single-colon grammar.
func TestValidateRelationString_RejectsSecondColon(t *testing.T) {
	twoColon := []string{
		"compute_instance:a:b",
		"vpc_network:enp_1:extra",
		"user:usr_x:tail",
	}
	for _, v := range twoColon {
		t.Run(v, func(t *testing.T) {
			err := validateRelationString("object", v)
			require.Error(t, err, "a two-colon object must be rejected")
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	// Single-colon (well-formed) still passes.
	for _, v := range []string{"vpc_network:enp_1", "user:usr_x", "compute_instance:cmp_z"} {
		t.Run("valid_"+v, func(t *testing.T) {
			require.NoError(t, validateRelationString("object", v))
		})
	}
}
