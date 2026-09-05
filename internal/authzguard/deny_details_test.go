// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// deny_details_test.go — the machine-readable signal on a refusal, asserted the
// way a CLIENT reads it: the details array of the returned status.
//
// Why this exists. Some RPCs are authorized over the DATA by iam itself: their
// catalog row carries no required_relation, an empty scope extractor and the
// scope-filtered marker, so the edge runs no per-RPC check and passes the call
// through. The edge is the layer that used to attach the detail naming the
// action, and it still does for its neighbours — so on this band the refusal
// arrived as a bare `{"code":7,"message":"permission denied","details":[]}`.
//
// A bare refusal is not just terse: it is INDISTINGUISHABLE from a catalog miss
// (a misrouted path the edge cannot map to any permission at all), which also
// fail-closes to 7. A client cannot tell "you may not read this" from "this
// method is not in the catalog" — and neither can a test. These assertions pin
// both halves: a scope refusal names its action; a catalog miss still does not.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
)

func mustRegistry(t *testing.T) *seed.PermissionRegistry {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)
	return reg
}

// denyThrough runs the interceptor around a handler that refuses exactly the way
// the iam use-cases refuse — authzguard.PermissionDenied(), the single
// construction every denial site in the service goes through.
func denyThrough(t *testing.T, catalog authzguard.DenyActionLookup, fullMethod string) *status.Status {
	t.Helper()
	return throughInterceptor(t, catalog, fullMethod, authzguard.PermissionDenied())
}

func throughInterceptor(t *testing.T, catalog authzguard.DenyActionLookup, fullMethod string, handlerErr error) *status.Status {
	t.Helper()
	ic := authzguard.DenyDetailUnary(catalog)
	_, err := ic(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: fullMethod},
		func(context.Context, any) (any, error) { return nil, handlerErr })
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	require.True(t, ok, "the interceptor must return a gRPC status")
	return st
}

// errorInfo extracts the google.rpc.ErrorInfo a client keys on, or nil.
func errorInfo(st *status.Status) *errdetails.ErrorInfo {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info
		}
	}
	return nil
}

// ── The class, not one case ─────────────────────────────────────────────────

// Every method on the data-filtered band must carry the machine-readable
// reason. Enumerated FROM THE CATALOG rather than hard-coded, so a method added
// to the band later is covered by this lock the day it is added.
func TestDenyDetail_EveryScopeFilteredMethodNamesItsAction(t *testing.T) {
	reg := mustRegistry(t)

	var band []seed.PermissionEntry
	for _, e := range reg.All() {
		if e.ScopeFiltered && strings.HasPrefix(e.FQN, "kacho.cloud.iam.") {
			band = append(band, e)
		}
	}
	require.NotEmpty(t, band,
		"the catalog must expose the scope-filtered marker — without it iam cannot "+
			"even enumerate the band it is responsible for authorizing")

	for _, e := range band {
		t.Run(e.FQN, func(t *testing.T) {
			st := denyThrough(t, reg, "/"+e.FQN)
			require.Equal(t, codes.PermissionDenied, st.Code())

			info := errorInfo(st)
			require.NotNil(t, info,
				"a refusal decided over the data must still carry the machine-readable "+
					"reason the convention requires; the client cannot parse the prose")
			assert.Equal(t, "AUTHZ_DENIED", info.GetReason())
			assert.Equal(t, "kacho.cloud.iam.v1", info.GetDomain(),
				"the same domain the edge stamps — a client keying on it must not have "+
					"to know which layer refused")
			assert.Equal(t, e.Permission, info.GetMetadata()["action"],
				"the action names the permission of the method that refused")
			assert.Equal(t, e.FQN, info.GetMetadata()["fqn"])
		})
	}
}

// ── The discriminator the band lost ─────────────────────────────────────────

// The point of naming the action: a refusal by scope and a catalog miss are
// both code 7, and before this they were byte-identical on the wire. They must
// not be.
func TestDenyDetail_ScopeRefusalIsDistinguishableFromCatalogMiss(t *testing.T) {
	reg := mustRegistry(t)

	scoped := denyThrough(t, reg,
		"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject")
	missed := denyThrough(t, reg,
		"/kacho.cloud.iam.v1.AccessBindingService/ThisMethodIsNotInTheCatalog")

	require.Equal(t, codes.PermissionDenied, scoped.Code())
	require.Equal(t, codes.PermissionDenied, missed.Code())
	require.Equal(t, scoped.Message(), missed.Message(),
		"the prose is deliberately identical — which is exactly why the detail has to differ")

	scopedInfo := errorInfo(scoped)
	require.NotNil(t, scopedInfo)
	require.Equal(t, "iam.access_bindings_by_subjects.listBySubject",
		scopedInfo.GetMetadata()["action"])

	require.Nil(t, errorInfo(missed),
		"a method the catalog does not know has no action to name; claiming one would "+
			"turn the discriminator back into noise")
}

// An exempt row has no permission to name. Stamping the literal placeholder as
// if it were an action would be a false claim, so nothing is attached.
func TestDenyDetail_ExemptMethodNamesNoAction(t *testing.T) {
	reg := mustRegistry(t)
	st := denyThrough(t, reg, "/kacho.cloud.iam.v1.InternalIAMService/ForceLogout")
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Nil(t, errorInfo(st))
}

// ── Not clobbering what is already there ────────────────────────────────────

// The step-up refusal already carries a PreconditionFailure telling the client
// to re-authenticate. Enriching must ADD the reason, never replace the signal
// that tells the caller what to do about it.
func TestDenyDetail_PreservesExistingDetails(t *testing.T) {
	reg := mustRegistry(t)

	base := status.New(codes.PermissionDenied, "permission denied")
	withPF, err := base.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{
			Type:    "authz.step_up",
			Subject: "acr_values:2",
		}},
	})
	require.NoError(t, err)

	st := throughInterceptor(t, reg,
		"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject", withPF.Err())

	var sawPF bool
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.PreconditionFailure); ok {
			sawPF = true
		}
	}
	assert.True(t, sawPF, "the step-up signal must survive")
	require.NotNil(t, errorInfo(st), "and the machine-readable reason must be added")
}

// A refusal that already names its reason is left exactly as it is — enrichment
// must be idempotent, never append a second, possibly disagreeing, reason.
func TestDenyDetail_AlreadyCarriesReason_LeftAlone(t *testing.T) {
	reg := mustRegistry(t)

	base := status.New(codes.PermissionDenied, "permission denied")
	withInfo, err := base.WithDetails(&errdetails.ErrorInfo{
		Reason: "AUTHZ_DENIED", Domain: "kacho.cloud.iam.v1",
		Metadata: map[string]string{"action": "already.set"},
	})
	require.NoError(t, err)

	st := throughInterceptor(t, reg,
		"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject", withInfo.Err())

	var infos int
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.ErrorInfo); ok {
			infos++
		}
	}
	require.Equal(t, 1, infos, "exactly one reason, and it is the one already set")
	assert.Equal(t, "already.set", errorInfo(st).GetMetadata()["action"])
}

// ── Everything else is untouched ────────────────────────────────────────────

func TestDenyDetail_NonRefusalsPassThroughUnchanged(t *testing.T) {
	reg := mustRegistry(t)

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"not_found", status.Error(codes.NotFound, "AccessBinding acb-1 not found")},
		{"invalid_argument", status.Error(codes.InvalidArgument, "Illegal argument subject_type")},
		{"unauthenticated", status.Error(codes.Unauthenticated, "unauthenticated")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := throughInterceptor(t, reg,
				"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject", tc.err)
			require.Nil(t, errorInfo(st),
				"only a refusal carries an authz reason — anything else would mislabel the failure")
			assert.Equal(t, status.Convert(tc.err).Message(), st.Message())
		})
	}
}

func TestDenyDetail_SuccessIsNotDisturbed(t *testing.T) {
	reg := mustRegistry(t)
	ic := authzguard.DenyDetailUnary(reg)
	resp, err := ic(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/ListBySubject"},
		func(context.Context, any) (any, error) { return "ok", nil })
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

// Without a catalog the interceptor must be a pass-through, not a source of
// empty actions — an empty action is the very thing that means "catalog miss".
func TestDenyDetail_NilCatalog_IsPassThrough(t *testing.T) {
	st := denyThrough(t, nil, "/kacho.cloud.iam.v1.AccessBindingService/ListBySubject")
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Nil(t, errorInfo(st))
}
