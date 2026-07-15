// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// handler_test.go — unit-тесты InternalIAMService.Check.
//
// Check делегирует в AuthorizeService.CheckRelation. Тест мокает authorizer
// port-iface (без OpenFGA / OPA) и проверяет transport-маппинг:
//   - allowed=true                                  → CheckResponse{Allowed:true}
//   - allowed=false (deny path)                     → CheckResponse{Allowed:false, Reason}
//   - missing subject_id / relation / object        → InvalidArgument
//   - authorizer == nil (FGA stack not wired)       → Unavailable (fail-closed)
//   - CheckRelation -> "authz unavailable"          → Unavailable
//   - CheckRelation -> "Illegal argument ..."       → InvalidArgument
//   - CheckRelation -> generic error                → Internal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeAuthorizer — in-memory implementation of the authorizer port-iface.
type fakeAuthorizer struct {
	result  *service.CheckResult
	err     error
	gotReq  service.CheckRelationRequest
	callCnt int
}

func (f *fakeAuthorizer) CheckRelation(_ context.Context, req service.CheckRelationRequest) (*service.CheckResult, error) {
	f.callCnt++
	f.gotReq = req
	if f.err != nil {
		return f.result, f.err
	}
	return f.result, nil
}

func newCheckHandler(authz Authorizer) *Handler {
	// LookupSubject use-case is not exercised by Check tests — nil repo is
	// fine because Check never touches it.
	return NewHandler(NewLookupSubjectUseCase(nil), authz)
}

func TestInternalIAM_Check_Allowed(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{
		Allowed:              true,
		AuthorizationModelID: "model_v2",
		CheckedAt:            time.Now().UTC().Truncate(time.Second),
	}}
	h := newCheckHandler(authz)

	resp, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_alice",
		Relation:  "viewer",
		Object:    "vpc_network:enp_xxx",
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.Empty(t, resp.GetReason())
	// Delegation passes the FGA-native triple through unchanged.
	assert.Equal(t, "user:usr_alice", authz.gotReq.Subject)
	assert.Equal(t, "viewer", authz.gotReq.Relation)
	assert.Equal(t, "vpc_network:enp_xxx", authz.gotReq.Object)
	assert.Equal(t, 1, authz.callCnt)
}

func TestInternalIAM_Check_Denied(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{
		Allowed:     false,
		DenyReasons: []string{"no path"},
	}}
	h := newCheckHandler(authz)

	resp, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_bob",
		Relation:  "editor",
		Object:    "vpc_network:enp_yyy",
	})
	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
	assert.Equal(t, "no path", resp.GetReason())
}

func TestInternalIAM_Check_DeniedMultipleReasons(t *testing.T) {
	authz := &fakeAuthorizer{result: &service.CheckResult{
		Allowed:     false,
		DenyReasons: []string{"policy: mfa_fresh: acr=2 (need 3)", "policy: stale-session"},
	}}
	h := newCheckHandler(authz)

	resp, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_carol",
		Relation:  "admin",
		Object:    "compute_instance:cmp_zzz",
	})
	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
	assert.Equal(t, "policy: mfa_fresh: acr=2 (need 3); policy: stale-session", resp.GetReason())
}

func TestInternalIAM_Check_MissingFields(t *testing.T) {
	h := newCheckHandler(&fakeAuthorizer{result: &service.CheckResult{}})

	cases := []struct {
		name string
		req  *iamv1.CheckRequest
	}{
		{"no subject", &iamv1.CheckRequest{Relation: "viewer", Object: "vpc_network:e"}},
		{"no relation", &iamv1.CheckRequest{SubjectId: "user:u", Object: "vpc_network:e"}},
		{"no object", &iamv1.CheckRequest{SubjectId: "user:u", Relation: "viewer"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.Check(context.Background(), tc.req)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestInternalIAM_Check_NilAuthorizer_FailsClosed(t *testing.T) {
	// FGA stack not wired → Unavailable (interceptor treats this as deny,
	// NOT as Unimplemented / skip-the-gate).
	h := newCheckHandler(nil)

	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:u", Relation: "viewer", Object: "vpc_network:e",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestInternalIAM_Check_ErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    codes.Code
		wantMsg string // if non-empty, the EXACT opaque gRPC message (leak-lock)
	}{
		// Backend-unavailable is classified by the typed iamerr.ErrUnavailable
		// sentinel (robust to error-text rewording), not an error-string prefix.
		{"unavailable sentinel", iamerr.Wrapf(iamerr.ErrUnavailable, "authz unavailable: openfga check: status 503"), codes.Unavailable, ""},
		{"unavailable sentinel other text", iamerr.Wrapf(iamerr.ErrUnavailable, "policy unavailable: opa down"), codes.Unavailable, ""},
		{"illegal argument", errors.New("Illegal argument relation: required"), codes.InvalidArgument, ""},
		// Leak-lock (audit r3): the Internal default must be the OPAQUE fixed text,
		// never err.Error() — an un-sentineled pgx/DB error carries driver text
		// (host/port/user/db). Asserting the message (not just the code) is what
		// regression-locks the fix: a refactor reintroducing err.Error() fails here.
		{"generic — opaque, must not echo raw err", errors.New("unexpected boom"), codes.Internal, "internal error"},
		// Regression-lock: a raw "authz unavailable" TEXT with no sentinel must NOT
		// be classified as Unavailable anymore (the brittle string branch is gone),
		// and its message must be the opaque fixed text (no raw-text echo).
		{"raw unavailable text without sentinel", errors.New("authz unavailable: raw"), codes.Internal, "internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCheckHandler(&fakeAuthorizer{
				result: &service.CheckResult{},
				err:    tc.err,
			})
			_, err := h.Check(context.Background(), &iamv1.CheckRequest{
				SubjectId: "user:u", Relation: "viewer", Object: "vpc_network:e",
			})
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err))
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, status.Convert(err).Message(),
					"INTERNAL must be opaque fixed text — never echo raw err (pgx/DB leak)")
			}
		})
	}
}

// ── WriteCreatorTuple in-handler gate (C2) ──
//
// WriteCreatorTuple is NOT in the gateway-only set of the internal caller policy
// (its caller is a vpc/compute/nlb MODULE SA, not the api-gateway). Its authZ is
// enforced HERE by the same cert-bound RelationWriteGate as RegisterResource
// (fga_writer@iam_fgaproxy:system), gated FIRST before any field is read.

// fakeGate implements the relationWriteGate port (RelationWriteGate).
type fakeGate struct {
	domain  string
	err     error
	callCnt int
}

func (g *fakeGate) Authorize(_ context.Context) (string, error) { g.callCnt++; return g.domain, g.err }

// fakeRelationWriter implements the relationWriter port.
type fakeRelationWriter struct {
	gotTuples []clients.RelationTuple
	err       error
}

func (w *fakeRelationWriter) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	w.gotTuples = append(w.gotTuples, tuples...)
	return w.err
}

func newWriteCreatorHandler(w relationWriter, gate relationWriteGate) *Handler {
	return NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithRelationWriter(w).
		WithResourceRegistrar(nil, gate)
}

// TestInternalIAM_WriteCreatorTuple_GateDenied — C2: a denying gate → PermissionDenied
// and the tuple is NOT written (gate runs before the writer).
func TestInternalIAM_WriteCreatorTuple_GateDenied(t *testing.T) {
	gate := &fakeGate{err: status.Error(codes.PermissionDenied, "permission denied")}
	writer := &fakeRelationWriter{}
	h := newWriteCreatorHandler(writer, gate)

	_, err := h.WriteCreatorTuple(context.Background(), &iamv1.WriteCreatorTupleRequest{
		SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, 1, gate.callCnt)
	assert.Empty(t, writer.gotTuples, "tuple must NOT be written when the gate denies")
}

// TestInternalIAM_WriteCreatorTuple_GateAllowed — an allowing gate → the tuple is written.
func TestInternalIAM_WriteCreatorTuple_GateAllowed(t *testing.T) {
	gate := &fakeGate{}
	writer := &fakeRelationWriter{}
	h := newWriteCreatorHandler(writer, gate)

	_, err := h.WriteCreatorTuple(context.Background(), &iamv1.WriteCreatorTupleRequest{
		SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
	})
	require.NoError(t, err)
	require.Len(t, writer.gotTuples, 1)
	assert.Equal(t, "user:usr_x", writer.gotTuples[0].User)
}

// TestInternalIAM_WriteCreatorTuple_PrivilegeTupleDenied — least-privilege guard:
// модульная SA (домен vpc) не может выписать creator-tuple с privilege-relation
// или на cluster/foreign-объект, даже когда WHO-gate пропускает. Tuple не пишется.
func TestInternalIAM_WriteCreatorTuple_PrivilegeTupleDenied(t *testing.T) {
	cases := []struct{ name, relation, object string }{
		{"cluster system_admin", "system_admin", "cluster:cluster_kacho_root"},
		{"editor on own object", "editor", "vpc_network:net1"},
		{"foreign iam object", "owner", "iam_account:acc1"},
		{"cluster object with hierarchy relation", "project", "cluster:cluster_kacho_root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := &fakeGate{domain: "vpc"}
			writer := &fakeRelationWriter{}
			h := newWriteCreatorHandler(writer, gate)

			_, err := h.WriteCreatorTuple(context.Background(), &iamv1.WriteCreatorTupleRequest{
				SubjectId: "service_account:sva1", Relation: tc.relation, Object: tc.object,
			})
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Empty(t, writer.gotTuples, "privilege/foreign tuple must NOT be written")
		})
	}
}

// TestInternalIAM_WriteCreatorTuple_WriterError_OpaqueMessage — leak-lock (audit r11):
// the raw OpenFGA transport error must never reach the gRPC status message — it
// carries the cluster-internal FGA endpoint host:port + store id. The message must
// be the fixed opaque text, not err.Error() (%v). Mirrors internal_authorize's
// ReadTuples/GetFGAStoreInfo scrub. security.md hardening-invariant #1 (:9091 not exempt).
func TestInternalIAM_WriteCreatorTuple_WriterError_OpaqueMessage(t *testing.T) {
	rawErr := `openfga write: Post "http://fga-host.internal:8080/stores/01STOREID/write": dial tcp 10.1.2.3:8080: connect: connection refused`
	gate := &fakeGate{}
	writer := &fakeRelationWriter{err: errors.New(rawErr)}
	h := newWriteCreatorHandler(writer, gate)

	_, err := h.WriteCreatorTuple(context.Background(), &iamv1.WriteCreatorTupleRequest{
		SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	msg := status.Convert(err).Message()
	assert.Equal(t, "authz backend unavailable", msg,
		"UNAVAILABLE must be opaque fixed text — never echo raw FGA transport err (endpoint/store-id leak)")
	assert.NotContains(t, msg, "fga-host.internal", "FGA endpoint host:port leaked into status message")
	assert.NotContains(t, msg, "01STOREID", "FGA store id leaked into status message")
}

// TestInternalIAM_WriteCreatorTuple_NilGateFailsClosed — an unwired gate → deny
// (never silently allow an unconfigured gate).
func TestInternalIAM_WriteCreatorTuple_NilGateFailsClosed(t *testing.T) {
	writer := &fakeRelationWriter{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).WithRelationWriter(writer)

	_, err := h.WriteCreatorTuple(context.Background(), &iamv1.WriteCreatorTupleRequest{
		SubjectId: "user:usr_x", Relation: "owner", Object: "vpc_network:enp_1",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, writer.gotTuples)
}
