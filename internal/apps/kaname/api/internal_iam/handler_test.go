// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// handler_test.go — unit-тесты InternalIAMService.Check.
//
// Check делегирует в AuthorizeService.CheckRelation. Тест ставит дублёра на порт
// решателя и проверяет transport-маппинг:
//   - allowed=true                                  → CheckResponse{Allowed:true}
//   - allowed=false (deny path)                     → CheckResponse{Allowed:false, Reason}
//   - missing subject_id / relation / object        → InvalidArgument
//   - authorizer == nil (решатель не провязан)      → Unavailable (fail-closed)
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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
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
		Allowed:   true,
		CheckedAt: time.Now().UTC().Truncate(time.Second),
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
		{"unavailable sentinel", iamerr.Wrapf(iamerr.ErrUnavailable, "authz unavailable: read relation_fact: conn refused"), codes.Unavailable, ""},
		{"unavailable sentinel other text", iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable"), codes.Unavailable, ""},
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

// fakeGate — заглушка порта relationWriteGate (RelationWriteGate). Осталась
// после снятия WriteCreatorTuple (#788): её читают пробы RegisterResource.
type fakeGate struct {
	domain  string
	err     error
	callCnt int
}

func (g *fakeGate) Authorize(_ context.Context) (string, error) { g.callCnt++; return g.domain, g.err }
