// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// force_logout_authz_test.go — defense-in-depth ReBAC + principal-sourced audit
// actor for InternalIAMService.ForceLogout (P1 security).
//
// Before this fix ForceLogout had NO admin gate (catalog `<exempt>`) and took
// the audit actor from the REQUEST body (req.actor_id) — spoofable audit trail.
// Now: the same system_admin@cluster ReBAC gate as the cluster-admin RPCs, and
// the recorded `revoked_by` is sourced from the VERIFIED principal in ctx, not
// from the client-supplied body field.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeForceLogoutChecker — authzguard.RelationChecker spy for ForceLogout.
type fakeForceLogoutChecker struct {
	allow    bool
	err      error
	called   bool
	subject  string
	relation string
	object   string
}

func (f *fakeForceLogoutChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.called = true
	f.subject = subject
	f.relation = relation
	f.object = object
	return f.allow, f.err
}

func forceLogoutHandlerWithGate(rec sessionRevoker, chk *fakeForceLogoutChecker) *Handler {
	return NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(chk)
}

func ctxAdmin(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

func TestForceLogout_DeniesWhenNoSystemAdmin(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{allow: false}
	h := forceLogoutHandlerWithGate(rec, chk)

	_, err := h.ForceLogout(ctxAdmin("usr0000000000000admin"), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"caller lacking system_admin must be denied")
	require.True(t, chk.called, "ReBAC Check must be consulted")
	require.Equal(t, "system_admin", chk.relation)
	require.Equal(t, "cluster:"+domain.ClusterSingletonID, chk.object)
	require.Zero(t, rec.allCnt, "no revocation may be written on deny (fail-closed before mutation)")
}

func TestForceLogout_DeniesWhenPrincipalEmpty(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{allow: true}
	h := forceLogoutHandlerWithGate(rec, chk)

	// No principal in ctx → anonymous → deny even though the checker would allow.
	_, err := h.ForceLogout(context.Background(), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Zero(t, rec.allCnt)
}

func TestForceLogout_DeniesWhenCheckerErrors(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{err: errors.New("fga backend down")}
	h := forceLogoutHandlerWithGate(rec, chk)

	_, err := h.ForceLogout(ctxAdmin("usr0000000000000admin"), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "checker error must fail closed")
	require.Zero(t, rec.allCnt)
}

func TestForceLogout_DeniesWhenCheckerNil(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).WithSessionRevoker(rec) // no checker
	_, err := h.ForceLogout(ctxAdmin("usr0000000000000admin"), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "nil checker must fail closed")
	require.Zero(t, rec.allCnt)
}

func TestForceLogout_AuditActorFromPrincipal_NotBody(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{allow: true}
	h := forceLogoutHandlerWithGate(rec, chk)

	const verifiedAdmin = "usr0000000000000admin"
	// Body actor_id omitted: the recorded actor MUST come from the verified
	// principal, not from any body field.
	op, err := h.ForceLogout(ctxAdmin(verifiedAdmin), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Equal(t, 1, rec.allCnt)
	assert.Equal(t, domain.UserID(verifiedAdmin), rec.allBy,
		"revoked_by must be the verified principal, not the spoofable req.actor_id")
	assert.Equal(t, domain.UserID("usr0000000000000victm"), rec.allUser)
}

func TestForceLogout_RejectsSpoofedBodyActor(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{allow: true}
	h := forceLogoutHandlerWithGate(rec, chk)

	const verifiedAdmin = "usr0000000000000admin"
	// A non-empty body actor_id that disagrees with the verified principal is a
	// spoof attempt → reject (never record a falsified audit actor).
	_, err := h.ForceLogout(ctxAdmin(verifiedAdmin), &iamv1.ForceLogoutRequest{
		UserId:  "usr0000000000000victm",
		ActorId: "usr00000000spoofedXX",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"mismatching client-supplied actor_id must be rejected")
	require.Zero(t, rec.allCnt, "no revocation may be written when the actor is spoofed")
}

func TestForceLogout_AcceptsMatchingBodyActor(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	chk := &fakeForceLogoutChecker{allow: true}
	h := forceLogoutHandlerWithGate(rec, chk)

	const verifiedAdmin = "usr0000000000000admin"
	// A body actor_id that matches the verified principal is harmless and
	// accepted; the recorded actor is still the verified principal.
	_, err := h.ForceLogout(ctxAdmin(verifiedAdmin), &iamv1.ForceLogoutRequest{
		UserId:  "usr0000000000000victm",
		ActorId: verifiedAdmin,
	})
	require.NoError(t, err)
	require.Equal(t, 1, rec.allCnt)
	assert.Equal(t, domain.UserID(verifiedAdmin), rec.allBy)
}
