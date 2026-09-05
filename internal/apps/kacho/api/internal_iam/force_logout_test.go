// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// force_logout_test.go — unit-тесты InternalIAMService.ForceLogout. До этого
// фикса метод был advertised (caller_policy + permission_catalog), но
// Unimplemented. ForceLogout — admin force-logout, который ДОЛЖЕН записывать
// session-revocation для целевого subject (тот же writer, что и user-logout
// Revoke). Ретайр GetJWKSStatus — jwks_status_retired_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// adminCtx returns a ctx carrying an authenticated admin principal — the
// ForceLogout gate requires a non-empty principal holding system_admin@cluster
// (the allowing fakeForceLogoutChecker covers the ReBAC side).
const testAdminID = "usr0000000000000admin"

func adminCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: testAdminID})
}

var errForceLogoutDown = errors.New("user_token_revocations: backend down")

// fakeForceLogoutRecorder — in-memory sessionRevoker port. Records the
// user-level RevokeAllUserTokensTx call so a test can prove ForceLogout writes a
// user-level cutoff (the gate the refresh-hook actually enforces), not just a
// synthetic per-jti row that can never match. The port is the
// tx-scoped *Tx variant (cutoff + audit row atomic); allEventType captures the
// audit taxonomy value passed (expected iam.session.force_logout).
type fakeForceLogoutRecorder struct {
	// User-level revoke-all state.
	allCnt       int
	allUser      domain.UserID
	allBy        domain.UserID
	allBefore    time.Time
	allReason    string
	allEventType string
	allErr       error
}

func (f *fakeForceLogoutRecorder) RevokeAllUserTokensTx(_ context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error {
	f.allCnt++
	f.allUser = userID
	f.allBefore = revokeBefore
	f.allReason = reason
	f.allBy = revokedBy
	f.allEventType = eventType
	return f.allErr
}

// recordingForceLogoutOps — operations repo stub recording the transitions
// ForceLogout drives. Every method the handler touches is stubbed explicitly
// (embedding the interface and overriding only some leaves the rest as a
// nil-panic waiting to happen).
type recordingForceLogoutOps struct {
	operations.Repo

	calls     []string
	created   operations.Operation
	doneMeta  *anypb.Any
	doneResp  *anypb.Any
	errStatus *statuspb.Status
}

func (f *recordingForceLogoutOps) Create(_ context.Context, op operations.Operation) error {
	f.calls = append(f.calls, "create")
	f.created = op
	return nil
}

func (f *recordingForceLogoutOps) MarkDone(context.Context, string, *anypb.Any) error {
	f.calls = append(f.calls, "markdone")
	return nil
}

func (f *recordingForceLogoutOps) MarkDoneWithMetadata(_ context.Context, _ string, meta, resp *anypb.Any) error {
	f.calls = append(f.calls, "markdone-with-metadata")
	f.doneMeta, f.doneResp = meta, resp
	return nil
}

func (f *recordingForceLogoutOps) MarkError(_ context.Context, _ string, st *statuspb.Status) error {
	f.calls = append(f.calls, "markerror")
	f.errStatus = st
	return nil
}

func forceLogoutHandler(rec sessionRevoker) *Handler {
	h, _ := forceLogoutHandlerWithOps(rec)
	return h
}

// forceLogoutHandlerWithOps is forceLogoutHandler plus a handle on the recorded
// operation transitions.
func forceLogoutHandlerWithOps(rec sessionRevoker) (*Handler, *recordingForceLogoutOps) {
	// An allowing ReBAC checker — these tests exercise the revocation behaviour,
	// not the authZ gate (gate-specific cases live in force_logout_authz_test.go).
	ops := &recordingForceLogoutOps{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}).
		WithOperations(ops)
	return h, ops
}

func TestForceLogout_RecordsUserLevelRevocationForSubject(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := forceLogoutHandler(rec)

	before := time.Now().UTC()
	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{
		UserId: "usr_victim",
		Reason: "admin-force-logout",
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.True(t, op.GetDone())

	// ForceLogout MUST record a USER-LEVEL revoke-all cutoff — that is the gate
	// the refresh-hook enforces against the token's real session auth_time. A
	// per-jti synthetic row would be inert (real jti never matches synthetic).
	require.Equal(t, 1, rec.allCnt, "ForceLogout must write a user-level revoke-all marker, not just a synthetic jti")
	assert.Equal(t, domain.UserID("usr_victim"), rec.allUser)
	// revoked_by is sourced from the VERIFIED principal (anti-spoof), not a body field.
	assert.Equal(t, domain.UserID(testAdminID), rec.allBy, "actor recorded as revoked_by for audit")
	assert.NotEmpty(t, rec.allReason)
	assert.False(t, rec.allBefore.Before(before), "revoke_before must be at-or-after request time")
}

func TestForceLogout_DoesNotWriteSyntheticJTI(t *testing.T) {
	// Regression guard: the old implementation wrote a synthetic
	// `force-logout:<user>:<unixnano>` jti to session_revocations that the real
	// token jti could never match (inert + silent false-success). ForceLogout
	// must take the user-level revoke-all path only. It must also
	// pass the iam.session.force_logout audit taxonomy value to the tx-scoped
	// writer (so the durable compliance row carries the right event_type).
	rec := &fakeForceLogoutRecorder{}
	h := forceLogoutHandler(rec)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{
		UserId: "usr_victim",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, rec.allCnt, "ForceLogout must use the user-level revoke-all path")
	assert.Equal(t, "iam.session.force_logout", rec.allEventType,
		"ForceLogout must emit the iam.session.force_logout audit event_type")
}

func TestForceLogout_RevokerError_MapsCode(t *testing.T) {
	rec := &fakeForceLogoutRecorder{allErr: errForceLogoutDown}
	h := forceLogoutHandler(rec)
	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{
		UserId: "usr_victim",
	})
	require.Error(t, err, "a user-level revoke-all write error must surface, never silent success")
}

func TestForceLogout_MissingUserID_InvalidArgument(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := forceLogoutHandler(rec)
	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{Reason: "x"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Zero(t, rec.allCnt)
}

func TestForceLogout_NotWired_Unavailable(t *testing.T) {
	// Gate passes (admin ctx + allowing checker); the not-wired session revoker
	// then yields Unavailable.
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}) // no session revoker wired
	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_x"})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// ── Operation persistence (unit level) ───────────────────────────────────────

// ForceLogout returns an Operation, so the row that id names must exist. It
// used to be built in memory, stamped done=true and returned — the admin got an
// id that answered NotFound forever.
func TestForceLogout_PersistsOperationAndCompletesIt(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h, ops := forceLogoutHandlerWithOps(rec)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.NotEmpty(t, op.GetId())

	require.Contains(t, ops.calls, "create", "the operation row must be persisted")
	require.Contains(t, ops.calls, "markdone-with-metadata",
		"the terminal transition must write the declared metadata and response")
	require.Equal(t, op.GetId(), ops.created.ID,
		"the id handed to the admin must be the id of the persisted row")

	meta := &iamv1.ForceLogoutMetadata{}
	require.NotNil(t, ops.doneMeta)
	require.NoError(t, ops.doneMeta.UnmarshalTo(meta))
	assert.Equal(t, "usr_victim", meta.GetUserId())

	resp := &iamv1.ForceLogoutResult{}
	require.NotNil(t, ops.doneResp, "ForceLogout declares response: ForceLogoutResult")
	require.NoError(t, ops.doneResp.UnmarshalTo(resp))
	assert.Equal(t, int32(1), resp.GetRevokedCount(),
		"one revocation record was committed — not the inert 0-with-success")
}

// A failing cutoff write must mark the already-persisted operation terminally
// with the error a poller will read.
func TestForceLogout_WriteFailure_MarksOperationError(t *testing.T) {
	rec := &fakeForceLogoutRecorder{allErr: errForceLogoutDown}
	h, ops := forceLogoutHandlerWithOps(rec)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err)
	require.Contains(t, ops.calls, "create")
	require.Contains(t, ops.calls, "markerror",
		"a failed cutoff must leave a terminal error the poller can read")
	require.NotContains(t, ops.calls, "markdone-with-metadata")
	require.NotNil(t, ops.errStatus)
	assert.NotZero(t, ops.errStatus.GetCode())
}

// Without a place to persist the operation the RPC must refuse rather than hand
// back an id that names no row.
func TestForceLogout_NoOperationRepo_Unavailable(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true})

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Equal(t, codes.Unavailable, status.Code(err))
	assert.Zero(t, rec.allCnt, "the refusal must precede the mutation")
}
