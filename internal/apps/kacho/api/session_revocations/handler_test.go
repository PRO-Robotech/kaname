// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// handler_test.go — unit-тесты InternalSessionRevocationsService handler.
//
// Закрывает P0: до этого фикса логаут вызывал Revoke, а сервис не был
// реализован → codes.Unimplemented → revocation INERT (refresh-hook IsRevoked
// gate'у нечего было читать). Тесты доказывают:
//   - Revoke записывает revocation через writer-порт и возвращает Operation;
//   - Revoke без user_id → InvalidArgument (sync-валидация до записи);
//   - writer недоступен → Unavailable (fail-closed для мутации);
//   - IsRevoked делегирует в reader и маппит результат;
//   - ListByUser делегирует в reader и маппит rows.
//
// Замыкание контура revoke→IsRevoked проверяется отдельно integration-тестом
// против настоящей session_revocations таблицы (refresh-hook читает ту же
// таблицу через IsRevoked).

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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// fakeRevoker — in-memory writer port. Records both the per-jti RevokeTx and the
// user-level RevokeAllUserTokensTx calls so a test can prove a bulk
// revoke_all_user_tokens request writes a user-level cutoff (not a no-op row).
// The port is the tx-scoped *Tx variants (revocation + audit row committed
// atomically); allEventType captures the audit taxonomy value passed.
type fakeRevoker struct {
	got     domain.SessionRevocation
	gotBy   domain.UserID
	err     error
	callCnt int

	allCnt       int
	allUser      domain.UserID
	allBy        domain.UserID
	allBefore    time.Time
	allReason    string
	allEventType string
	allErr       error
}

func (f *fakeRevoker) RevokeTx(_ context.Context, rev domain.SessionRevocation, by domain.UserID) error {
	f.callCnt++
	f.got = rev
	f.gotBy = by
	return f.err
}

func (f *fakeRevoker) RevokeAllUserTokensTx(_ context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error {
	f.allCnt++
	f.allUser = userID
	f.allBefore = revokeBefore
	f.allReason = reason
	f.allBy = revokedBy
	f.allEventType = eventType
	return f.allErr
}

// fakeReader — in-memory reader port.
type fakeReader struct {
	revoked   bool
	revAt     time.Time
	reason    string
	isRevErr  error
	listRows  []domain.SessionRevocation
	listErr   error
	gotJTI    string
	gotUserID string
}

func (f *fakeReader) IsRevoked(_ context.Context, jti string) (bool, error) {
	f.gotJTI = jti
	return f.revoked, f.isRevErr
}

func (f *fakeReader) GetByJTI(_ context.Context, jti string) (domain.SessionRevocation, error) {
	f.gotJTI = jti
	if f.isRevErr != nil {
		return domain.SessionRevocation{}, f.isRevErr
	}
	return domain.SessionRevocation{TokenJTI: jti, RevokedAt: f.revAt, Reason: f.reason}, nil
}

func (f *fakeReader) ListByUser(_ context.Context, userID string, _ int32, _ string) ([]domain.SessionRevocation, string, error) {
	f.gotUserID = userID
	return f.listRows, "", f.listErr
}

// recordingOpsRepo — operations repo stub that records the call sequence, so a
// test can pin that the operation row is created BEFORE the mutation and
// completed after it. Every method the use-case touches is stubbed explicitly
// (embedding the interface and overriding only some leaves the rest as a
// nil-panic waiting to happen).
type recordingOpsRepo struct {
	operations.Repo

	calls     []string
	created   operations.Operation
	doneMeta  *anypb.Any
	doneResp  *anypb.Any
	errStatus *statuspb.Status
	createErr error
}

func (f *recordingOpsRepo) Create(_ context.Context, op operations.Operation) error {
	f.calls = append(f.calls, "create")
	f.created = op
	return f.createErr
}

func (f *recordingOpsRepo) MarkDone(context.Context, string, *anypb.Any) error {
	f.calls = append(f.calls, "markdone")
	return nil
}

func (f *recordingOpsRepo) MarkDoneWithMetadata(_ context.Context, _ string, meta, resp *anypb.Any) error {
	f.calls = append(f.calls, "markdone-with-metadata")
	f.doneMeta, f.doneResp = meta, resp
	return nil
}

func (f *recordingOpsRepo) MarkError(_ context.Context, _ string, st *statuspb.Status) error {
	f.calls = append(f.calls, "markerror")
	f.errStatus = st
	return nil
}

// newHandler builds the production handler around a RevokeUseCase over the
// fake writer + a fake reader. A nil writer exercises the fail-closed path.
func newHandler(w sessionRevocationWriter, r reader) *Handler {
	h, _ := newHandlerWithOps(w, r)
	return h
}

// newHandlerWithOps is newHandler plus a handle on the recorded operation calls.
func newHandlerWithOps(w sessionRevocationWriter, r reader) (*Handler, *recordingOpsRepo) {
	ops := &recordingOpsRepo{}
	var uc revoker
	if w != nil {
		uc = NewRevokeUseCase(w, ops)
	}
	return NewHandler(uc, r), ops
}

func TestRevoke_RecordsAndReturnsOperation(t *testing.T) {
	w := &fakeRevoker{}
	h := newHandler(w, &fakeReader{})

	op, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti:     "jti-123",
		UserId:       "usr_alice",
		Reason:       "user-logout",
		TtlExpiresAt: timestamppb.New(time.Now().Add(24 * time.Hour)),
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.True(t, op.GetDone(), "Revoke Operation is synchronous (done=true)")
	assert.Equal(t, 1, w.callCnt, "writer must be called exactly once")
	assert.Equal(t, "jti-123", w.got.TokenJTI)
	assert.Equal(t, domain.UserID("usr_alice"), w.got.UserID)
	assert.Equal(t, "user-logout", w.got.Reason)
}

func TestRevoke_MissingUserID_InvalidArgument(t *testing.T) {
	w := &fakeRevoker{}
	h := newHandler(w, &fakeReader{})

	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-123",
		Reason:   "user-logout",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Zero(t, w.callCnt, "no write must happen on a rejected request")
}

func TestRevoke_MissingJTIAndNotAll_InvalidArgument(t *testing.T) {
	// Without a jti AND without revoke_all_user_tokens there is nothing to revoke.
	w := &fakeRevoker{}
	h := newHandler(w, &fakeReader{})

	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		UserId: "usr_alice",
		Reason: "user-logout",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Zero(t, w.callCnt)
	assert.Zero(t, w.allCnt)
}

func TestRevoke_RevokeAllUserTokens_WritesUserLevelMarker(t *testing.T) {
	// revoke_all_user_tokens=true (no jti) MUST record a user-level revoke-all
	// cutoff — the refresh-hook gate that actually denies the user's live tokens.
	// The previous code passed the flag to a use-case that never read it and
	// wrote one empty-jti row (revokedCount=0) → silent no-op.
	w := &fakeRevoker{}
	h := newHandler(w, &fakeReader{})

	before := time.Now().UTC()
	op, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		UserId:              "usr_alice",
		Reason:              "admin-revoke",
		RevokeAllUserTokens: true,
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.True(t, op.GetDone())

	require.Equal(t, 1, w.allCnt, "revoke_all must write a user-level marker")
	assert.Zero(t, w.callCnt, "revoke_all must NOT write a per-jti row (no real jti is known)")
	assert.Equal(t, domain.UserID("usr_alice"), w.allUser)
	assert.NotEmpty(t, w.allReason)
	assert.False(t, w.allBefore.Before(before), "revoke_before must be at-or-after request time")

	// Operation metadata must reflect reality: a user-level revoke-all is not
	// a 0-count no-op. revoked_count is the documented "newly revoked" signal;
	// for a user-level cutoff it must be ≥1 (not the inert 0-with-success).
	var md iamv1.RevokeMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	assert.GreaterOrEqual(t, md.GetRevokedCount(), int32(1),
		"revoke_all must not report revoked_count=0 with success")
}

func TestRevoke_RevokeAllUserTokens_WriterError_FailsClosed(t *testing.T) {
	w := &fakeRevoker{allErr: errors.New("user_token_revocations down")}
	h := newHandler(w, &fakeReader{})
	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		UserId: "usr_alice", Reason: "admin-revoke", RevokeAllUserTokens: true,
	})
	require.Error(t, err, "a user-level revoke-all write error must surface, never silent success")
}

func TestRevoke_WriterUnavailable_FailsClosed(t *testing.T) {
	h := newHandler(nil, &fakeReader{})
	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-1", UserId: "usr_alice", Reason: "user-logout",
	})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestRevoke_WriterError_MapsToCode(t *testing.T) {
	w := &fakeRevoker{err: iamerr.Wrapf(iamerr.ErrUnavailable, "db down")}
	h := newHandler(w, &fakeReader{})
	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-1", UserId: "usr_alice", Reason: "user-logout",
	})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestIsRevoked_DelegatesToReader(t *testing.T) {
	r := &fakeReader{revoked: true, revAt: time.Now().UTC().Truncate(time.Second), reason: "user-logout"}
	h := newHandler(&fakeRevoker{}, r)

	resp, err := h.IsRevoked(context.Background(), &iamv1.IsRevokedRequest{TokenJti: "jti-x"})
	require.NoError(t, err)
	assert.True(t, resp.GetRevoked())
	assert.Equal(t, "jti-x", r.gotJTI)
}

func TestIsRevoked_NotRevoked(t *testing.T) {
	r := &fakeReader{revoked: false}
	h := newHandler(&fakeRevoker{}, r)
	resp, err := h.IsRevoked(context.Background(), &iamv1.IsRevokedRequest{TokenJti: "jti-x"})
	require.NoError(t, err)
	assert.False(t, resp.GetRevoked())
}

func TestIsRevoked_MissingJTI_InvalidArgument(t *testing.T) {
	h := newHandler(&fakeRevoker{}, &fakeReader{})
	_, err := h.IsRevoked(context.Background(), &iamv1.IsRevokedRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestIsRevoked_ReaderError_Internal(t *testing.T) {
	r := &fakeReader{isRevErr: errors.New("boom")}
	h := newHandler(&fakeRevoker{}, r)
	_, err := h.IsRevoked(context.Background(), &iamv1.IsRevokedRequest{TokenJti: "jti-x"})
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestListByUser_DelegatesToReader(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := &fakeReader{listRows: []domain.SessionRevocation{
		{TokenJTI: "jti-1", UserID: "usr_alice", Reason: "user-logout", RevokedAt: now, TTLExpiresAt: now.Add(time.Hour)},
	}}
	h := newHandler(&fakeRevoker{}, r)

	// Self-read: this case is about the reader delegation. Who may read WHOSE
	// history is settled separately, in list_by_user_authz_test.go.
	resp, err := h.ListByUser(asUser("usr_alice"), &iamv1.ListByUserRequest{UserId: "usr_alice"})
	require.NoError(t, err)
	require.Len(t, resp.GetRevocations(), 1)
	assert.Equal(t, "jti-1", resp.GetRevocations()[0].GetTokenJti())
	assert.Equal(t, "usr_alice", r.gotUserID)
}

func TestListByUser_MissingUserID_InvalidArgument(t *testing.T) {
	h := newHandler(&fakeRevoker{}, &fakeReader{})
	_, err := h.ListByUser(context.Background(), &iamv1.ListByUserRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── Operation persistence (unit level) ───────────────────────────────────────

// The declared metadata field revoked_count is knowable only after the writes,
// so it must arrive on the TERMINAL transition, not on Create. MarkDone would
// not do: its third parameter is the response and it never touches metadata,
// which is how a contract field stays empty forever while everything looks
// green.
func TestRevoke_TerminalTransitionCarriesMetadataAndResponse(t *testing.T) {
	w := &fakeRevoker{}
	h, ops := newHandlerWithOps(w, &fakeReader{})

	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-123",
		UserId:   "usr_alice",
		Reason:   "user-logout",
	})
	require.NoError(t, err)

	require.Contains(t, ops.calls, "create", "the operation row must be persisted")
	require.Contains(t, ops.calls, "markdone-with-metadata",
		"the terminal transition must replace metadata, not only write a response")
	require.NotContains(t, ops.calls, "markdone",
		"MarkDone leaves metadata as Create wrote it — revoked_count would stay 0 forever")

	// What Create wrote cannot yet know the count; what the terminal transition
	// wrote must.
	createdMeta := &iamv1.RevokeMetadata{}
	require.NoError(t, ops.created.Metadata.UnmarshalTo(createdMeta))
	assert.Equal(t, int32(0), createdMeta.GetRevokedCount())

	doneMeta := &iamv1.RevokeMetadata{}
	require.NotNil(t, ops.doneMeta)
	require.NoError(t, ops.doneMeta.UnmarshalTo(doneMeta))
	assert.Equal(t, int32(1), doneMeta.GetRevokedCount())
	assert.Equal(t, "usr_alice", doneMeta.GetUserId())

	doneResp := &iamv1.SessionRevocation{}
	require.NotNil(t, ops.doneResp, "Revoke declares response: SessionRevocation")
	require.NoError(t, ops.doneResp.UnmarshalTo(doneResp))
	assert.Equal(t, "jti-123", doneResp.GetTokenJti())
	assert.Equal(t, "usr_alice", doneResp.GetUserId())
}

// A failing write must mark the already-persisted operation terminally with the
// error a poller will read.
func TestRevoke_WriteFailure_MarksOperationError(t *testing.T) {
	w := &fakeRevoker{err: iamerr.ErrNotFound}
	h, ops := newHandlerWithOps(w, &fakeReader{})

	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-123",
		UserId:   "usr_alice",
	})
	require.Error(t, err)
	require.Contains(t, ops.calls, "create")
	require.Contains(t, ops.calls, "markerror",
		"a failed write must leave a terminal error the poller can read, not an unfinished row")
	require.NotNil(t, ops.errStatus)
	assert.NotZero(t, ops.errStatus.GetCode())
}

// Without a place to persist the operation the RPC must refuse: an id that
// names no row is exactly the defect, and a wiring omission must not
// reintroduce it silently.
func TestRevoke_NilOperationRepo_FailsClosed(t *testing.T) {
	w := &fakeRevoker{}
	h := NewHandler(NewRevokeUseCase(w, nil), &fakeReader{})

	_, err := h.Revoke(context.Background(), &iamv1.RevokeRequest{
		TokenJti: "jti-123",
		UserId:   "usr_alice",
	})
	require.Equal(t, codes.Unavailable, status.Code(err))
	assert.Zero(t, w.callCnt, "the refusal must precede the mutation")
}
