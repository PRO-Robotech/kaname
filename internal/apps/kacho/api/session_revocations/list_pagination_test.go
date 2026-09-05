// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// list_pagination_test.go — ListByUser is an audit enumeration, so it must never
// answer "this is all of it" when it is not.
//
// Platform pagination contract (api-conventions):
//   - page_size outside [0..1000] is REJECTED (InvalidArgument), never clamped —
//     a clamp hands back a short page indistinguishable from a complete one;
//   - a malformed page_token is REJECTED, never ignored — an ignored cursor
//     restarts the enumeration at the newest row, so the caller pages forever
//     over page one while believing it advances;
//   - a page that was cut carries next_page_token — without it the rest of the
//     revocation history is unreachable, and an audit that silently shows a
//     prefix is worse than one that shows nothing.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// pagingReader — reader port recording exactly what the handler asked for and
// returning a canned page + continuation token.
type pagingReader struct {
	rows []domain.SessionRevocation
	next string

	gotUserID    string
	gotPageSize  int32
	gotPageToken string
	calls        int
}

func (f *pagingReader) IsRevoked(context.Context, string) (bool, error) { return false, nil }
func (f *pagingReader) GetByJTI(context.Context, string) (domain.SessionRevocation, error) {
	return domain.SessionRevocation{}, nil
}

func (f *pagingReader) ListByUser(_ context.Context, userID string, pageSize int32, pageToken string) ([]domain.SessionRevocation, string, error) {
	f.calls++
	f.gotUserID, f.gotPageSize, f.gotPageToken = userID, pageSize, pageToken
	return f.rows, f.next, nil
}

func revRow(jti string) domain.SessionRevocation {
	now := time.Now().UTC().Truncate(time.Second)
	return domain.SessionRevocation{
		TokenJTI: jti, UserID: "usr_alice", Reason: "user-logout",
		RevokedAt: now, TTLExpiresAt: now.Add(time.Hour),
	}
}

// A page_size above the platform maximum is a caller error. Clamping it to 100
// and answering 200 OK reports a truncated audit as a whole one.
func TestListByUser_PageSizeOverMax_InvalidArgument(t *testing.T) {
	r := &pagingReader{}
	h := newHandler(&fakeRevoker{}, r)

	_, err := h.ListByUser(context.Background(), &iamv1.ListByUserRequest{
		UserId: "usr_alice", PageSize: 5000,
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"page_size outside [0..1000] is rejected, never clamped")
	assert.Zero(t, r.calls, "a rejected page_size must not reach the store")
}

func TestListByUser_NegativePageSize_InvalidArgument(t *testing.T) {
	r := &pagingReader{}
	h := newHandler(&fakeRevoker{}, r)

	_, err := h.ListByUser(context.Background(), &iamv1.ListByUserRequest{
		UserId: "usr_alice", PageSize: -1,
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Zero(t, r.calls)
}

// A cursor the service cannot decode must be refused, not ignored.
func TestListByUser_GarbagePageToken_InvalidArgument(t *testing.T) {
	r := &pagingReader{rows: []domain.SessionRevocation{revRow("jti-1")}}
	h := newHandler(&fakeRevoker{}, r)

	_, err := h.ListByUser(context.Background(), &iamv1.ListByUserRequest{
		UserId: "usr_alice", PageToken: "!!!not-base64!!!",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"a malformed cursor is rejected, never silently ignored")
	assert.Zero(t, r.calls, "a rejected cursor must not reach the store")
}

// The caller's cursor must reach the store, and the store's continuation token
// must reach the caller. Either half missing turns the enumeration into a loop.
func TestListByUser_CursorRoundTrips(t *testing.T) {
	r := &pagingReader{rows: []domain.SessionRevocation{revRow("jti-2")}, next: "bmV4dA=="}
	h := newHandler(&fakeRevoker{}, r)

	// A well-formed opaque cursor, in the platform's own encoding.
	const cursor = "MjAyNi0wNy0yOVQxMDoxMTowMFp8anRpLTE="

	// Self-read: this case is about the cursor, so it runs under the one identity
	// that needs no grant. Who may read WHOSE history is settled separately, in
	// list_by_user_authz_test.go.
	resp, err := h.ListByUser(asUser("usr_alice"), &iamv1.ListByUserRequest{
		UserId: "usr_alice", PageSize: 25, PageToken: cursor,
	})

	require.NoError(t, err)
	assert.Equal(t, cursor, r.gotPageToken, "the caller's cursor must reach the store")
	assert.EqualValues(t, 25, r.gotPageSize, "the caller's page_size must reach the store")
	assert.Equal(t, "bmV4dA==", resp.GetNextPageToken(),
		"a cut page must advertise its continuation; without it the rest of the history is unreachable")
	require.Len(t, resp.GetRevocations(), 1)
}

// page_size 0 means "server default" — accepted, forwarded as-is so the store
// applies its own documented default.
func TestListByUser_ZeroPageSize_UsesStoreDefault(t *testing.T) {
	r := &pagingReader{rows: []domain.SessionRevocation{revRow("jti-3")}}
	h := newHandler(&fakeRevoker{}, r)

	_, err := h.ListByUser(asUser("usr_alice"), &iamv1.ListByUserRequest{UserId: "usr_alice"})

	require.NoError(t, err)
	assert.EqualValues(t, 0, r.gotPageSize, "0 is forwarded so the store applies the documented default")
	assert.Equal(t, "usr_alice", r.gotUserID)
}
