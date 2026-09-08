// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// list_page_size_rejected_test.go — every paged read of this service rejects an
// out-of-range page_size instead of quietly shrinking it.
//
// The platform contract (api-conventions) is [0..1000], 0 meaning the default,
// anything outside REJECTED. A clamp answers 200 OK with a page smaller than the
// caller asked for, and nothing in the response distinguishes that from a
// complete answer — the caller believes it has everything. `effectivePageSize`
// already encodes the rule for the repos that adopted it; this locks the ones
// that still carried the legacy clamp.
//
// The repos are built over a nil pool ON PURPOSE: the guard must run BEFORE any
// query is issued, so reaching the pool at all would panic and fail the test.
// "The check runs first" is therefore asserted, not assumed.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// overMaxPageSize — one above the platform maximum.
const overMaxPageSize = int32(maxListPageSize) + 1

func TestUserOAuthClientList_PageSizeOverMax_Rejected(t *testing.T) {
	r := &UserOAuthClientRepo{}

	_, _, err := r.List(context.Background(), domain.UserID("usr00000000000000001"), "", overMaxPageSize)

	require.Error(t, err, "page_size over the maximum must be rejected, never clamped")
	assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
}

func TestSAOAuthClientList_PageSizeOverMax_Rejected(t *testing.T) {
	r := &SAOAuthClientRepo{}

	_, _, err := r.List(context.Background(), domain.ServiceAccountID("sva00000000000000001"), "", overMaxPageSize)

	require.Error(t, err, "page_size over the maximum must be rejected, never clamped")
	assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
}

func TestSessionRevocationList_PageSizeOverMax_Rejected(t *testing.T) {
	r := &SessionRevocationRepo{}

	_, _, err := r.ListByUser(context.Background(), "usr00000000000000001", overMaxPageSize, "")

	require.Error(t, err, "page_size over the maximum must be rejected, never clamped")
	assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
}

// A cursor the repo cannot decode is refused rather than ignored: an ignored
// cursor restarts the walk at the newest row, so the caller pages forever over
// the same page while believing it advances.
func TestSessionRevocationList_GarbagePageToken_Rejected(t *testing.T) {
	r := &SessionRevocationRepo{}

	_, _, err := r.ListByUser(context.Background(), "usr00000000000000001", 10, "!!!not-base64!!!")

	require.Error(t, err)
	assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
}

// The five AccessBinding read paths take page_size straight from the request
// (only the canonical List has a handler-side check in front of it), so the same
// clamp there hands a short page to ListByScope / ListBySubject / ListByAccount /
// ListSubjectPrivileges / ListByRole callers with nothing to say it was short.
func TestAccessBindingReads_PageSizeOverMax_Rejected(t *testing.T) {
	ctx := context.Background()
	r := &abReader{}

	t.Run("List", func(t *testing.T) {
		_, _, err := r.List(ctx, access_binding.ListFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
	t.Run("ListByScope", func(t *testing.T) {
		_, _, err := r.ListByScope(ctx, domain.ResourceType("account"), "acc00000000000000001",
			access_binding.PageFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
	t.Run("ListBySubject", func(t *testing.T) {
		_, _, err := r.ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID("usr00000000000000001"),
			access_binding.PageFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
	t.Run("ListByAccount", func(t *testing.T) {
		_, _, err := r.ListByAccount(ctx, domain.AccountID("acc00000000000000001"),
			access_binding.AccountPageFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
	t.Run("ListSubjectPrivileges", func(t *testing.T) {
		_, _, err := r.ListSubjectPrivileges(ctx, domain.SubjectTypeUser, domain.SubjectID("usr00000000000000001"),
			access_binding.PageFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
	t.Run("ListByRole", func(t *testing.T) {
		_, _, err := r.ListByRole(ctx, domain.RoleID("rol00000000000000001"),
			access_binding.ListByRoleFilter{PageSize: overMaxPageSize})
		require.Error(t, err)
		assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
	})
}

// No weakening: a page_size INSIDE the range is not rejected — it goes on to the
// query (which panics on the nil pool, proving the guard let it through rather
// than swallowing everything).
func TestListPageSize_WithinRange_NotRejected(t *testing.T) {
	assert.Panics(t, func() {
		r := &SessionRevocationRepo{}
		_, _, _ = r.ListByUser(context.Background(), "usr00000000000000001", int32(maxListPageSize), "")
	}, "a legal page_size must reach the query; a guard that rejected it too would make the check meaningless")
}
