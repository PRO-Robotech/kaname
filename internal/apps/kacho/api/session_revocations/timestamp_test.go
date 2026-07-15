// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// timestamp_test.go — Wave T conformance: SessionRevocation proto-response
// timestamps (RevokedAt / TtlExpiresAt) must be truncated to whole seconds
// (api-conventions; DB stores microseconds). Covers both the toProto mapper
// (ListByUser path) and the IsRevoked enrichment path.
package session_revocations

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestToProto_TruncatesTimestampsToSeconds(t *testing.T) {
	revoked := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)
	ttl := time.Date(2026, 6, 16, 11, 20, 30, 987654321, time.UTC)

	out := toProto(domain.SessionRevocation{
		TokenJTI:     "jti-1",
		UserID:       "usr_alice",
		Reason:       "user-logout",
		RevokedAt:    revoked,
		TTLExpiresAt: ttl,
	})

	assert.Zero(t, out.GetRevokedAt().AsTime().Nanosecond(), "RevokedAt sub-second leaked")
	assert.True(t, out.GetRevokedAt().AsTime().Equal(revoked.Truncate(time.Second)))
	assert.Zero(t, out.GetTtlExpiresAt().AsTime().Nanosecond(), "TtlExpiresAt sub-second leaked")
	assert.True(t, out.GetTtlExpiresAt().AsTime().Equal(ttl.Truncate(time.Second)))
}

func TestIsRevoked_TruncatesRevokedAtToSeconds(t *testing.T) {
	revoked := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)
	r := &fakeReader{revoked: true, revAt: revoked, reason: "user-logout"}
	h := newHandler(&fakeRevoker{}, r)

	resp, err := h.IsRevoked(context.Background(), &iamv1.IsRevokedRequest{TokenJti: "jti-x"})
	require.NoError(t, err)
	require.True(t, resp.GetRevoked())
	require.NotNil(t, resp.GetRevokedAt())
	assert.Zero(t, resp.GetRevokedAt().AsTime().Nanosecond(), "RevokedAt sub-second leaked in IsRevoked")
	assert.True(t, resp.GetRevokedAt().AsTime().Equal(revoked.Truncate(time.Second)))
}
