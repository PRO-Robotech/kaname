// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_timestamp_test.go — Wave T conformance: SAOAuthClient proto-response
// timestamps (CreatedAt / ExpiresAt / LastUsedAt) must be truncated to whole
// seconds (api-conventions; DB stores microseconds).
package sa_keys

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestSAClientToProto_TruncatesTimestampsToSeconds(t *testing.T) {
	created := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)
	expires := time.Date(2027, 1, 2, 3, 4, 5, 555555555, time.UTC)
	used := time.Date(2026, 6, 16, 11, 22, 33, 999999999, time.UTC)

	pb, err := saClientToProto(domain.ServiceAccountOAuthClient{
		ID:         "sak_test_1234567890abcd",
		SvaID:      "sva_test_1234567890abcd",
		CreatedAt:  created,
		ExpiresAt:  &expires,
		LastUsedAt: &used,
	})
	if err != nil {
		t.Fatalf("saClientToProto: %v", err)
	}

	if got := pb.GetCreatedAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("CreatedAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !pb.GetCreatedAt().AsTime().Equal(created.Truncate(time.Second)) {
		t.Fatalf("CreatedAt = %v, want %v", pb.GetCreatedAt().AsTime(), created.Truncate(time.Second))
	}
	if got := pb.GetExpiresAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("ExpiresAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !pb.GetExpiresAt().AsTime().Equal(expires.Truncate(time.Second)) {
		t.Fatalf("ExpiresAt = %v, want %v", pb.GetExpiresAt().AsTime(), expires.Truncate(time.Second))
	}
	if got := pb.GetLastUsedAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("LastUsedAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !pb.GetLastUsedAt().AsTime().Equal(used.Truncate(time.Second)) {
		t.Fatalf("LastUsedAt = %v, want %v", pb.GetLastUsedAt().AsTime(), used.Truncate(time.Second))
	}
}
