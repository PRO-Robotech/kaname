// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// timestamp_test.go — Wave T conformance: Condition proto-response CreatedAt
// must be truncated to whole seconds (api-conventions; DB stores microseconds).
package conditions

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

func TestConditionToProto_TruncatesCreatedAtToSeconds(t *testing.T) {
	created := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)

	pb := service.ConditionToProto(domain.Condition{
		ID:        "cnd_test_1234567890abcd",
		FolderID:  "fld_test",
		Name:      "cond-a",
		Status:    domain.ConditionStatusActive,
		CreatedAt: created,
	})

	if pb.GetCreatedAt() == nil {
		t.Fatalf("CreatedAt must be set for a non-zero created time")
	}
	if got := pb.GetCreatedAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("CreatedAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !pb.GetCreatedAt().AsTime().Equal(created.Truncate(time.Second)) {
		t.Fatalf("CreatedAt = %v, want %v", pb.GetCreatedAt().AsTime(), created.Truncate(time.Second))
	}
}
