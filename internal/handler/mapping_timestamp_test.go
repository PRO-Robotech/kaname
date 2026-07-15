// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// mapping_timestamp_test.go — Wave T conformance: proto-response timestamps
// must be truncated to whole seconds (api-conventions: "Timestamps: в
// proto-ответе truncate до секунд"; DB stores microseconds). A micros-bearing
// Operation.CreatedAt / ModifiedAt must surface with a zero sub-second part.
package handler

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

func TestOperationToProto_TruncatesTimestampsToSeconds(t *testing.T) {
	// 123456789ns sub-second part — must be dropped in the proto response.
	created := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)
	modified := time.Date(2026, 6, 16, 10, 20, 31, 987654321, time.UTC)

	p := operationToProto(&operations.Operation{
		ID:         "iop_test_op_1234567890ab",
		CreatedAt:  created,
		ModifiedAt: modified,
		Principal:  operations.Principal{Type: "user", ID: "usr_alice"},
	})

	if got := p.GetCreatedAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("CreatedAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !p.GetCreatedAt().AsTime().Equal(created.Truncate(time.Second)) {
		t.Fatalf("CreatedAt = %v, want %v", p.GetCreatedAt().AsTime(), created.Truncate(time.Second))
	}
	if got := p.GetModifiedAt().AsTime().Nanosecond(); got != 0 {
		t.Fatalf("ModifiedAt sub-second leaked: nanos=%d, want 0", got)
	}
	if !p.GetModifiedAt().AsTime().Equal(modified.Truncate(time.Second)) {
		t.Fatalf("ModifiedAt = %v, want %v", p.GetModifiedAt().AsTime(), modified.Truncate(time.Second))
	}
}
