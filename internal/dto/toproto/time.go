// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package toproto — DTO transfer implementations domain/repo → proto for
// kacho-iam. Transfers are registered at init time (parity with kacho-vpc).
package toproto

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

// tsTruncate — the single truncation granularity for every proto timestamp in
// kacho-iam: the API contract truncates created_at/added_at to whole SECONDS
// (api-conventions.md: "в proto-ответе truncate до секунд"); the DB keeps
// microseconds. Use this constant for all `.Truncate(...)` calls in this
// package instead of a hardcoded `1_000_000_000` ns literal (DRY — the literal
// IS time.Second, so this is semantically identical).
const tsTruncate = time.Second

// timeObj — empty struct-receiver for the time.Time → pb timestamp
// transfer method (parity with kacho-vpc/internal/dto/toproto/time.go).
type timeObj struct{}

func (timeObj) toPb(t time.Time) (*timestamppb.Timestamp, error) {
	return timestamppb.New(t.Truncate(tsTruncate)), nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(timeObj{}.toPb))
}
