// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — errdetails.go: builder для InvalidArgument с BadRequest
// FieldViolations details (Kachō error-format convention).
//
// Заменяет 6+ копий per-resource `invalidArg(field, desc)` (account/helpers.go,
// project/helpers.go, …) — все идентичны bit-for-bit.
package shared

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InvalidArg — InvalidArgument-error с одним BadRequest_FieldViolation. Если
// WithDetails не смог приклеить детали (proto-marshal-fail), возвращает голый
// status без них (best-effort — клиент получит code+message, отсутствие
// details не критично).
func InvalidArg(field, desc string) error {
	st := status.New(codes.InvalidArgument, desc)
	br := &errdetails.BadRequest{
		FieldViolations: []*errdetails.BadRequest_FieldViolation{
			{Field: field, Description: desc},
		},
	}
	if withDetails, derr := st.WithDetails(br); derr == nil {
		return withDetails.Err()
	}
	return st.Err()
}
