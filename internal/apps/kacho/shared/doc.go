// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — общие helpers для всех api-слайсов (parity с
// kacho-vpc/internal/apps/kacho/shared).
//
// Содержит:
//   - errors.go     — sentinel → gRPC status mapping (MapRepoErr,
//     MapValidationErr); заменяет per-resource `mapRepoErr`.
//   - errdetails.go — InvalidArgument-builder с BadRequest FieldViolations.
//   - ids.go        — `ValidateResourceID(id, prefix, name)` (parity с YC-style
//     ошибкой `"invalid <resource> id '<id>'"`).
//   - proto.go      — `TimestampProto` (truncate-to-seconds), `OperationToProto`
//     (corelib.Operation → proto.Operation).
package shared
