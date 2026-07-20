// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delta_input.go — scope-anchor input mapping on AccessBinding.Create
// (redesign-2026 F7). The wire carries the dotted scopeType
// (`iam.cluster` | `iam.account` | `iam.project`); the within-service storage keeps
// the bare kind (`cluster` / `account` / `project`). This maps the dotted wire form
// to the bare kind at the API boundary — domain stays pure, the writer-tx untouched.
//
// Pre-Phase-0 the scopeType is REQUIRED explicitly (prefix-derivation from scopeId
// is B3-gated). An empty / non-dotted / unknown value is rejected sync
// (INVALID_ARGUMENT, first statement, before any Operation is minted).

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// scopeTypeToBare maps the dotted wire scopeType to the bare within-service anchor
// kind. Empty → INVALID_ARGUMENT "scopeType is required" (pre-Phase-0 explicit);
// non-dotted / unknown → INVALID_ARGUMENT "Illegal argument scopeType".
func scopeTypeToBare(scopeType string) (string, error) {
	if scopeType == "" {
		return "", status.Error(codes.InvalidArgument, "scopeType is required")
	}
	bare, ok := domain.ScopeTypeFromDotted(scopeType)
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "Illegal argument scopeType %q", scopeType)
	}
	return bare, nil
}
