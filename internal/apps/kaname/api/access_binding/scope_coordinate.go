// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// scope_coordinate.go — ONE coordinate, ONE name (redesign-2026 F7 follow-through
// on the READ side).
//
// F7 flattened the binding anchor into `scope_type`/`scope_id` (dotted) and gave
// the word "resource" to the `target` (F8 — WHICH OBJECTS under the anchor a grant
// covers). `AccessBinding` and `AccessBinding.Create` speak that vocabulary. The
// read RPCs did not: `ListByScope` and `ListAssignableRoles` took
// `resource_type`/`resource_id` (bare) and `SubjectPrivilege` returned the same
// legacy pair — so the SAME coordinate had three spellings, and the legacy one
// meant the exact OPPOSITE of what access_binding.proto documents.
//
// The requests now accept the canonical dotted pair ADDITIVELY: `scope_type` wins
// when set, the legacy bare pair remains the fallback (wire-compatible), and the
// responses populate BOTH.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// scopeCoordinate resolves the scope anchor a read RPC was called with into the
// BARE within-service anchor kind (cluster|account|project) plus its id.
//
// Precedence: the canonical dotted `scope_type`/`scope_id` wins whenever
// `scope_type` is non-empty; otherwise the legacy bare `resource_type`/
// `resource_id` pair is used verbatim. A non-empty dotted value outside the closed
// three-tier set is rejected SYNC with INVALID_ARGUMENT — it must NOT silently
// fall through to the legacy pair, which would resolve a typo'd anchor to a
// DIFFERENT anchor (a mistyped `iam.acount` would quietly list `account`).
//
// The bare kind is what every downstream (use-case, repo, FGA object) already
// speaks, so this is a pure transport-edge translation.
func scopeCoordinate(scopeType, scopeID, legacyType, legacyID string) (string, string, error) {
	if scopeType == "" {
		return legacyType, legacyID, nil
	}
	bare, ok := domain.ScopeTypeFromDotted(scopeType)
	if !ok {
		return "", "", status.Errorf(codes.InvalidArgument, "Illegal argument scopeType %q", scopeType)
	}
	return bare, scopeID, nil
}
