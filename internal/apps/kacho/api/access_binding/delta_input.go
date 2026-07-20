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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// targetRequiredMsg — the actionable least-privilege reject (redesign-2026 F8
// IAM-1-22): the broadest grant is reachable ONLY via explicit allInScope opt-in.
const targetRequiredMsg = "target is required; use target.allInScope{} to grant all objects under the anchor"

// targetFromProto maps the required proto AccessTarget oneof to the domain target,
// rejecting a missing/empty target sync (IAM-1-22) and an unknown per-object type
// against the closed type-registry (IAM-1-23). First-statement gRPC errors, before
// any Operation is minted.
func targetFromProto(t *iamv1.AccessTarget) (domain.AccessTarget, error) {
	if t == nil {
		return domain.AccessTarget{}, status.Error(codes.InvalidArgument, targetRequiredMsg)
	}
	switch arm := t.GetTarget().(type) {
	case *iamv1.AccessTarget_AllInScope:
		return domain.AccessTarget{AllInScope: true}, nil
	case *iamv1.AccessTarget_Resources:
		refs := arm.Resources.GetResources()
		if len(refs) == 0 {
			return domain.AccessTarget{}, status.Error(codes.InvalidArgument, targetRequiredMsg)
		}
		out := make([]domain.ResourceRef, 0, len(refs))
		for _, r := range refs {
			if !domain.ValidTargetType(r.GetType()) {
				return domain.AccessTarget{}, status.Errorf(codes.InvalidArgument,
					"Illegal argument target.resources[].type %q", r.GetType())
			}
			out = append(out, domain.ResourceRef{Type: r.GetType(), ID: r.GetId()})
		}
		return domain.AccessTarget{Resources: out}, nil
	default:
		// target message present but no arm set (empty oneof) → treat as missing.
		return domain.AccessTarget{}, status.Error(codes.InvalidArgument, targetRequiredMsg)
	}
}

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
