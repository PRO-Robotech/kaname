// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delta_input.go — TWO-WAY INPUT NORMALIZATION of the scope dimension on
// AccessBinding.Create. The role.rules carry the "what object" decision, so only
// the scope normalization remains here.
//
// This is a pure FORM-projection over the SAME data: no new tables, no domain
// change, no behaviour change. The normalization lives here in the use-case
// transport-adjacent layer (proto → domain) — domain stays pure, the writer-tx is
// untouched.
//
// scope:  legacy flat resource_type/resource_id ⟷ canonical scope_ref{tier,id}.
//   - only legacy        → used as-is.
//   - only canonical     → derived to the (resource_type, resource_id) pair.
//   - both, equivalent   → OK, NOT a conflict (derived-equivalent).
//   - both, disagree     → sync INVALID_ARGUMENT.
//   - canonical invalid (tier↔id mismatch / unspecified tier) → INVALID_ARGUMENT,
//     re-using domain.Scope.ValidateAgainst.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// normalizeScopeInput reconciles the legacy flat scope (resourceType/resourceID)
// with the canonical scope_ref into the single (resourceType, resourceID) pair
// the rest of the pipeline consumes. The canonical form has priority only when
// the legacy form is absent; a present-and-conflicting pair is rejected,
// a derived-equivalent pair is accepted.
func normalizeScopeInput(resourceType, resourceID string, scopeRef *iamv1.ScopeRef) (string, string, error) {
	legacySet := resourceType != "" || resourceID != ""
	if scopeRef == nil {
		// Only the legacy form (or neither — downstream domain.Validate rejects an
		// empty resource). Used as-is.
		return resourceType, resourceID, nil
	}

	// The canonical form is set — validate it standalone first: the tier
	// must be specified and must be consistent with its id, re-using the existing
	// derived-equivalence predicate (no new logic).
	tier := scopeToDomain(scopeRef.GetTier())
	if tier == domain.ScopeUnspecified {
		return "", "", status.Error(codes.InvalidArgument, "scope.tier is required")
	}
	canonType, canonID := scopeRefToLegacy(tier, scopeRef.GetId())
	if err := tier.ValidateAgainst(canonType, canonID); err != nil {
		return "", "", status.Errorf(codes.InvalidArgument,
			"scope: tier %s requires a consistent id (%s)", tier, err.Error())
	}

	if !legacySet {
		// Only the canonical form → derive the legacy pair.
		return canonType, canonID, nil
	}

	// BOTH set — derived-equivalent ⇒ OK; disagree ⇒ INVALID_ARGUMENT.
	if canonType != resourceType || canonID != resourceID {
		return "", "", status.Error(codes.InvalidArgument,
			"scope conflicts with resource_type/resource_id")
	}
	return resourceType, resourceID, nil
}

// scopeRefToLegacy maps a canonical {tier, id} to the legacy (resource_type,
// resource_id) pair. resource_id == scope_ref.id for every tier; resource_type
// is the tier's canonical kind string (mirrors the migration-0005 trigger and
// Scope.ValidateAgainst).
func scopeRefToLegacy(tier domain.Scope, id string) (resourceType, resourceID string) {
	switch tier {
	case domain.ScopeCluster:
		return "cluster", id
	case domain.ScopeAccount:
		return "account", id
	case domain.ScopeProject:
		return "project", id
	default:
		return "", id
	}
}

// scopeToDomain maps the proto Scope enum to the domain Scope (the inverse of
// domainScopeToProto, kept here so the use-case does not depend on toproto).
func scopeToDomain(s iamv1.AccessBinding_Scope) domain.Scope {
	switch s {
	case iamv1.AccessBinding_CLUSTER:
		return domain.ScopeCluster
	case iamv1.AccessBinding_ACCOUNT:
		return domain.ScopeAccount
	case iamv1.AccessBinding_PROJECT:
		return domain.ScopeProject
	default:
		return domain.ScopeUnspecified
	}
}
