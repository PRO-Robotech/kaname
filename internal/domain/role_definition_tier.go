// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_definition_tier.go — redesign-2026 F4. The Role carries a `definitionTier`
// wire projection ({tierType, tierId}, dotted) over the within-service typed scope
// columns (cluster_id / account_id / project_id). The word "scope" stays reserved
// for the AccessBinding anchor; a Role is DEFINED at a tier. `isSystem` is DERIVED
// from the tier (tierType == iam.cluster), never an independently stored flag —
// the roles_definition_tier_xor DB CHECK keeps exactly one tier anchor non-null,
// so the derivation cannot disagree with storage.
//
// The dotted tier vocabulary is identical to the AccessBinding scope vocabulary
// (iam.cluster | iam.account | iam.project — see access_binding_scope.go), so the
// same dotted constants are reused here.

// DefinitionTierType returns the dotted definition-tier type of the role:
// iam.cluster for a system role (cluster_id set), iam.account / iam.project for a
// custom role. Empty when no anchor is set (should not happen under the XOR CHECK).
func (r Role) DefinitionTierType() string {
	switch {
	case r.ClusterID != "":
		return ScopeTypeClusterDotted
	case r.AccountID != "":
		return ScopeTypeAccountDotted
	case r.ProjectID != "":
		return ScopeTypeProjectDotted
	default:
		return ""
	}
}

// DefinitionTierID returns the anchor object id of the role's definition tier
// (cluster / account / project id), matching DefinitionTierType.
func (r Role) DefinitionTierID() string {
	switch {
	case r.ClusterID != "":
		return string(r.ClusterID)
	case r.AccountID != "":
		return string(r.AccountID)
	case r.ProjectID != "":
		return string(r.ProjectID)
	default:
		return ""
	}
}

// IsSystemDerived reports whether the role is a system role, DERIVED from its
// definition tier (tierType == iam.cluster) rather than a stored provenance flag
// (redesign-2026 F4). Equivalent to ClusterID != "".
func (r Role) IsSystemDerived() bool {
	return r.ClusterID != ""
}

// CustomDefinitionTierToScope maps a wire definition_tier (dotted tierType + anchor
// id) to the account/project scope of a CUSTOM role (redesign-2026 F4). Pre-Phase-0
// tierType is REQUIRED (prefix-derivation is B3-gated, so an empty tierType is
// rejected). iam.cluster is rejected — system roles are seeded by migration, never
// created via the public API. ok=false for an empty / iam.cluster / unknown
// tierType (the caller turns it into INVALID_ARGUMENT "Illegal argument
// definitionTier").
func CustomDefinitionTierToScope(tierType, tierID string) (account, project string, ok bool) {
	switch tierType {
	case ScopeTypeAccountDotted:
		return tierID, "", true
	case ScopeTypeProjectDotted:
		return "", tierID, true
	default:
		return "", "", false
	}
}
