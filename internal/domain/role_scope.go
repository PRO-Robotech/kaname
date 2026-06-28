// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import "time"

// AssignableRole — the lean projection of a Role for the grant-form picker
// Carries only publicly-safe fields the UI needs to
// render + group the picker (id / resolved name / description / is_system /
// server-computed scope_group / created_at) — NO permissions array and
// no infra-sensitive fields. ScopeGroup is computed via ScopeGroupOf.
type AssignableRole struct {
	RoleID      RoleID
	Name        RoleName
	Description Description
	IsSystem    bool
	ScopeGroup  RoleScopeGroup
	CreatedAt   time.Time
}

// role_scope.go — the single source-of-truth predicate for "which roles may be
// bound to a given resource". Shared verbatim by:
//   - AccessBindingService.ListAssignableRoles (WHERE filter),
//   - AccessBinding.Create (scope-enforcement; mis-scoped → FAILED_PRECONDITION
//     via Operation.error).
//
// Pure domain logic (no pgx/grpc): it reads the role's scope columns
// (IsSystem / ClusterID / AccountID / ProjectID) and the target resource
// (type, id) and decides assignability. Keeping it here means both call sites
// share ONE definition — the assignable-set returned by ListAssignableRoles is
// exactly the set Create accepts (no bypass via direct API).
//
// STRICT semantics (assignability matrix):
//   - SYSTEM role (is_system, cluster-scoped) → assignable on ANY resource type.
//   - ACCOUNT-scoped custom role → assignable IFF resource_type=="account" AND
//     role.account_id == resource_id.
//   - PROJECT-scoped custom role → assignable IFF resource_type=="project" AND
//     role.project_id == resource_id.
//   - cluster resource → only SYSTEM roles.
// No hierarchy-down: an account-role is NOT assignable on its projects (STRICT).

// RoleScopeGroup — server-computed scope tier of a role, surfaced to the UI in
// AssignableRole.scope_group so the picker groups without client-side logic
// Maps 1:1 to the proto ScopeGroup enum.
type RoleScopeGroup int8

const (
	RoleScopeGroupUnspecified RoleScopeGroup = 0
	RoleScopeGroupSystem      RoleScopeGroup = 1
	RoleScopeGroupAccount     RoleScopeGroup = 2
	RoleScopeGroupProject     RoleScopeGroup = 3
)

// String — debug rendering (matches the proto enum names).
func (g RoleScopeGroup) String() string {
	switch g {
	case RoleScopeGroupSystem:
		return "SYSTEM"
	case RoleScopeGroupAccount:
		return "ACCOUNT"
	case RoleScopeGroupProject:
		return "PROJECT"
	default:
		return "SCOPE_GROUP_UNSPECIFIED"
	}
}

// ScopeGroupOf derives the scope tier from the role's scope columns. System
// roles are SYSTEM; otherwise the non-empty custom scope decides
// (account → ACCOUNT, project → PROJECT).
func ScopeGroupOf(r Role) RoleScopeGroup {
	switch {
	case r.IsSystem:
		return RoleScopeGroupSystem
	case r.AccountID != "":
		return RoleScopeGroupAccount
	case r.ProjectID != "":
		return RoleScopeGroupProject
	default:
		return RoleScopeGroupUnspecified
	}
}

// IsRoleAssignable reports whether role r may be bound on resource
// (resourceType, resourceID) per the STRICT assignability matrix.
func IsRoleAssignable(r Role, resourceType, resourceID string) bool {
	// SYSTEM roles are assignable everywhere (including cluster).
	if r.IsSystem {
		return true
	}
	switch resourceType {
	case "account":
		// account-scoped custom role → only on its OWN account.
		return r.AccountID != "" && string(r.AccountID) == resourceID
	case "project":
		// project-scoped custom role → only on its OWN project (STRICT: no
		// hierarchy-down from an account-role).
		return r.ProjectID != "" && string(r.ProjectID) == resourceID
	case "cluster":
		// cluster ⇒ only SYSTEM (handled above) — no custom role qualifies.
		return false
	default:
		return false
	}
}
