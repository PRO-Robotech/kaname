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
//
// STATELESS predicate — no hierarchy-down: the pure IsRoleAssignable cannot know a
// project's OWNING account (it holds no repo), so it treats an account-role on a
// project as NOT assignable. That keeps the ListAssignableRoles palette (WHERE filter)
// and its SQL mirror strict-per-tier. The hierarchy-down rule "an iam.account-tier
// role IS assignable on a project NESTED in the role's account" (acceptance IAM-1-25)
// is admitted by IsRoleAssignableInAccount, which takes the RESOLVED owning-account of
// the scope — the Create gate resolves project→account and calls it, so the
// authoritative Create boundary honours nesting while the stateless predicate stays
// pure. The account boundary is never crossed: a role of a DIFFERENT account is still
// rejected.

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

// IsRoleAssignableInAccount extends IsRoleAssignable with the hierarchy-down rule that
// needs the scope's RESOLVED owning-account — knowledge the stateless predicate does
// not have (acceptance IAM-1-25). scopeOwningAccountID is the account that OWNS the
// scope anchor: for an account scope it is the account id itself; for a project scope
// it is the project's account_id (resolved by the caller via a project→account lookup);
// for cluster / cross-service scopes it is "".
//
// It admits the strict matrix (IsRoleAssignable) PLUS the single hierarchy-down case:
// an iam.account-tier custom role is assignable on a PROJECT nested in the role's own
// account (role.account_id == the project's owning account). The account boundary is
// never crossed — an account-role of a DIFFERENT account stays not-assignable — and no
// other tier gains breadth (system stays everywhere, project-role stays own-project).
// scopeOwningAccountID=="" (unresolved / non-account scope) collapses to the strict
// predicate, so a missing resolve never over-grants (fail-closed).
func IsRoleAssignableInAccount(r Role, resourceType, resourceID, scopeOwningAccountID string) bool {
	if IsRoleAssignable(r, resourceType, resourceID) {
		return true
	}
	// Hierarchy-down: iam.account-tier role on a project nested in the role's account.
	if resourceType == "project" && !r.IsSystem && r.AccountID != "" && r.ProjectID == "" {
		return scopeOwningAccountID != "" && string(r.AccountID) == scopeOwningAccountID
	}
	return false
}
