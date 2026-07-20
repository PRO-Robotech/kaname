// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_scope_test.go — unit tests for the single-source-of-truth predicate
// IsRoleAssignable + ScopeGroupOf.
//
// This predicate is shared by AccessBindingService.ListAssignableRoles (WHERE
// filter) and AccessBinding.Create (scope-enforcement). It is pure domain logic
// (no pgx/grpc) — it reads the role's scope columns and the target resource
// (type, id) and returns whether the role may be bound there. STRICT semantics:
// account-role only on its own account, project-role only on its own
// project, system-role everywhere; cluster ⇒ system only.

import "testing"

func systemRole() Role {
	return Role{ID: "rol00000000000000sys00", ClusterID: ClusterSingletonID, IsSystem: true, Name: "roles/iam.viewer"}
}

func accountRole(acc AccountID) Role {
	return Role{ID: "rol00000000000000acc00", AccountID: acc, IsSystem: false, Name: "my-account-role"}
}

func projectRole(prj ProjectID) Role {
	return Role{ID: "rol00000000000000prj00", ProjectID: prj, IsSystem: false, Name: "my-project-role"}
}

func TestIsRoleAssignable_Matrix(t *testing.T) {
	const (
		accA = AccountID("acc00000000000000000A")
		accB = AccountID("acc00000000000000000B")
		prjP = ProjectID("prj00000000000000000P")
		prjQ = ProjectID("prj00000000000000000Q")
	)

	cases := []struct {
		name         string
		role         Role
		resourceType string
		resourceID   string
		want         bool
	}{
		// account resource
		{"system on account", systemRole(), "account", string(accA), true},
		{"own account-role on account", accountRole(accA), "account", string(accA), true},
		{"foreign account-role on account", accountRole(accB), "account", string(accA), false}, // isolation
		{"project-role on account", projectRole(prjP), "account", string(accA), false},

		// project resource (STRICT)
		{"system on project", systemRole(), "project", string(prjP), true},
		{"own project-role on project", projectRole(prjP), "project", string(prjP), true},
		{"foreign project-role on project", projectRole(prjQ), "project", string(prjP), false},
		{"account-role on project STRICT", accountRole(accA), "project", string(prjP), false},

		// cluster resource — system only
		{"system on cluster", systemRole(), "cluster", ClusterSingletonID, true},
		{"account-role on cluster", accountRole(accA), "cluster", ClusterSingletonID, false},
		{"project-role on cluster", projectRole(prjP), "cluster", ClusterSingletonID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsRoleAssignable(tc.role, tc.resourceType, tc.resourceID)
			if got != tc.want {
				t.Fatalf("IsRoleAssignable(%s on %s:%s) = %v, want %v",
					tc.role.ID, tc.resourceType, tc.resourceID, got, tc.want)
			}
		})
	}
}

// TestIsRoleAssignableInAccount_HierarchyDown locks the IAM-1-25 hierarchy-down rule:
// an iam.account-tier role IS assignable on a project nested in the role's account
// (resolved owning-account == role.account_id), but never on a project of a different
// account. Every stateless-matrix verdict is preserved (the resolved account only ADDS
// the one nesting case; it never broadens system / project-role / cluster).
func TestIsRoleAssignableInAccount_HierarchyDown(t *testing.T) {
	const (
		accA = AccountID("acc00000000000000000A")
		accB = AccountID("acc00000000000000000B")
		prjP = ProjectID("prj00000000000000000P")
	)
	cases := []struct {
		name          string
		role          Role
		resourceType  string
		resourceID    string
		owningAccount string // resolved owning account of the scope
		want          bool
	}{
		// hierarchy-down: account-role on a project nested in the SAME account → OK.
		{"account-role on nested project (same account)", accountRole(accA), "project", string(prjP), string(accA), true},
		// isolation: account-role on a project of a DIFFERENT account → rejected.
		{"account-role on project of different account", accountRole(accA), "project", string(prjP), string(accB), false},
		// unresolved owning account (empty) → collapses to strict → rejected (fail-closed).
		{"account-role on project, unresolved account", accountRole(accA), "project", string(prjP), "", false},
		// strict verdicts preserved regardless of the resolved account:
		{"own account-role on account", accountRole(accA), "account", string(accA), string(accA), true},
		{"foreign account-role on account", accountRole(accB), "account", string(accA), string(accA), false},
		{"own project-role on project", projectRole(prjP), "project", string(prjP), string(accA), true},
		{"system on project", systemRole(), "project", string(prjP), string(accA), true},
		{"account-role on cluster", accountRole(accA), "cluster", ClusterSingletonID, string(accA), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsRoleAssignableInAccount(tc.role, tc.resourceType, tc.resourceID, tc.owningAccount)
			if got != tc.want {
				t.Fatalf("IsRoleAssignableInAccount(%s on %s:%s, owning=%s) = %v, want %v",
					tc.role.ID, tc.resourceType, tc.resourceID, tc.owningAccount, got, tc.want)
			}
		})
	}
}

func TestScopeGroupOf(t *testing.T) {
	if g := ScopeGroupOf(systemRole()); g != RoleScopeGroupSystem {
		t.Fatalf("system role scope group = %v, want SYSTEM", g)
	}
	if g := ScopeGroupOf(accountRole("acc00000000000000000A")); g != RoleScopeGroupAccount {
		t.Fatalf("account role scope group = %v, want ACCOUNT", g)
	}
	if g := ScopeGroupOf(projectRole("prj00000000000000000P")); g != RoleScopeGroupProject {
		t.Fatalf("project role scope group = %v, want PROJECT", g)
	}
}
