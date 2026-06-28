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
