// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_cluster_admin_test.go — RBAC explicit-model 2026 P5 (A-05 / A-05c / D-9 /
// D-11a). Unit tests for the two domain predicates that decide GLOBAL+all
// legality at AccessBinding.Create:
//
//   - Rules.HasAnchorRule()    — does the role carry a selector=all (ARM_ANCHOR)
//     rule? (A-05 / A-05b: a non-cluster-admin role on the cluster/GLOBAL scope
//     is legal ONLY with names/labels; an ARM_ANCHOR rule is the rejected case.)
//   - Role.IsClusterAdminRole() — is the role the system superuser `*.*.*`
//     (modules:["*"], resources:["*"], verbs:["*"], selector:all)? (A-05c /
//     D-11a: the SINGLE role for which GLOBAL+all is legal — served by the D-9
//     cluster-relation short-circuit, not per-object materialization.)

import "testing"

func TestRules_HasAnchorRule(t *testing.T) {
	tests := []struct {
		name  string
		rules Rules
		want  bool
	}{
		{
			name:  "single anchor rule (selector all)",
			rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}},
			want:  true,
		},
		{
			name:  "names-only rule (no anchor)",
			rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"net1"}}},
			want:  false,
		},
		{
			name:  "labels-only rule (no anchor)",
			rules: Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}}},
			want:  false,
		},
		{
			name: "mixed: names + anchor → has anchor",
			rules: Rules{
				{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"net1"}},
				{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}},
			},
			want: true,
		},
		{
			name:  "superuser *.*.* is an anchor rule",
			rules: Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}},
			want:  true,
		},
		{
			name:  "empty rules",
			rules: nil,
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rules.HasAnchorRule(); got != tt.want {
				t.Fatalf("HasAnchorRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRole_IsClusterAdminRole(t *testing.T) {
	// The cluster-admin role is identified by its PINNED deterministic id
	// (ClusterAdminRoleID = 'admin' role / SystemAdminRoleID = kacho-system.admin),
	// gated by is_system — NOT by the bare `*.*.*` wildcard shape, which the `owner`
	// role ALSO carries (#8). Matching by shape alone misclassified owner.
	clusterAdmin := Role{
		ID:       RoleID(ClusterAdminRoleID),
		IsSystem: true,
		Rules:    Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}},
	}
	if !clusterAdmin.IsClusterAdminRole() {
		t.Fatalf("pinned cluster-admin (`admin`) role must be recognised as cluster-admin")
	}

	// kacho-system.admin (the hand-rolled deterministic id) is also a cluster-admin
	// superuser role.
	sysAdmin := Role{
		ID:       RoleID(SystemAdminRoleID),
		IsSystem: true,
		Rules:    Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}},
	}
	if !sysAdmin.IsClusterAdminRole() {
		t.Fatalf("pinned kacho-system.admin role must be recognised as cluster-admin")
	}

	// #8 regression: the `owner` system role carries the SAME `*.*.*` shape but is
	// NOT the cluster-admin role — it must NOT be treated as the GLOBAL+all
	// exception.
	owner := Role{
		ID:       RoleID(OwnerRoleID),
		IsSystem: true,
		Rules:    OwnerRoleRules(),
	}
	if owner.IsClusterAdminRole() {
		t.Fatalf("owner role (`*.*.*` shape) must NOT be cluster-admin (#8)")
	}

	// system role with the cluster-admin id but degraded to read-only `*.*.{get,list}`
	// is a defensive shape-check belt: the id matches but the rule is no longer the
	// full superuser → NOT cluster-admin (a tampered seed must not silently confer
	// the GLOBAL+all exception).
	systemRead := Role{
		ID:       RoleID(ClusterAdminRoleID),
		IsSystem: true,
		Rules:    Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"get", "list"}}},
	}
	if systemRead.IsClusterAdminRole() {
		t.Fatalf("cluster-admin id with *.*.{get,list} must NOT be cluster-admin (verbs not *)")
	}

	// concrete-module system role (wrong id, concrete module) → NOT cluster-admin.
	systemScoped := Role{
		ID:       "rol_some_scoped",
		IsSystem: true,
		Rules:    Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}},
	}
	if systemScoped.IsClusterAdminRole() {
		t.Fatalf("concrete-module system role must NOT be cluster-admin")
	}

	// non-system role even with the cluster-admin id → NOT cluster-admin (custom
	// roles cannot masquerade; the predicate is system-gated).
	customWildcard := Role{
		ID:       RoleID(ClusterAdminRoleID),
		IsSystem: false,
		Rules:    Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}},
	}
	if customWildcard.IsClusterAdminRole() {
		t.Fatalf("non-system role must NOT be cluster-admin (system-gated)")
	}
}
