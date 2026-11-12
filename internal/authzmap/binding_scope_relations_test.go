// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestBindingScopeRelations_ExactWriterBranchAndAccountCap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		role  domain.Role
		want  []Relation
	}{
		{name: "empty-role-does-not-use-viewer-fallback", scope: "cluster"},
		{name: "missing-scope", role: domain.Role{Permissions: domain.Permissions{"*.*.*.*"}}},
		{name: "rules-shadow-compiled-permissions", scope: "cluster", role: domain.Role{Rules: domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}, Permissions: domain.Permissions{"*.*.*.*"}}},
		{name: "even-empty-rule-selects-rules-branch", scope: "cluster", role: domain.Role{Rules: domain.Rules{{}}, Permissions: domain.Permissions{"*.*.*.*"}}},
		{name: "legacy-cluster-admin", scope: "cluster", role: domain.Role{Permissions: domain.Permissions{"*.*.*.*"}}, want: []Relation{"system_admin"}},
		{name: "legacy-cluster-viewer", scope: "cluster", role: domain.Role{Permissions: domain.Permissions{"*.*.*.get"}}, want: []Relation{"system_viewer"}},
		{name: "legacy-cluster-editor-is-direct-admin", scope: "cluster", role: domain.Role{Permissions: domain.Permissions{"vpc.network.*.update"}}, want: []Relation{"system_admin"}},
		{name: "legacy-project-keeps-admin", scope: "project", role: domain.Role{Permissions: domain.Permissions{"vpc.network.*.*"}}, want: []Relation{"admin"}},
		{name: "account-unrelated-admin-capped", scope: "account", role: domain.Role{Permissions: domain.Permissions{"vpc.network.*.*"}}, want: []Relation{"editor"}},
		{name: "account-own-read-excludes-unrelated-admin", scope: "account", role: domain.Role{Permissions: domain.Permissions{"iam.account.*.get", "vpc.network.*.*"}}, want: []Relation{"viewer"}},
		{name: "account-own-wildcard-admin", scope: "account", role: domain.Role{Permissions: domain.Permissions{"iam.account.*.*"}}, want: []Relation{"admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BindingScopeRelations(tc.scope, tc.role); !slices.Equal(got, tc.want) {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}
