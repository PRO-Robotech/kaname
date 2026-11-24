// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestWildcardBindingEmission_ClusterRulesDoNotMintShortcut(t *testing.T) {
	binding := domain.AccessBinding{ID: "wildcard-binding", ResourceType: "cluster", ResourceID: domain.ClusterSingletonID}
	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: "reader"}
	for _, verbs := range [][]string{{"*"}, {"get", "list"}, {"get", "update"}} {
		role := domain.Role{
			Rules:       domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: verbs}},
			Permissions: domain.Permissions{"*.*.*.*"},
		}
		got := buildBindingTuples(binding, subject, role)
		if len(got) != 1 || got[0].User != "cluster:"+domain.ClusterSingletonID || got[0].Relation != "cluster" || got[0].Object != "iam_access_binding:"+string(binding.ID) {
			t.Fatalf("rules branch must only emit structural parent, verbs=%v tuples=%+v", verbs, got)
		}
		selectors := role.Rules.MaterializingSelectorsInScope(domain.ScopeCluster)
		if len(selectors) != 1 || len(selectors[0].ObjectTypes) != 0 {
			t.Fatalf("cluster wildcard materialized: %+v", selectors)
		}
		projection := role.Rules[0].MaterializedTypeProjection(domain.ScopeCluster)
		if !projection.WildcardSuppressed || projection.UsesStaticRegistry() {
			t.Fatalf("suppression not explicit: %+v", projection)
		}
	}
}

func TestWildcardBindingEmission_LegacyUsesActualDirectClusterRelations(t *testing.T) {
	binding := domain.AccessBinding{ID: "legacy-binding", ResourceType: "cluster", ResourceID: domain.ClusterSingletonID}
	subject := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "reader"}
	for _, tc := range []struct {
		name        string
		permissions []string
		want        []string
	}{
		{name: "full-wildcard-admin", permissions: []string{"*.*.*.*"}, want: []string{"system_admin"}},
		{name: "type-wildcard-read-only", permissions: []string{"*.*.*.get"}, want: []string{"system_viewer"}},
		{name: "write-maps-to-direct-admin", permissions: []string{"vpc.network.*.update"}, want: []string{"system_admin"}},
		{name: "empty-role-only-parent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := domain.Role{Permissions: toPermissions(tc.permissions)}
			var got []string
			for _, tuple := range buildBindingTuples(binding, subject, role) {
				if tuple.Object == "cluster:"+domain.ClusterSingletonID {
					if tuple.User != "service_account:reader" {
						t.Fatalf("recipient type lost: %+v", tuple)
					}
					got = append(got, tuple.Relation)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("actual producer=%v want=%v", got, tc.want)
			}
			var shared []string
			for _, r := range authzmap.BindingScopeRelations("cluster", role) {
				shared = append(shared, string(r))
			}
			if !slices.Equal(got, shared) {
				t.Fatalf("shared legacy producer diverged: %v / %v", got, shared)
			}
		})
	}
}
