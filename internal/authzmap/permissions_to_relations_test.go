// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// permissions_to_relations_test.go — unit tests for
// authzmap.PermissionsToRelations (RBAC v2).
//
// Grammar is strict 4-segment `module.resource.resourceName.verb`. Tests
// here exercise the tier-collapsing summariser; the closed
// (module,resource)→fga_type table is covered in fga_types_test.go.
package authzmap_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

func asStrings(rs []authzmap.Relation) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	sort.Strings(out)
	return out
}

func TestPermissionsToRelations_MAP_01_EmptyFallsBackToViewer(t *testing.T) {
	require.Equal(t, []string{"viewer"}, asStrings(authzmap.PermissionsToRelations(nil)))
	require.Equal(t, []string{"viewer"}, asStrings(authzmap.PermissionsToRelations([]string{})))
}

func TestPermissionsToRelations_MAP_02_ReadOnlyTierIsViewer(t *testing.T) {
	cases := [][]string{
		{"vpc.networks.*.get"},
		{"compute.instances.*.list"},
		{"iam.roles.*.view"},
		{"vpc.networks.*.watch"},
		{"vpc.networks.*.get", "compute.instances.*.list", "iam.roles.*.view"},
	}
	for _, perms := range cases {
		got := asStrings(authzmap.PermissionsToRelations(perms))
		require.Equal(t, []string{"viewer"}, got, "read-only verbs %v must map to viewer", perms)
	}
}

func TestPermissionsToRelations_MAP_03_MixedReadAndWriteIsEditor(t *testing.T) {
	cases := [][]string{
		{"vpc.networks.*.get", "vpc.networks.*.create"},
		{"iam.accessBindings.*.create"},
		{"compute.instances.*.update"},
		{"compute.instances.*.delete"},
		{"vpc.networks.*.write"},
	}
	for _, perms := range cases {
		got := asStrings(authzmap.PermissionsToRelations(perms))
		require.Equal(t, []string{"editor"}, got, "write-class verbs %v must map to editor", perms)
	}
}

func TestPermissionsToRelations_MAP_04_WildcardOrAdminIsAdmin(t *testing.T) {
	cases := [][]string{
		{"vpc.*.*.*"},
		{"iam.accessBindings.*.admin"},
		{"vpc.networks.*.get", "vpc.*.*.*"},
		{"*.*.*.*"},
	}
	for _, perms := range cases {
		got := asStrings(authzmap.PermissionsToRelations(perms))
		require.Equal(t, []string{"admin"}, got, "admin/wildcard %v must map to admin", perms)
	}
}

// TestPermissionsToRelations_3SegLegacyRejectedAsViewer — 3-segment legacy
// strings hit the parser fallback (least privilege). The migration 0005
// promotes them automatically; any 3-seg string seen at runtime is a bug
// to track, but the runtime stays safe (deny-by-default).
func TestPermissionsToRelations_3SegLegacyRejectedAsViewer(t *testing.T) {
	got := asStrings(authzmap.PermissionsToRelations([]string{"compute.instance.read"}))
	require.Equal(t, []string{"viewer"}, got, "3-seg legacy → least-privilege viewer")
}

func TestPermissionsToRelations_Deduplicates(t *testing.T) {
	got := asStrings(authzmap.PermissionsToRelations(
		[]string{"vpc.networks.*.get", "vpc.networks.*.get", "compute.instances.*.list"}))
	require.Equal(t, []string{"viewer"}, got)
}

func TestPermissionsToRelations_NLB_WriteVerbs(t *testing.T) {
	writeVerbs := []string{
		"loadbalancer.networkLoadBalancers.*.start",
		"loadbalancer.networkLoadBalancers.*.stop",
		"loadbalancer.networkLoadBalancers.*.move",
		"loadbalancer.targetGroups.*.addTargets",
		"loadbalancer.targetGroups.*.removeTargets",
		"loadbalancer.networkLoadBalancers.*.attachTargetGroup",
		"loadbalancer.networkLoadBalancers.*.detachTargetGroup",
		"loadbalancer.networkLoadBalancers.*.enableZones",
		"loadbalancer.networkLoadBalancers.*.disableZones",
		"loadbalancer.networkLoadBalancers.*.addListener",
		"loadbalancer.networkLoadBalancers.*.removeListener",
	}
	for _, p := range writeVerbs {
		got := asStrings(authzmap.PermissionsToRelations([]string{p}))
		require.Equal(t, []string{"editor"}, got, "NLB write %q must map to editor", p)
	}
}

func TestPermissionsToRelations_NLB_ReadVerbs(t *testing.T) {
	readVerbs := []string{
		"loadbalancer.networkLoadBalancers.*.getTargetStates",
		"loadbalancer.networkLoadBalancers.*.listOperations",
		"loadbalancer.targetGroups.*.listOperations",
		"loadbalancer.listeners.*.listOperations",
	}
	for _, p := range readVerbs {
		got := asStrings(authzmap.PermissionsToRelations([]string{p}))
		require.Equal(t, []string{"viewer"}, got, "NLB read %q must map to viewer", p)
	}
}
