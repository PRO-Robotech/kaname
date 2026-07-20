// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_types_test.go — unit tests for the closed (module, resource)
// → fga_object_type map.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

func TestObjectType_KnownPairs(t *testing.T) {
	cases := []struct{ module, resource, want string }{
		{"compute", "instance", "compute_instance"},
		{"compute", "disk", "compute_disk"},
		{"compute", "image", "compute_image"},
		{"compute", "snapshot", "compute_snapshot"},
		{"compute", "diskPlacementGroup", "compute_disk_placement_group"},
		{"compute", "hostGroup", "compute_host_group"},
		{"compute", "filesystem", "compute_filesystem"},
		{"compute", "gpuCluster", "compute_gpu_cluster"},
		{"compute", "placementGroup", "compute_placement_group"},
		{"compute", "reservedInstancePool", "compute_reserved_instance_pool"},
		{"compute", "snapshotSchedule", "compute_snapshot_schedule"},
		{"compute", "hostType", "compute_host_type"},
		{"vpc", "network", "vpc_network"},
		{"vpc", "subnet", "vpc_subnet"},
		{"vpc", "address", "vpc_address"},
		{"vpc", "securityGroup", "vpc_security_group"},
		{"vpc", "routeTable", "vpc_route_table"},
		{"vpc", "gateway", "vpc_gateway"},
		{"vpc", "networkInterface", "vpc_network_interface"},
		{"vpc", "addressPool", "vpc_address_pool"},
		{"loadbalancer", "networkLoadBalancers", "nlb_network_load_balancer"},
		{"loadbalancer", "targetGroups", "nlb_target_group"},
		{"loadbalancer", "listeners", "nlb_listener"},
		{"iam", "account", "account"},
		{"iam", "project", "project"},
		{"iam", "user", "iam_user"},
		{"iam", "serviceAccount", "iam_service_account"},
		{"iam", "group", "iam_group"},
		{"iam", "role", "iam_role"},
		{"iam", "accessBinding", "iam_access_binding"},
		{"iam", "condition", "iam_condition"},
	}
	for _, tc := range cases {
		got, ok := authzmap.ObjectType(tc.module, tc.resource)
		require.True(t, ok, "ObjectType(%q,%q) ok=false; want true", tc.module, tc.resource)
		require.Equal(t, tc.want, got, "ObjectType(%q,%q) mismatch", tc.module, tc.resource)
	}
}

func TestObjectType_UnknownReturnsEmptyFalse(t *testing.T) {
	got, ok := authzmap.ObjectType("unknown", "thing")
	require.False(t, ok)
	require.Equal(t, "", got)
}

func TestObjectType_WildcardSegmentReturnsFalse(t *testing.T) {
	// `*.*` is not a concrete (module,resource) pair; resolution falls back
	// to scope anchor.
	got, ok := authzmap.ObjectType("*", "*")
	require.False(t, ok)
	require.Equal(t, "", got)
}
