// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// verb_bearing_account_project_test.go — RBAC explicit-model.
//
// Asserts the authzmap-layer contract that makes `account`/`project`
// verb-bearing resource types. The flip is the SINGLE source of truth the FGA
// emitter consults (access_binding/scope_grant_tuples.go gates `v_*` emission on
// authzmap.TypeHasVerbRelations(objType)); once these return true, a grant of
// `iam.account.get` materializes `account:<id> # v_get @ subj` — object-level
// access to the account itself, with NO cascade to its contents.
//
// This is the EXPAND half of expand→contract: the table flip is purely
// additive — it does NOT touch the viewer-tier emission, scope_grant carrier,
// or cascade (those are the contract step). It only marks the two hierarchy
// ancestors as also carrying the closed per-verb relation set, matching the
// canonical fga_model.fga which already defines v_* on both types.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// account/project are now verb-bearing (TypeHasVerbRelations == true).
func TestVerbBearing_AccountProjectAreVerbBearing(t *testing.T) {
	for _, ft := range []string{"account", "project"} {
		require.Truef(t, authzmap.TypeHasVerbRelations(ft),
			"TypeHasVerbRelations(%q) must be true (account/project are now verb-bearing)", ft)
	}
}

// Regression: every leaf resource type stays verb-bearing — the flip must not
// disturb the existing mappings (no loss of v_* emission anywhere).
func TestVerbBearing_LeafTypesStillVerbBearing(t *testing.T) {
	leaf := []string{
		"compute_instance", "compute_disk", "compute_image", "compute_snapshot",
		"compute_disk_placement_group", "compute_host_group", "compute_filesystem",
		"compute_gpu_cluster", "compute_placement_group", "compute_reserved_instance_pool",
		"compute_snapshot_schedule", "compute_host_type",
		"vpc_network", "vpc_subnet", "vpc_address", "vpc_security_group",
		"vpc_route_table", "vpc_gateway", "vpc_network_interface", "vpc_address_pool",
		"lb_network_load_balancer", "lb_target_group", "lb_listener",
		"iam_user", "iam_service_account", "iam_group", "iam_role",
		"iam_access_binding", "iam_condition",
	}
	for _, ft := range leaf {
		require.Truef(t, authzmap.TypeHasVerbRelations(ft),
			"regression: leaf type %q must remain verb-bearing", ft)
	}
}

// An unknown FGA type must never be reported as verb-bearing (closed set).
func TestVerbBearing_UnknownTypeNotVerbBearing(t *testing.T) {
	require.False(t, authzmap.TypeHasVerbRelations("definitely_not_a_type"))
}

// verb→relation resolution at the authzmap+domain seam:
// a rule on iam.account / iam.project with verbs [get,list] resolves to the
// closed per-verb relation set v_get/v_list, AND the type is verb-bearing so
// the emitter writes those v_* tuples (rather than SKIPping as a tier-only
// ancestor). This mirrors emitNamesRule's emitVerbs gate without coupling the
// test to the emitter package.
func TestVerbBearing_AccountProjectVerbToRelation(t *testing.T) {
	cases := []struct {
		name        string
		module, res string
		verbs       []string
		wantRels    []string // expected v_<verb> relations
	}{
		{"account get/list", "iam", "account", []string{"get", "list"}, []string{"v_get", "v_list"}},
		{"project get/update", "iam", "project", []string{"get", "update"}, []string{"v_get", "v_update"}},
		{"account wildcard verb → full closed set", "iam", "account", []string{"*"},
			[]string{"v_get", "v_list", "v_create", "v_update", "v_delete"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objType, ok := authzmap.ObjectType(tc.module, tc.res)
			require.True(t, ok, "ObjectType(%q,%q)", tc.module, tc.res)
			require.Truef(t, authzmap.TypeHasVerbRelations(objType),
				"%s must be verb-bearing for v_* emission", objType)

			resolved, _ := domain.ResolveVerbsAndTier(tc.verbs)
			var got []string
			for _, v := range resolved {
				if domain.IsClosedVerb(v) {
					got = append(got, "v_"+v)
				}
			}
			require.ElementsMatch(t, tc.wantRels, got,
				"%s verbs %v should resolve to %v", objType, tc.verbs, tc.wantRels)
		})
	}
}

// The per-verb v_* relations remain in the closed expandable-relation set
// (ExpandAccess "who can do <verb> on account:<id>" Check).
func TestVerbBearing_VRelationsAreExpandable(t *testing.T) {
	for _, r := range []string{"v_get", "v_list", "v_create", "v_update", "v_delete"} {
		require.Truef(t, authzmap.IsExpandableRelation(r),
			"%q must be an expandable relation (Check/ExpandAccess on verb-bearing account/project)", r)
	}
}
