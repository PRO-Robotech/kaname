// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// create_global_all_validation_test.go — RBAC explicit-model 2026 P5 (A-05 / A-05b /
// A-05c / Q-2). GLOBAL (=cluster scope) + selector all materialization policy,
// enforced SYNC (before the Operation) in Create.Execute:
//
//   - A-05  : GLOBAL + ARM_ANCHOR (selector all) on a NON cluster-admin role →
//             sync INVALID_ARGUMENT (per-object materialization cluster-wide for an
//             ordinary role is an anti-pattern; unbounded ledger + churn).
//   - A-05b : GLOBAL + names/labels on an ordinary role → OK (finite explicit set).
//   - A-05c : GLOBAL + all on the system cluster-admin role (*.*.*) → OK (served by
//             the D-9 cluster-relation short-circuit, not per-object).
//
// The role is read SYNC in Execute (reused for the validation) so the rejection
// happens before any Operation/tuple is created.

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// clusterScopeBinding builds a GLOBAL (cluster-scope) binding for role roleID.
func clusterScopeBinding(roleID, userID string) domain.AccessBinding {
	return domain.AccessBinding{
		RoleID:       domain.RoleID(roleID),
		ResourceType: "cluster",
		ResourceID:   domain.ClusterSingletonID,
		Scope:        domain.ScopeCluster,
		Subjects:     []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(userID)}},
	}
}

// TestCreate_A05_GlobalAll_NonClusterAdmin_Rejected — GLOBAL + selector all on an
// ordinary (non-*.*.*) system role → sync INVALID_ARGUMENT, no Operation.
func TestCreate_A05_GlobalAll_NonClusterAdmin_Rejected(t *testing.T) {
	const roleID = "rol_a05_anchor"
	repo := newABFakeRepo("usr_owner", "acc_x", "", roleID, "vpc_reader", nil)
	// system role, NOT cluster-admin: an ARM_ANCHOR rule over a concrete module.
	repo.setRoleRules(domain.Rules{
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}, // selector=all
	})
	opsRepo := newFakeOpsRepo()

	// caller passes grant-authority (recordingFGA.Check → true everywhere).
	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(clusterAdminCtx("usr_root"), clusterScopeBinding(roleID, "usr_target"))
	require.Error(t, err, "GLOBAL+all on a non-cluster-admin role must be rejected sync")
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"GLOBAL+all non-cluster-admin → INVALID_ARGUMENT (A-05)")
	// no Operation must have been created.
	require.Empty(t, opsRepo.ops, "no Operation on a sync-rejected Create")
}

// TestCreate_A05b_GlobalNames_NonClusterAdmin_OK — GLOBAL + names selector on an
// ordinary role is legal (finite per-object cluster-wide set).
func TestCreate_A05b_GlobalNames_NonClusterAdmin_OK(t *testing.T) {
	const roleID = "rol_a05b_names"
	repo := newABFakeRepo("usr_owner", "acc_x", "", roleID, "vpc_reader", nil)
	repo.setRoleRules(domain.Rules{
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"net1"}},
	})
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)

	op, err := uc.Execute(clusterAdminCtx("usr_root"), clusterScopeBinding(roleID, "usr_target"))
	require.NoError(t, err, "GLOBAL+names on an ordinary role is legal (A-05b)")
	require.NotNil(t, op)
}

// TestCreate_A05c_GlobalAll_ClusterAdminRole_OK — GLOBAL + all on the system
// cluster-admin role (*.*.*) is the single legal GLOBAL+all (A-05c / D-11a).
// The cluster-admin role is identified by its PINNED deterministic id
// (domain.ClusterAdminRoleID), NOT by the bare `*.*.*` wildcard shape — the
// `owner` role shares that shape (see TestCreate_A05_GlobalAll_OwnerRole_Rejected).
func TestCreate_A05c_GlobalAll_ClusterAdminRole_OK(t *testing.T) {
	roleID := domain.ClusterAdminRoleID
	repo := newABFakeRepo("usr_owner", "acc_x", "", roleID, "admin", nil)
	repo.setRoleRules(domain.Rules{
		{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}, // *.*.* superuser
	})
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)

	op, err := uc.Execute(clusterAdminCtx("usr_root"), clusterScopeBinding(roleID, "usr_target"))
	require.NoError(t, err, "GLOBAL+all on the cluster-admin role is legal (A-05c)")
	require.NotNil(t, op)
}

// TestCreate_A05_GlobalAll_OwnerRole_Rejected — #8 regression: the `owner` system
// role carries the SAME `*.*.*` wildcard shape as the cluster-admin role, so a
// shape-only IsClusterAdminRole() misclassified it as the cluster-admin GLOBAL+all
// exception and let an owner@GLOBAL binding slip past the A-05 reject. owner is NOT
// the cluster-admin role — a GLOBAL+all binding for it must be rejected (A-05).
func TestCreate_A05_GlobalAll_OwnerRole_Rejected(t *testing.T) {
	roleID := domain.OwnerRoleID
	repo := newABFakeRepo("usr_owner", "acc_x", "", roleID, "owner", nil)
	repo.setRoleRules(domain.OwnerRoleRules()) // [{module:*,resources:[*],verbs:[*]}] — same shape as cluster-admin
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(clusterAdminCtx("usr_root"), clusterScopeBinding(roleID, "usr_target"))
	require.Error(t, err, "GLOBAL+all on the owner role must be rejected (owner is not cluster-admin)")
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"owner@GLOBAL+all → INVALID_ARGUMENT (A-05, #8)")
	require.Empty(t, opsRepo.ops, "no Operation on a sync-rejected Create")
}
