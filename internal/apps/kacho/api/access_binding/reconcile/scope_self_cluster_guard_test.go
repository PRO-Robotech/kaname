// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// scope_self_cluster_guard_test.go — RBAC explicit-model 2026 P5 (Q-2 / D-9 guard).
//
// The cluster scope-self path is INTENTIONALLY dead: cluster super-admin is served
// by the D-9 flat short-circuit (cluster:cluster_kacho_root#system_admin), NOT by a
// per-object scope-self tuple. scopeSelfMember gates on fgaObjectType("iam.cluster")
// which is NOT in the objectTypes registry, so a cluster scope NEVER materializes a
// per-object scope-self member.
//
// This guard test FIXES that invariant: should a future change add an iam.cluster
// FGA type (re-enabling the path), this test fails — forcing an explicit decision
// so cluster super-admin does not silently regress to per-object materialization
// (which would re-introduce the per-object-on-cluster anti-pattern Q-2/D-9 forbid).

import "testing"

func TestScopeSelfMember_Cluster_EmitsNothing(t *testing.T) {
	// A full superuser verb-set on the cluster scope must STILL produce no
	// scope-self member — cluster is owned by the D-9 short-circuit.
	_, ok := scopeSelfMember("user:usr_root", "cluster", "cluster_kacho_root",
		[]string{"get", "list", "create", "update", "delete"})
	if ok {
		t.Fatalf("cluster scope-self must NOT materialize a per-object member (D-9 short-circuit owns cluster super-admin)")
	}
}

func TestScopeSelfMember_AccountProject_StillEmit(t *testing.T) {
	// Sanity: the live hierarchy scopes (account/project) DO still materialize a
	// scope-self member — the guard above is specific to cluster, not a blanket
	// disablement.
	if _, ok := scopeSelfMember("user:usr_a", "account", "acc_1", []string{"get"}); !ok {
		t.Fatalf("account scope-self must still materialize a member")
	}
	if _, ok := scopeSelfMember("user:usr_a", "project", "prj_1", []string{"get"}); !ok {
		t.Fatalf("project scope-self must still materialize a member")
	}
}
