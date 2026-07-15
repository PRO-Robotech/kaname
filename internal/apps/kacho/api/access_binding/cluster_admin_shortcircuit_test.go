// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// cluster_admin_shortcircuit_test.go — RBAC explicit-model 2026 P5 (D-06 / D-07 /
// КФ-2). The cluster-admin short-circuit must apply to WRITE-authz, not only to
// authorize_service.Check: after the access-cascade is contracted, a cluster-admin
// no longer holds an account-tier admin-tuple, so requireGrantAuthority must
// recognise cluster-admin via the flat `cluster:...#system_admin` relation and let
// them grant on a foreign account (D-06) / manage binding objects (D-07).

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// scopedFGA — a RelationStore whose Check answers per (relation, object). It lets
// a test grant ONLY the flat cluster super-admin relation (and nothing on the
// account-tier) so the short-circuit is the ONLY path that can authorize.
type scopedFGA struct {
	recordingFGA
	allow         map[string]bool // "<relation>|<object>" → allowed
	sysAdminCheck int             // count of cluster-admin (system_admin@cluster) Checks
}

func (s *scopedFGA) Check(_ context.Context, _, relation, object string) (bool, error) {
	if relation == "system_admin" && object == "cluster:"+domain.ClusterSingletonID {
		s.sysAdminCheck++
	}
	return s.allow[relation+"|"+object], nil
}

func clusterAdminCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "user"})
}

// onlyClusterAdmin grants the flat super-admin relation and NOTHING else (no
// account-tier admin tuple) — the post-contract cluster-admin shape (D-9 КФ-2).
func onlyClusterAdmin() *scopedFGA {
	return &scopedFGA{allow: map[string]bool{
		"system_admin|cluster:" + domain.ClusterSingletonID: true,
	}}
}

// TestRequireGrantAuthority_D06_ClusterAdmin_ForeignAccount — a cluster-admin who
// is NEITHER the account owner NOR holds an account-tier admin-tuple on acc_foreign
// must pass requireGrantAuthority via the cluster-admin short-circuit.
func TestRequireGrantAuthority_D06_ClusterAdmin_ForeignAccount(t *testing.T) {
	// Owner of acc_foreign is usr_owner; caller is usr_root (cluster-admin, not owner).
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	var rs clients.RelationStore = onlyClusterAdmin()

	err := requireGrantAuthority(clusterAdminCtx("usr_root"), repo, rs, "account", "acc_foreign")
	if err != nil {
		t.Fatalf("cluster-admin must pass requireGrantAuthority on a foreign account (D-06): %v", err)
	}
}

// TestRequireGrantAuthority_D07_ClusterAdmin_BindingObject — a cluster-admin must
// retain authority over iam_access_binding objects (List/Get/Delete) through the
// short-circuit even with no materialized tuple on the binding.
func TestRequireGrantAuthority_D07_ClusterAdmin_BindingObject(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_x", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	var rs clients.RelationStore = onlyClusterAdmin()

	// requireGrantAuthority on a non-hierarchy object (iam_access_binding) skips the
	// owner-path entirely → only the short-circuit / FGA-admin path can authorize.
	err := requireGrantAuthority(clusterAdminCtx("usr_root"), repo, rs, "iam_access_binding", "acb_1")
	if err != nil {
		t.Fatalf("cluster-admin must retain authority over binding objects (D-07): %v", err)
	}
}

// TestRequireGrantAuthority_NonClusterAdmin_ForeignAccount_Denied — the negative:
// a caller who is NOT the owner and holds neither account-tier admin nor the
// cluster super-admin relation is denied.
func TestRequireGrantAuthority_NonClusterAdmin_ForeignAccount_Denied(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	// grants nothing at all.
	var rs clients.RelationStore = &scopedFGA{allow: map[string]bool{}}

	err := requireGrantAuthority(clusterAdminCtx("usr_nobody"), repo, rs, "account", "acc_foreign")
	if err == nil {
		t.Fatalf("non-cluster-admin non-owner must be denied on a foreign account")
	}
}

// TestRequireGrantAuthority_NonClusterAdmin_SingleSysAdminCheck — #9: a single
// requireGrantAuthority pass must issue AT MOST ONE cluster-admin (system_admin@
// cluster) FGA Check. The pre-fix code did it twice (Path 0 + the redundant copy
// inside fgaHoldsAdmin reached on the cluster-admin miss). Correctness is preserved
// (deny either way) — this pins the round-trip dedup.
func TestRequireGrantAuthority_NonClusterAdmin_SingleSysAdminCheck(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	rs := &scopedFGA{allow: map[string]bool{}} // grants nothing

	err := requireGrantAuthority(clusterAdminCtx("usr_nobody"), repo, rs, "account", "acc_foreign")
	if err == nil {
		t.Fatalf("non-cluster-admin non-owner must be denied")
	}
	if rs.sysAdminCheck != 1 {
		t.Fatalf("requireGrantAuthority issued %d cluster-admin Checks, want exactly 1 (#9 dedup)", rs.sysAdminCheck)
	}
}
