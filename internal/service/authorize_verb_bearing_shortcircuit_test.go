// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// authorize_verb_bearing_shortcircuit_test.go — Design-B (flat-authz verb-bearing
// complete) acceptance VBC-08-CA / VBC-09-CA. The cluster-admin short-circuit
// (D-9 / F-6) MUST keep working after enforcement is decoupled from tier and
// resolves on the v_* relations. A cluster-admin with NO per-object tuple on a
// foreign object is ALLOWED via the short-circuit when the gate Check resolves a
// v_get/v_list/v_update/v_delete (or the create-child `editor`) relation that the
// per-object FGA denies.

import (
	"context"
	"testing"
)

// TestAuthorize_VBC08_ClusterAdminForeignGet_ShortCircuit — VBC-08-CA: a
// cluster-admin GET of a leaf object in a foreign account (no per-object v_get
// tuple) short-circuits to ALLOW. Public Check path (action → v_get via catalog
// required_relation forwarded by the gateway).
func TestAuthorize_VBC08_ClusterAdminForeignGet_ShortCircuit(t *testing.T) {
	fga := &mockRelations{checkResp: false} // no per-object tuple → FGA denies
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_ca": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	// gateway forwards required_relation=v_get (catalog iam.users.get → v_get).
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:          "user:usr_ca",
		Resource:         ResourceRef{Type: "iam_user", ID: "usr_foreign"},
		Action:           "iam.users.get",
		RequiredRelation: "v_get",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("VBC-08-CA: cluster-admin foreign GET must short-circuit ALLOW on v_get DENY; deny=%v", res.DenyReasons)
	}
	// Per-object resolve runs first (v_get deny), short-circuit fallback allows.
	if fga.checkCalls != 1 {
		t.Fatalf("VBC-08-CA: per-object v_get resolve must run first (1 call); got %d", fga.checkCalls)
	}
	if cl.calls != 1 {
		t.Fatalf("VBC-08-CA: cluster-admin fallback must run once on v_get deny; got %d", cl.calls)
	}
	if cl.gotRelation != "system_admin" {
		t.Fatalf("VBC-08-CA: short-circuit must Check the flat cluster relation; got %q", cl.gotRelation)
	}
}

// TestAuthorize_VBC08_ClusterAdminForeignGet_ConsumerPlan — VBC-08-CA consumer
// plan: the InternalIAMService.Check (CheckRelation) path forwards an
// already-resolved v_get relation from the consumer permission_map; the
// cluster-admin short-circuit must allow on the per-object DENY.
func TestAuthorize_VBC08_ClusterAdminForeignGet_ConsumerPlan(t *testing.T) {
	fga := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_ca": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_ca",
		Relation: "v_get", // vpc per-RPC gate resolves Get → v_get
		Object:   "vpc_network:vpcn_foreign",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("VBC-08-CA consumer: cluster-admin foreign v_get must short-circuit ALLOW")
	}
}

// TestAuthorize_VBC09_ClusterAdminForeignListCrudCreate — VBC-09-CA: a
// cluster-admin short-circuits LIST (v_list), CRUD (v_delete) and create-child
// (editor) in a foreign account; a non-cluster-admin with no tuple is denied on
// all three.
func TestAuthorize_VBC09_ClusterAdminForeignListCrudCreate(t *testing.T) {
	for _, rel := range []string{"v_list", "v_delete", "editor"} {
		t.Run("cluster_admin_allow_"+rel, func(t *testing.T) {
			fga := &mockRelations{checkResp: false}
			cl := &scClusterChecker{admins: map[string]bool{"user:usr_ca": true}}
			svc := NewAuthorizeService(AuthorizeServiceConfig{
				Relations: fga, ModelID: "m1", ClusterAdminChecker: cl,
			})
			res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
				Subject: "user:usr_ca", Relation: rel, Object: "compute_instance:inst_foreign",
			})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.Allowed {
				t.Fatalf("VBC-09-CA: cluster-admin must short-circuit ALLOW on %q DENY", rel)
			}
		})
		t.Run("non_cluster_admin_deny_"+rel, func(t *testing.T) {
			fga := &mockRelations{checkResp: false}
			cl := &scClusterChecker{admins: map[string]bool{}} // nobody
			svc := NewAuthorizeService(AuthorizeServiceConfig{
				Relations: fga, ModelID: "m1", ClusterAdminChecker: cl,
			})
			res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
				Subject: "user:usr_x", Relation: rel, Object: "compute_instance:inst_foreign",
			})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if res.Allowed {
				t.Fatalf("VBC-09-CA: non-cluster-admin must be DENIED on %q (short-circuit strictly cluster-admin)", rel)
			}
		})
	}
}
