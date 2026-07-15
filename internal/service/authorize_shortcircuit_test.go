// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authorize_shortcircuit_test.go — RBAC explicit-model 2026 P5 (D-9 / D-02 / D-15).
//
// authorize_service.Check (public AuthZ) AND CheckRelation (InternalIAMService.Check)
// apply a cluster-admin short-circuit: a subject holding the flat
// `cluster:cluster_kacho_root#system_admin` relation is ALLOWED on ANY resource
// without a per-object tuple (D-9 is a flat super-gate, not a `<rel> from cluster`
// cascade).
//
// ORDERING (#3, perf): the per-object FGA resolve runs FIRST; the cluster-admin
// short-circuit is the FALLBACK on a per-object DENY. The common allow case costs
// exactly ONE FGA round-trip (no redundant cluster-admin Check); only a denied
// request pays the second round-trip to test cluster-admin authority. Correctness
// and fail-closed are preserved — a cluster-admin is still allowed on everything,
// just resolved second.
package service

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// scClusterChecker — a RelationChecker-shaped fake: allows the flat cluster
// super-admin relation for the configured subjects, denies everything else.
type scClusterChecker struct {
	admins      map[string]bool
	gotRelation string
	gotObject   string
	calls       int // number of cluster-admin short-circuit Checks issued
}

func (c *scClusterChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	c.calls++
	c.gotRelation, c.gotObject = relation, object
	return c.admins[subject], nil
}

func TestAuthorize_Check_ClusterAdminShortCircuit(t *testing.T) {
	// FGA grants NOTHING (checkResp:false) — only the short-circuit can allow.
	fga := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_root": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_root",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "compute.instances.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("cluster-admin must be allowed via short-circuit (D-02); deny=%v", res.DenyReasons)
	}
	// #3: per-object resolve runs FIRST (denies here), then the cluster-admin
	// fallback allows → exactly ONE FGA Check + ONE short-circuit Check.
	if fga.checkCalls != 1 {
		t.Fatalf("per-object FGA resolve must run first (1 call); got %d", fga.checkCalls)
	}
	if cl.calls != 1 {
		t.Fatalf("cluster-admin fallback must run once on deny; got %d", cl.calls)
	}
	// Flat super-gate: relation/object are the singleton cluster tuple.
	if cl.gotRelation != "system_admin" || cl.gotObject != "cluster:"+domain.ClusterSingletonID {
		t.Fatalf("short-circuit must Check the flat cluster relation, got %q on %q", cl.gotRelation, cl.gotObject)
	}
}

func TestAuthorize_Check_NonClusterAdmin_NoShortCircuit(t *testing.T) {
	fga := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{}} // nobody is cluster-admin
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_other",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "compute.instances.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("non-cluster-admin must NOT short-circuit (resolves to FGA deny)")
	}
	if fga.checkCalls != 1 {
		t.Fatalf("non-cluster-admin must fall through to the FGA Check; got %d calls", fga.checkCalls)
	}
}

func TestAuthorize_CheckRelation_ClusterAdminShortCircuit(t *testing.T) {
	fga := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_root": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_root",
		Relation: "v_delete",
		Object:   "vpc_network:vpcn_x",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("cluster-admin must be allowed via CheckRelation short-circuit (КФ-2)")
	}
	// #3: per-object resolve first (deny), then cluster-admin fallback → 1 FGA + 1 SC.
	if fga.checkCalls != 1 {
		t.Fatalf("CheckRelation per-object resolve must run first (1 call); got %d", fga.checkCalls)
	}
	if cl.calls != 1 {
		t.Fatalf("CheckRelation cluster-admin fallback must run once on deny; got %d", cl.calls)
	}
}

// TestAuthorize_Check_Allow_NoClusterAdminRoundTrip — #3: the common allow case
// (FGA grants the per-object relation) must NOT issue the cluster-admin
// short-circuit Check. Exactly ONE FGA round-trip; zero cluster-admin Checks.
func TestAuthorize_Check_Allow_NoClusterAdminRoundTrip(t *testing.T) {
	fga := &mockRelations{checkResp: true} // per-object FGA allows
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_x": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_x",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "compute.instances.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("per-object allow must be allowed")
	}
	if fga.checkCalls != 1 {
		t.Fatalf("allow path must do exactly 1 FGA Check; got %d", fga.checkCalls)
	}
	if cl.calls != 0 {
		t.Fatalf("#3: allow path must NOT issue the cluster-admin short-circuit; got %d", cl.calls)
	}
}

// TestAuthorize_BatchCheck_ClusterAdmin_SingleShortCircuit — #3: a 100-item batch
// from a single cluster-admin subject (all per-object denied → all resolved via the
// cluster-admin fallback) must issue the cluster-admin short-circuit Check AT MOST
// ONCE for the subject (memoized per-batch), not once per item.
func TestAuthorize_BatchCheck_ClusterAdmin_SingleShortCircuit(t *testing.T) {
	fga := &mockRelations{checkResp: false} // every per-object resolve denies
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_root": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           fga,
		ModelID:             "m1",
		ClusterAdminChecker: cl,
	})

	reqs := make([]CheckRequest, 100)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:  "user:usr_root",
			Resource: ResourceRef{Type: "compute_instance", ID: "inst_x"},
			Action:   "compute.instances.delete",
		}
	}
	results, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for i, r := range results {
		if !r.Allowed {
			t.Fatalf("item %d: cluster-admin must be allowed via fallback; deny=%v", i, r.DenyReasons)
		}
	}
	if cl.calls > 1 {
		t.Fatalf("#3: cluster-admin short-circuit must be memoized per-batch (≤1 call); got %d", cl.calls)
	}
}

// TestAuthorize_Check_NilClusterChecker_NoShortCircuit — backward-compat: an
// unwired ClusterAdminChecker (nil) never short-circuits; the ordinary FGA path
// is the sole decision (fail-closed, no panic).
func TestAuthorize_Check_NilClusterChecker_NoShortCircuit(t *testing.T) {
	fga := &mockRelations{checkResp: true} // FGA itself allows
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: fga, ModelID: "m1"})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_root",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "compute.instances.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("nil cluster-checker must defer to FGA (which allowed)")
	}
}
