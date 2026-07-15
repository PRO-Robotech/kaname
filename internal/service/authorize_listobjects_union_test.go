// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// authorize_listobjects_union_test.go — Design-B (flat-authz verb-bearing complete)
// acceptance VBC-03 (selector-without-content centralized in iam). For a list/get
// action on a verb-bearing type, AuthorizeService.ListObjects unions the principal's
// `viewer`-set with the `v_list`-set (viewer ∪ v_list, deduplicated) so a consumer
// (vpc/compute/nlb) that issues ONE ListObjects call with ONE action sees both:
//   - objects it holds the viewer tier on (broader access), AND
//   - objects granted ONLY v_list via a names/labels selector (see-in-selector-
//     without-content, D-6a).
// This centralizes the union account/project already do in their use-case layer so
// the consumers do not each re-implement it.
//
// RED until ListObjects performs the viewer ∪ v_list union: today it resolves a
// SINGLE relation (resolveActionToRelation(list)→viewer), so a v_list-only object
// is invisible in the consumer's list.

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// unionRelations — relation-aware ListObjects fake: returns a distinct id set per
// (relation) so the union (viewer ∪ v_list) and dedup are observable. CheckWithContext
// is inert (ListObjects path only).
type unionRelations struct {
	byRelation map[string][]string
	listErr    error
	listCalls  map[string]int
}

func newUnionRelations() *unionRelations {
	return &unionRelations{byRelation: map[string][]string{}, listCalls: map[string]int{}}
}

func (m *unionRelations) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return false, nil
}
func (m *unionRelations) ListObjects(_ context.Context, _ /*subject*/, relation, _ /*objectType*/ string, _ map[string]any, _ int) ([]string, error) {
	m.listCalls[relation]++
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.byRelation[relation], nil
}
func (m *unionRelations) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", nil
}
func (m *unionRelations) Expand(context.Context, string, string, string) (*clients.ExpandTree, error) {
	return nil, nil //nolint:nilnil // inert in this test
}
func (m *unionRelations) ReadTuples(context.Context, string, string, string, int, string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

// TestListObjects_VBC03_VerbBearing_ViewerVListUnion — verb-bearing list action
// unions viewer ∪ v_list (dedup). A v_list-only object IS returned.
func TestListObjects_VBC03_VerbBearing_ViewerVListUnion(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = []string{"vpcn_a", "vpcn_b"}
	m.byRelation["v_list"] = []string{"vpcn_b", "vpcn_c"} // vpcn_b in both → dedup

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network", // verb-bearing
		Action:       "vpc.networks.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := append([]string(nil), res.ResourceIDs...)
	sort.Strings(got)
	want := []string{"vpcn_a", "vpcn_b", "vpcn_c"}
	if len(got) != len(want) {
		t.Fatalf("VBC-03: want union %v (dedup); got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("VBC-03: want %v; got %v", want, got)
		}
	}
	if m.listCalls["viewer"] == 0 || m.listCalls["v_list"] == 0 {
		t.Fatalf("VBC-03: union must query BOTH viewer and v_list; calls=%v", m.listCalls)
	}
}

// TestListObjects_VBC03_VListOnly_SelectorVisible — a v_list-only grant surfaces
// the object in the consumer's list (the selector-without-content goal).
func TestListObjects_VBC03_VListOnly_SelectorVisible(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = nil
	m.byRelation["v_list"] = []string{"inst_only_list"}

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "compute_instance",
		Action:       "compute.instances.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res.ResourceIDs) != 1 || res.ResourceIDs[0] != "inst_only_list" {
		t.Fatalf("VBC-03: v_list-only object must be selector-visible via the union; got %v", res.ResourceIDs)
	}
}

// TestListObjects_VBC03_FailClosedEitherRelation — an FGA error on EITHER relation
// query fails closed (no partial list).
func TestListObjects_VBC03_FailClosedEitherRelation(t *testing.T) {
	m := newUnionRelations()
	m.listErr = errors.New("openfga listObjects: status 503")

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	_, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
	})
	if err == nil {
		t.Fatalf("VBC-03: FGA error on a union relation must fail closed (no partial list)")
	}
}

// TestListObjects_NonVerbBearing_SingleRelation — a NON-verb-bearing type (e.g.
// `cluster`) must NOT attempt a v_list union (cluster has no v_* relations);
// the single resolved relation is used as before (no regression / no FGA 400).
func TestListObjects_NonVerbBearing_SingleRelation(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = []string{"cluster_kacho_root"}

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "cluster", // NOT verb-bearing
		Action:       "iam.cluster.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res.ResourceIDs) != 1 || res.ResourceIDs[0] != "cluster_kacho_root" {
		t.Fatalf("non-verb-bearing type: single relation only; got %v", res.ResourceIDs)
	}
	if m.listCalls["v_list"] != 0 {
		t.Fatalf("non-verb-bearing type must NOT query v_list (no v_* relations); calls=%v", m.listCalls)
	}
}
