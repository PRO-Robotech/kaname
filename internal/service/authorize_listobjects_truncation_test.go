// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// authorize_listobjects_truncation_test.go — AuthorizeService.ListObjects must be
// HONEST about the OpenFGA cap.
//
// OpenFGA bounds ListObjects server-side (OPENFGA_LIST_OBJECTS_MAX_RESULTS,
// default 1000) and exposes NO continuation token. The client's `maxResults`
// argument is a CLIENT-SIDE trim only — requesting more can never widen the
// answer. `truncated := len(ids) >= maxR` therefore reported FALSE for every
// server-capped result whenever the caller asked for more than the server cap:
// the caller was told "this is the complete set" about a silently cut prefix.
//
// The RPC is public and stays; what changes is that a capped result is REPORTED
// as truncated, and a page_token (which can never be honoured) is rejected
// instead of silently ignored.

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// cappedRelations — ListObjects fake that returns exactly the OpenFGA server cap
// worth of ids, i.e. a silently truncated prefix.
type cappedRelations struct {
	unionRelations
	perRelation int
}

func newCappedRelations(perRelation int) *cappedRelations {
	return &cappedRelations{
		unionRelations: *newUnionRelations(),
		perRelation:    perRelation,
	}
}

func (m *cappedRelations) ListObjects(_ context.Context, _, relation, _ string,
	_ map[string]any, _ int) ([]string, error) {
	m.listCalls[relation]++
	out := make([]string, 0, m.perRelation)
	for i := 0; i < m.perRelation; i++ {
		// Distinct per relation so the union does not dedup them away.
		out = append(out, fmt.Sprintf("%s_obj%06d", relation, i))
	}
	return out, nil
}

// A server-capped result must report Truncated=true even when the caller asked
// for MORE than the cap — the case in which the old `len(ids) >= maxR` formula
// was silently always false.
func TestListObjects_ServerCappedResult_ReportsTruncated(t *testing.T) {
	m := newCappedRelations(fgaListObjectsServerCap)
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
		MaxResults:   5000, // > the OpenFGA server cap
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("a server-capped ListObjects result MUST report Truncated=true "+
			"(got %d ids for max_results=5000); silently reporting a complete set "+
			"is how a tenant's own objects vanish", len(res.ResourceIDs))
	}
}

// A result below the cap is NOT truncated — the honesty fix must not turn every
// answer into "truncated" (that would be equally uninformative).
func TestListObjects_SmallResult_NotTruncated(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = []string{"vpcn_a", "vpcn_b"}

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})
	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
		MaxResults:   5000,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Truncated {
		t.Fatalf("a complete (sub-cap) result must NOT be reported truncated; got %v", res.ResourceIDs)
	}
}

// The client-side trim still reports truncation (unchanged contract).
func TestListObjects_ClientTrim_ReportsTruncated(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = []string{"vpcn_a", "vpcn_b", "vpcn_c"}

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})
	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
		MaxResults:   3,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("a client-trimmed result must report Truncated=true; got %v", res.ResourceIDs)
	}
}

// page_token cannot be honoured (OpenFGA has no ListObjects continuation token),
// so it is rejected rather than silently ignored — silently ignoring a
// pagination request returns a WRONG page under the guise of a right one.
func TestListObjects_PageToken_Rejected(t *testing.T) {
	m := newUnionRelations()
	m.byRelation["viewer"] = []string{"vpcn_a"}

	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})
	_, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
		PageToken:    "eyJjIjoiMjAyNi0wNy0yNSJ9",
	})
	if err == nil {
		t.Fatalf("a page_token that can never be honoured must be rejected, not ignored")
	}
	if !strings.HasPrefix(err.Error(), "Illegal argument") {
		t.Fatalf("page_token rejection must be an Illegal argument (→ INVALID_ARGUMENT); got %v", err)
	}
	// And the result never carries a next-page token.
	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_x",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.NextPageToken != "" {
		t.Fatalf("ListObjects cannot paginate; NextPageToken must stay empty, got %q", res.NextPageToken)
	}
}
