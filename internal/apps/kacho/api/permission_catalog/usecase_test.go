// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_test.go — Permission Catalog unit/handler tests.
//
// No Postgres: the catalog is a PROJECTION FROM CODE (authzmap.Catalog +
// authzmap.TypeHasVerbRelations + domain.ClosedVerbs + a curated
// hasListEndpoint table). Tests exercise the thin handler end-to-end (handler
// → use-case → proto) so the on-the-wire proto shape is asserted, and the
// anonymous fail-closed guard is covered through the public RPC entry.
//
// Coverage:
//
//	anonymous → fail-closed (PermissionDenied/Unauthenticated)
//	catalog (module,resource) set == authzmap.Catalog() exactly (2-way) +
//	    closedVerbs == domain.ClosedVerbs (set+order)
//	hasVerbRelations == authzmap.TypeHasVerbRelations per type
//	geo.* / compute.diskType absent; no `geo` module
//	wildcardPolicy flags (verb-* grantable in custom; module/resource-* system-only)
//	hasListEndpoint deterministic from the closed backend table
//	vpc.addressPool grantable+verb-bearing but hasListEndpoint==false
//	labelSelectable == domain.IsLabelSelectableType per type: mirror-fed types +
//	    ALL iam-native types (unified model) are label-selectable; a
//	    grantable+verb-bearing-but-non-fed type (vpc.addressPool) is NOT.
package permission_catalog

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// newHandler builds the production handler the same way the composition root
// does (no fakes — the catalog is in-code).
func newHandler() *Handler {
	return NewHandler(NewListPermissionCatalogUseCase())
}

// authedCtx — a non-anonymous principal (any authenticated user satisfies the
// system_viewer floor; the catalog is not per-tenant scoped).
func authedCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_catalog_reader"})
}

// callCatalog drives the RPC with an authenticated caller and fails the test on
// error (happy-path helper).
func callCatalog(t *testing.T) *iamv1.ListPermissionCatalogResponse {
	t.Helper()
	resp, err := newHandler().ListPermissionCatalog(authedCtx(), &iamv1.ListPermissionCatalogRequest{})
	if err != nil {
		t.Fatalf("ListPermissionCatalog returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("ListPermissionCatalog returned nil response")
	}
	return resp
}

// pairKey is the dotted "module.resource" key, the canonical form shared with
// authzmap.objectTypes.
func responsePairs(resp *iamv1.ListPermissionCatalogResponse) map[string]*iamv1.CatalogResource {
	out := make(map[string]*iamv1.CatalogResource)
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			out[m.GetModule()+"."+r.GetResource()] = r
		}
	}
	return out
}

// TestListPermissionCatalog_ReturnsGrantableTaxonomy — sync read returns
// modules/resources/closedVerbs/wildcardPolicy; idempotent.
func TestListPermissionCatalog_ReturnsGrantableTaxonomy(t *testing.T) {
	resp := callCatalog(t)

	if len(resp.GetModules()) == 0 {
		t.Fatal("modules[] must be non-empty")
	}
	wantModules := []string{"iam", "vpc", "compute", "loadbalancer"}
	got := make(map[string]bool)
	for _, m := range resp.GetModules() {
		got[m.GetModule()] = true
	}
	for _, w := range wantModules {
		if !got[w] {
			t.Errorf("module %q missing from modules[]", w)
		}
	}
	if len(resp.GetClosedVerbs()) == 0 {
		t.Error("closedVerbs must be present")
	}
	if resp.GetWildcardPolicy() == nil {
		t.Error("wildcardPolicy must be present")
	}

	// Idempotent — a second call yields the same (module,resource) set.
	second := callCatalog(t)
	if len(responsePairs(resp)) != len(responsePairs(second)) {
		t.Error("catalog must be idempotent (same set on repeat call)")
	}
}

// TestListPermissionCatalog_SetEqualsObjectTypes — two-way set-equality
// between the catalog's (module,resource) pairs and authzmap.Catalog().
func TestListPermissionCatalog_SetEqualsObjectTypes(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	// authzmap.Catalog() is the single source of truth — its keys must equal the
	// catalog response pairs exactly (no additions, no omissions).
	want := make(map[string]struct{})
	for _, e := range authzmap.Catalog() {
		want[e.Module+"."+e.Resource] = struct{}{}
	}

	for key := range want {
		if _, ok := pairs[key]; !ok {
			t.Errorf("objectTypes pair %q missing from catalog", key)
		}
	}
	for key := range pairs {
		if _, ok := want[key]; !ok {
			t.Errorf("catalog pair %q is NOT in authzmap.Catalog()", key)
		}
	}
	if len(pairs) != len(want) {
		t.Errorf("catalog has %d pairs, authzmap.Catalog() has %d", len(pairs), len(want))
	}
}

// TestListPermissionCatalog_ClosedVerbsEqualDomainClosedVerbs — closedVerbs
// == domain.ClosedVerbs (set + order).
func TestListPermissionCatalog_ClosedVerbsEqualDomainClosedVerbs(t *testing.T) {
	resp := callCatalog(t)
	got := resp.GetClosedVerbs()
	if len(got) != len(domain.ClosedVerbs) {
		t.Fatalf("closedVerbs len=%d, domain.ClosedVerbs len=%d", len(got), len(domain.ClosedVerbs))
	}
	for i, v := range domain.ClosedVerbs {
		if got[i] != v {
			t.Errorf("closedVerbs[%d]=%q, want %q (order is fixed)", i, got[i], v)
		}
	}
}

// TestListPermissionCatalog_HasVerbRelations_MirrorsTypeHasVerbRelations —
// every resource's hasVerbRelations == authzmap.TypeHasVerbRelations(objectType).
func TestListPermissionCatalog_HasVerbRelations_MirrorsTypeHasVerbRelations(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	for _, e := range authzmap.Catalog() {
		key := e.Module + "." + e.Resource
		r, ok := pairs[key]
		if !ok {
			t.Errorf("pair %q missing", key)
			continue
		}
		fgaType, _ := authzmap.ObjectType(e.Module, e.Resource)
		want := authzmap.TypeHasVerbRelations(fgaType)
		if r.GetHasVerbRelations() != want {
			t.Errorf("%q hasVerbRelations=%v, want %v (parity with TypeHasVerbRelations)",
				key, r.GetHasVerbRelations(), want)
		}
	}

	// account/project are verb-bearing (the canonical model defines direct v_*
	// on both) — the catalog must report them as hasVerbRelations=true. They
	// still carry tier relations as write-authz anchors; verb-bearing is additive.
	for _, key := range []string{"iam.account", "iam.project"} {
		if r := pairs[key]; r == nil || !r.GetHasVerbRelations() {
			t.Errorf("%q must be present with hasVerbRelations=true (now verb-bearing)", key)
		}
	}
	// Explicit verb-bearing leaves → true.
	for _, key := range []string{"compute.instance", "vpc.subnet", "iam.role", "loadbalancer.networkLoadBalancers"} {
		if r := pairs[key]; r == nil || !r.GetHasVerbRelations() {
			t.Errorf("%q must be present with hasVerbRelations=true (verb-bearing)", key)
		}
	}
}

// TestListPermissionCatalog_ExcludesNonGrantableTypes — types not in
// objectTypes (geo.* / compute.diskType) are absent; no `geo` module.
func TestListPermissionCatalog_ExcludesNonGrantableTypes(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	for _, key := range []string{"geo.region", "geo.zone", "compute.diskType"} {
		if _, ok := pairs[key]; ok {
			t.Errorf("non-grantable type %q must NOT appear in catalog", key)
		}
	}
	for _, m := range resp.GetModules() {
		if m.GetModule() == "geo" {
			t.Error("module `geo` must NOT appear in modules[] (no grantable geo pair)")
		}
	}
}

// TestListPermissionCatalog_WildcardPolicyParity — wildcard policy flags
// (verb-* grantable in custom; module/resource-* system-only).
func TestListPermissionCatalog_WildcardPolicyParity(t *testing.T) {
	resp := callCatalog(t)
	wp := resp.GetWildcardPolicy()
	if wp == nil {
		t.Fatal("wildcardPolicy must be present")
	}
	if !wp.GetVerbWildcardAllowedCustom() {
		t.Error("verbWildcardAllowedCustom must be true (verb-* bounded)")
	}
	if !wp.GetModuleResourceWildcardSystemOnly() {
		t.Error("moduleResourceWildcardSystemOnly must be true (module/resource-* system-only)")
	}
}

// TestListPermissionCatalog_HasListEndpoint_FromClosedTable — hasListEndpoint
// is deterministic from the curated backend table. Public-listable leaves →
// true; iam.condition → false (RPC exists in proto but NOT registered on the
// external gateway mux).
func TestListPermissionCatalog_HasListEndpoint_FromClosedTable(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	wantTrue := []string{
		"iam.role", "iam.account", "iam.project", "iam.serviceAccount", "iam.group", "iam.accessBinding",
		"vpc.subnet", "vpc.network", "compute.instance",
	}
	for _, key := range wantTrue {
		r := pairs[key]
		if r == nil {
			t.Errorf("pair %q missing", key)
			continue
		}
		if !r.GetHasListEndpoint() {
			t.Errorf("%q hasListEndpoint=false, want true (public external List exists)", key)
		}
	}

	// iam.condition: ConditionsService.List exists in proto but is NOT on the
	// external mux → false.
	if r := pairs["iam.condition"]; r == nil || r.GetHasListEndpoint() {
		t.Errorf("iam.condition must be present with hasListEndpoint=false (not on external mux)")
	}
}

// TestListPermissionCatalog_AddressPool_GrantableButInternalOnlyList
// (SECURITY): vpc.addressPool is grantable & verb-bearing, but its only List is
// Internal-only (:9091) → hasListEndpoint=false. Ground-truth anchor — not
// derivable from other flags.
func TestListPermissionCatalog_AddressPool_GrantableButInternalOnlyList(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	r := pairs["vpc.addressPool"]
	if r == nil {
		t.Fatal("vpc.addressPool must be present (grantable, verb-bearing)")
	}
	if !r.GetHasVerbRelations() {
		t.Error("vpc.addressPool hasVerbRelations must be true (verb-bearing)")
	}
	if r.GetHasListEndpoint() {
		t.Error("vpc.addressPool hasListEndpoint must be false (List only on Internal :9091)")
	}
}

// TestListPermissionCatalog_NewObjectType_AppearsWithoutUIChange — the catalog
// is a live projection of authzmap.Catalog(); the set-equality test already
// guarantees a future objectTypes addition appears automatically with no
// catalog-code change. This asserts that explicitly: the resource set is
// derived (not a hand-maintained literal) — every authzmap pair round-trips.
func TestListPermissionCatalog_NewObjectType_AppearsWithoutUIChange(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)
	for _, e := range authzmap.Catalog() {
		if _, ok := pairs[e.Module+"."+e.Resource]; !ok {
			t.Errorf("authzmap pair %q.%q not projected — catalog is not live-driven", e.Module, e.Resource)
		}
	}
}

// TestListPermissionCatalog_AnonymousFailClosed — an anonymous caller is
// rejected (fail-closed); no taxonomy leaks pre-authentication.
func TestListPermissionCatalog_AnonymousFailClosed(t *testing.T) {
	// Anonymous principal as injected by api-gateway: {Type:system, ID:anonymous}.
	anonCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})

	resp, err := newHandler().ListPermissionCatalog(anonCtx, &iamv1.ListPermissionCatalogRequest{})
	if err == nil {
		t.Fatal("anonymous request must be rejected, got nil error")
	}
	if resp != nil {
		t.Error("anonymous request must NOT return a catalog response")
	}
	code := status.Code(err)
	if code != codes.PermissionDenied && code != codes.Unauthenticated {
		t.Errorf("anonymous → code=%v, want PermissionDenied or Unauthenticated", code)
	}

	// Also reject a bare ctx (api-gateway forwarded no principal headers).
	if _, err := newHandler().ListPermissionCatalog(context.Background(), &iamv1.ListPermissionCatalogRequest{}); err == nil {
		t.Error("empty-principal ctx must be rejected (fail-closed)")
	}
}

// TestListPermissionCatalog_LabelSelectable_MirrorsDomain — every resource's
// labelSelectable == domain.IsLabelSelectableType("module.resource") (the
// feed-gate that Rule.Validate enforces on an ARM_LABELS rule). The catalog
// flag lets the UI hide the match_labels arm on a type the backend would reject,
// closing the gap where vpc.addressPool (grantable+verb-bearing, but NOT
// label-selectable) was offered in the labels arm → INVALID_ARGUMENT.
func TestListPermissionCatalog_LabelSelectable_MirrorsDomain(t *testing.T) {
	resp := callCatalog(t)
	pairs := responsePairs(resp)

	// Whole-catalog parity: labelSelectable must mirror the domain source of
	// truth for EVERY projected (module,resource) — never a hand-maintained subset.
	for _, e := range authzmap.Catalog() {
		key := e.Module + "." + e.Resource
		r, ok := pairs[key]
		if !ok {
			t.Errorf("pair %q missing", key)
			continue
		}
		want := domain.IsLabelSelectableType(key)
		if r.GetLabelSelectable() != want {
			t.Errorf("%q labelSelectable=%v, want %v (parity with domain.IsLabelSelectableType)",
				key, r.GetLabelSelectable(), want)
		}
	}

	// Representative anchors (ground-truth, not derivable from other flags):
	// mirror-fed leaves + ALL iam-native types are label-selectable (unified
	// visibility model); a grantable+verb-bearing-but-non-fed type
	// (vpc.addressPool) is NOT (the bug the labelSelectable flag closes).
	wantSelectable := map[string]bool{
		"vpc.address":        true,  // mirror-fed
		"vpc.subnet":         true,  // mirror-fed
		"compute.instance":   true,  // mirror-fed
		"iam.account":        true,  // iam-direct
		"iam.project":        true,  // iam-direct
		"iam.role":           true,  // iam-direct (unified model)
		"iam.user":           true,  // iam-direct (unified model)
		"iam.serviceAccount": true,  // iam-direct (unified model)
		"iam.group":          true,  // iam-direct (unified model)
		"iam.accessBinding":  true,  // iam-direct (unified model)
		"vpc.addressPool":    false, // grantable+verb-bearing but NOT fed — the gap
	}
	for key, want := range wantSelectable {
		r := pairs[key]
		if r == nil {
			t.Errorf("anchor pair %q missing from catalog", key)
			continue
		}
		if r.GetLabelSelectable() != want {
			t.Errorf("%q labelSelectable=%v, want %v", key, r.GetLabelSelectable(), want)
		}
	}
}
