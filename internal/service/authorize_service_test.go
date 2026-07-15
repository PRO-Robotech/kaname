// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authorize_service_test.go — unit tests for AuthorizeService.
package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// mockRelations — minimal Authorizer for unit tests.
type mockRelations struct {
	checkResp    bool
	checkErr     error
	checkCalls   int
	listResp     []string
	listErr      error
	subjectsResp []string
	subjectsNext string
	subjectsErr  error
	expandResp   *clients.ExpandTree
	expandErr    error
	// readResp — tuples returned by ReadTuples (used to build rich
	// deny_reasons on Check deny). Caller mutates per-test.
	readResp []clients.ConditionalTuple
	readErr  error
	// lastCondCtx — captures the CEL condition-context the last Check/ListObjects
	// passed to FGA, so a test can assert the server sanitised it (no forged
	// principal/connection attributes; server-forced current_time / trusted acr).
	lastCondCtx map[string]any
}

func (m *mockRelations) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	m.checkCalls++
	m.lastCondCtx = condCtx
	return m.checkResp, m.checkErr
}
func (m *mockRelations) ListObjects(ctx context.Context, subject, relation, objectType string, condCtx map[string]any, maxResults int) ([]string, error) {
	m.lastCondCtx = condCtx
	return m.listResp, m.listErr
}
func (m *mockRelations) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	return m.subjectsResp, m.subjectsNext, m.subjectsErr
}
func (m *mockRelations) Expand(ctx context.Context, objectType, objectID, relation string) (*clients.ExpandTree, error) {
	return m.expandResp, m.expandErr
}
func (m *mockRelations) ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]clients.ConditionalTuple, string, error) {
	return m.readResp, "", m.readErr
}

func TestAuthorize_Check_AllowsWhenFGAAllowsAndOPAEmpty(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
		ModelID:   "model-test-1",
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed; deny=%v", res.DenyReasons)
	}
	if res.AuthorizationModelID != "model-test-1" {
		t.Errorf("expected model id echo; got %q", res.AuthorizationModelID)
	}
}

// TestAuthorize_Check_DeniesNoPathFromFGA — caller has NO direct relations
// on the object → deny_reason states subject lacks the needed relation +
// reports "no direct relations granted". (Previously a flat "no path" string;
// rich-deny format ships in item-4 / KAC-WhoAmI.)
func TestAuthorize_Check_DeniesNoPathFromFGA(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: false /* no readResp -> no relations */},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_bob",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_y"},
		Action:   "vpc.networks.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	if len(res.DenyReasons) == 0 {
		t.Fatalf("expected at least one deny_reason; got empty")
	}
	got := res.DenyReasons[0]
	// Rich format must include subject, target relation, object, action,
	// and the "no direct relations granted" tail.
	for _, want := range []string{
		"user:usr_bob",
		"admin", // vpc.networks.delete -> admin
		"vpc_network:vpcn_y",
		"vpc.networks.delete",
		"no direct relations granted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
}

// TestAuthorize_Check_RichDenyIncludesCurrentRelations — caller has `viewer`
// but needs `admin` (delete verb). Rich deny_reason must enumerate the
// existing relations so the UI can surface "you have viewer; need admin".
func TestAuthorize_Check_RichDenyIncludesCurrentRelations(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp: false,
			readResp: []clients.ConditionalTuple{
				{User: "user:usr_alice", Relation: "viewer", Object: "vpc_network:vpcn_x"},
				// Duplicate relation should be deduplicated.
				{User: "user:usr_alice", Relation: "viewer", Object: "vpc_network:vpcn_x"},
				// Different relation should be preserved.
				{User: "user:usr_alice", Relation: "member", Object: "vpc_network:vpcn_x"},
			},
		},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	for _, want := range []string{
		"user:usr_alice",
		`lacks relation "admin"`,
		"vpc_network:vpcn_x",
		"vpc.networks.delete",
		"current direct relations:",
		"viewer",
		"member",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
	// "no direct relations granted" MUST NOT appear when relations exist.
	if strings.Contains(got, "no direct relations granted") {
		t.Errorf("unexpected fallback tail in rich deny: %q", got)
	}
}

// TestAuthorize_Check_RichDenyReadTuplesFailureFallsBackCleanly — when
// FGA ReadTuples fails (network blip), the deny decision is unchanged and
// the deny_reason falls back to the "no direct relations granted" tail.
// (ReadTuples is diagnostics; never affects the allow/deny verdict.)
func TestAuthorize_Check_RichDenyReadTuplesFailureFallsBackCleanly(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp: false,
			readErr:   errors.New("transport reset"),
		},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_charlie",
		Resource: ResourceRef{Type: "account", ID: "acc_xyz"},
		Action:   "iam.accounts.update",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	if !strings.Contains(got, "no direct relations granted") {
		t.Errorf("expected fallback tail; got %q", got)
	}
}

// TestAuthorize_CheckRelation_RichDenyAlso — gateway / internal path
// (CheckRelation) also returns rich deny_reasons (no action segment).
func TestAuthorize_CheckRelation_RichDenyAlso(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp: false,
			readResp: []clients.ConditionalTuple{
				{User: "user:usr_dave", Relation: "viewer", Object: "cluster:cluster_kacho_root"},
			},
		},
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_dave",
		Relation: "system_admin",
		Object:   "cluster:cluster_kacho_root",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	for _, want := range []string{
		"user:usr_dave",
		`lacks relation "system_admin"`,
		"cluster:cluster_kacho_root",
		"current direct relations:",
		"viewer",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
	// No action available on CheckRelation — action segment must NOT appear.
	if strings.Contains(got, "(action") {
		t.Errorf("unexpected action segment in CheckRelation deny: %q", got)
	}
}

func TestAuthorize_Check_InvalidArgumentMissingSubject(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{},
	})
	_, err := svc.Check(context.Background(), CheckRequest{
		Resource: ResourceRef{Type: "x", ID: "y"},
		Action:   "x.x.x",
	})
	if err == nil || !strings.HasPrefix(err.Error(), "Illegal argument") {
		t.Errorf("expected Illegal argument; got %v", err)
	}
}

func TestAuthorize_BatchCheck_PerItemFailureDoesNotAbort(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	results, err := svc.BatchCheck(context.Background(), []CheckRequest{
		{Subject: "user:usr_alice", Resource: ResourceRef{Type: "x", ID: "1"}, Action: "x.x.list"},
		{Subject: "", Resource: ResourceRef{Type: "x", ID: "2"}, Action: "x.x.list"}, // bad
		{Subject: "user:usr_carol", Resource: ResourceRef{Type: "x", ID: "3"}, Action: "x.x.list"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results; got %d", len(results))
	}
	if !results[0].Allowed {
		t.Errorf("expected idx0 allowed")
	}
	if results[1].Allowed {
		t.Errorf("expected idx1 denied (bad subject)")
	}
	if !results[2].Allowed {
		t.Errorf("expected idx2 allowed")
	}
}

// TestAuthorize_BatchCheck_UnavailableFailsWholeBatchNoLeak — a transient
// FGA-transport failure (the inner err carries the OpenFGA endpoint+store id,
// like a *url.Error `Post "http://fga:8080/stores/<id>/check": dial tcp ...`)
// must NOT be collapsed into a per-item deny_reason: that (a) leaks infra
// topology onto a user-facing surface and (b) mis-signals a transient outage as
// a permanent deny. BatchCheck must mirror the standalone Check sibling and fail
// the whole batch with iamerr.ErrUnavailable (handler → retryable gRPC
// Unavailable, empty responses), never surfacing the raw text as a deny_reason.
func TestAuthorize_BatchCheck_UnavailableFailsWholeBatchNoLeak(t *testing.T) {
	const fgaTransportLeak = `Post "http://fga.internal:8080/stores/01ABC/check": dial tcp 10.0.0.5:8080: connect: connection refused`
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New(fgaTransportLeak)},
	})
	results, err := svc.BatchCheck(context.Background(), []CheckRequest{
		{Subject: "user:usr_alice", Resource: ResourceRef{Type: "x", ID: "1"}, Action: "x.x.list"},
	})
	if err == nil {
		t.Fatalf("expected whole-batch failure on FGA-unavailable; got results=%v err=nil", results)
	}
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable sentinel (retryable, fail-closed); got %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results on whole-batch failure; got %v", results)
	}
	for _, r := range results {
		for _, dr := range r.DenyReasons {
			if strings.Contains(dr, "fga.internal") || strings.Contains(dr, "10.0.0.5") {
				t.Errorf("LEAK: deny_reason surfaces FGA transport detail: %q", dr)
			}
		}
	}
}

func TestAuthorize_BatchCheck_TooLarge(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	checks := make([]CheckRequest, 101)
	_, err := svc.BatchCheck(context.Background(), checks)
	if err == nil || !strings.Contains(err.Error(), "batch size") {
		t.Errorf("expected batch-too-large error; got %v", err)
	}
}

func TestAuthorize_ListObjects(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{listResp: []string{"vpcn_a", "vpcn_b"}},
	})
	res, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject: "user:x", ResourceType: "vpc_network", Action: "vpc.networks.list",
		MaxResults: 100,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res.ResourceIDs) != 2 {
		t.Fatalf("expected 2 ids; got %v", res.ResourceIDs)
	}
}

func TestAuthorize_FGAUnavailable_ReturnsUnavailable(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New("connection refused")},
	})
	_, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:x",
		Resource: ResourceRef{Type: "x", ID: "y"},
		Action:   "x.x.list",
	})
	if err == nil || !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected authz unavailable; got %v", err)
	}
}

func TestResolveActionToRelation(t *testing.T) {
	cases := map[string]string{
		"vpc.networks.list":     "viewer",
		"vpc.networks.create":   "editor",
		"vpc.networks.delete":   "admin",
		"compute.instances.ssh": "ssh",
		"":                      "",
		"just-one-part":         "",
		// M2: an unknown/typo'd verb must NOT default to "viewer"
		// (over-permissive — a read-only subject already holds viewer, so a
		// typo'd MUTATING verb would be wrongly allowed). Unknown → "" (deny).
		"vpc.networks.frobnicate": "",
		"compute.instances.nuke":  "",
		// Regression guard (M2 verb-case bug): action verbs carry camelCase
		// (Get→get but ListByScope→listByScope), and the case labels are
		// lower-cased — the resolver must fold the verb to lower-case, else these
		// multi-word verbs miss every case and fall through to unknown→deny,
		// which broke AccessBindingService.ListByScope (403) in e2e.
		"iam.access_bindings_by_resources.listByScope": "viewer",
		"iam.access_bindings.listBySubject":            "viewer",
		"iam.authorize.batchCheck":                     "viewer",
		"vpc.subnets.addCidrBlocks":                    "editor",
		"vpc.subnets.removeCidrBlocks":                 "editor",
		// SAKey credential lifecycle — issuing/revoking SA OAuth keys. The
		// permission catalog gives required_relation=editor; when the relation
		// is not supplied the verb-fallback must map issue/revoke to editor
		// instead of unknown→deny (which 403'd SAKeyService.Issue in the
		// grant-check-propagation e2e — the verb-fold M2 follow-up added the
		// multi-word read verbs but missed these credential-mutation verbs).
		"iam.issue_s_a_keies.issue":   "editor",
		"iam.revoke_s_a_keies.revoke": "editor",
	}
	for in, want := range cases {
		got := resolveActionToRelation(in)
		if got != want {
			t.Errorf("resolveActionToRelation(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestAuthorize_Check_UnknownVerb_DeniesEvenForViewerSubject — M2: a subject
// the FGA backend would happily allow at `viewer` (checkResp:true) must STILL
// be denied for an unknown verb, because the verb does not resolve to a known
// relation. Fail-closed: an unrecognised (possibly mutating) action is never
// silently downgraded to the viewer relation.
func TestAuthorize_Check_UnknownVerb_DeniesEvenForViewerSubject(t *testing.T) {
	mock := &mockRelations{checkResp: true} // FGA would ALLOW viewer
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: mock})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_readonly",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.frobnicate", // unknown verb
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected DENIED for unknown verb (over-permissive viewer mapping); got allowed")
	}
	if mock.checkCalls != 0 {
		t.Errorf("unknown verb must short-circuit BEFORE the FGA Check; got %d calls", mock.checkCalls)
	}
	if len(res.DenyReasons) == 0 {
		t.Fatalf("expected a deny_reason explaining the unresolved action")
	}
}

// TestAuthorize_Check_KnownMutatingVerb_StillMaps — guard: the fix must NOT
// break the known-verb CRUD mappings (delete → admin).
func TestAuthorize_Check_KnownMutatingVerb_StillMaps(t *testing.T) {
	mock := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: mock})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_admin",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.delete", // known mutating verb -> admin
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("known mutating verb must still resolve and allow; deny=%v", res.DenyReasons)
	}
	if mock.checkCalls != 1 {
		t.Errorf("known verb must reach the FGA Check exactly once; got %d", mock.checkCalls)
	}
}

// ── CheckRelation — FGA-native gate ──────────────────────────────────────

func TestAuthorize_CheckRelation_AllowsWhenFGAAllowsAndOPAEmpty(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
		ModelID:   "model-test-1",
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_alice",
		Relation: "viewer",
		Object:   "vpc_network:enp_x",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed; deny=%v", res.DenyReasons)
	}
	if res.AuthorizationModelID != "model-test-1" {
		t.Errorf("expected model id echo; got %q", res.AuthorizationModelID)
	}
}

func TestAuthorize_CheckRelation_DeniesNoPathFromFGA(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: false /* no readResp -> rich-deny falls back */},
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_bob",
		Relation: "editor",
		Object:   "vpc_network:enp_y",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected deny")
	}
	if len(res.DenyReasons) != 1 {
		t.Fatalf("expected single deny_reason; got %v", res.DenyReasons)
	}
	got := res.DenyReasons[0]
	// Rich-deny format: subject + relation + object + fallback tail.
	for _, want := range []string{
		"user:usr_bob",
		`lacks relation "editor"`,
		"vpc_network:enp_y",
		"no direct relations granted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
}

func TestAuthorize_CheckRelation_RejectsMissingFields(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	cases := []CheckRelationRequest{
		{Relation: "viewer", Object: "vpc_network:e"},
		{Subject: "user:u", Object: "vpc_network:e"},
		{Subject: "user:u", Relation: "viewer"},
	}
	for i, req := range cases {
		_, err := svc.CheckRelation(context.Background(), req)
		if err == nil || !strings.HasPrefix(err.Error(), "Illegal argument") {
			t.Errorf("case %d: expected Illegal argument err; got %v", i, err)
		}
	}
}

func TestAuthorize_CheckRelation_FGAUnavailableWhenNoClient(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{})
	_, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:u", Relation: "viewer", Object: "vpc_network:e",
	})
	// Backend-unavailable is now carried by the typed iamerr.ErrUnavailable
	// sentinel (handlers classify via errors.Is, not an error-text prefix); the
	// client-facing text still reads "authz unavailable".
	if err == nil || !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable-wrapped err; got %v", err)
	}
	if !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected message to mention authz unavailable; got %v", err)
	}
}

func TestAuthorize_CheckRelation_FGAErrorIsUnavailable(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New("openfga check: status 503")},
	})
	_, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:u", Relation: "viewer", Object: "vpc_network:e",
	})
	if err == nil || !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable-wrapped err; got %v", err)
	}
	if !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected message to mention authz unavailable; got %v", err)
	}
}
