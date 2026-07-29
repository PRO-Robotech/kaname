// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cascade_fallback_test.go — the contract of the structural fallback, at the level
// where its mistakes would be invisible in an integration run.
//
// Three properties, each of which is a way the fix could be quietly wrong:
//
//  1. An object iam does not own costs NO read. The fallback is on the deny path,
//     which negative probes take constantly, so a read per denied Check on every
//     object type in the platform would be a real cost paid for nothing.
//  2. An UNREADABLE row is an OUTAGE, not a denial. The structural fact is part of
//     the decision now; if the row cannot be read the answer is unknown, and
//     unknown must be retryable (UNAVAILABLE), never a terminal 403 that a caller
//     would take as "you may not". An ABSENT row is the opposite — that IS a fact,
//     and the deny stands.
//  3. The fallback cannot fire without both halves wired. An Authorizer that cannot
//     carry contextual tuples silently returns the cascade to depending on delivery,
//     which is why the composition root refuses to start on it.

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// cfResolver — a StructuralFactResolver fake that counts reads.
type cfResolver struct {
	derivable map[string]bool
	facts     []authztypes.ConditionalTuple
	err       error
	reads     int
}

func (r *cfResolver) Derivable(objectType string) bool { return r.derivable[objectType] }

func (r *cfResolver) StructuralFacts(_ context.Context, _, _ string) ([]authztypes.ConditionalTuple, error) {
	r.reads++
	return r.facts, r.err
}

// cfAuthorizer — mockRelations plus the contextual-tuple capability, recording what
// was supplied.
type cfAuthorizer struct {
	mockRelations
	contextualAllow bool
	gotContextual   []authztypes.ConditionalTuple
	contextualCalls int
}

func (a *cfAuthorizer) CheckWithContextualTuples(
	_ context.Context, _, _, _ string, _ map[string]any, contextual []authztypes.ConditionalTuple,
) (bool, error) {
	a.contextualCalls++
	a.gotContextual = contextual
	return a.contextualAllow, nil
}

func TestStructuralFallback_NoReadForAnObjectIAMDoesNotOwn(t *testing.T) {
	res := &cfResolver{derivable: map[string]bool{"iam_access_binding": true}}
	az := &cfAuthorizer{mockRelations: mockRelations{checkResp: false}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: az, ModelID: "m1", StructuralFacts: res,
	})

	out, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_x", Relation: "v_delete", Object: "vpc_network:net_1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Allowed {
		t.Fatal("must stay denied")
	}
	if res.reads != 0 {
		t.Fatalf("a Check on an object iam does not own must cost no database read, got %d", res.reads)
	}
	if az.contextualCalls != 0 {
		t.Fatalf("no contextual Check should have been issued, got %d", az.contextualCalls)
	}
}

func TestStructuralFallback_AbsentRowLeavesTheDenyStanding(t *testing.T) {
	// Derivable type, but the row is not there: (nil, nil) — a fact, not a fault.
	res := &cfResolver{derivable: map[string]bool{"iam_access_binding": true}}
	az := &cfAuthorizer{mockRelations: mockRelations{checkResp: false}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: az, ModelID: "m1", StructuralFacts: res,
	})

	out, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_x", Relation: "v_delete", Object: "iam_access_binding:abn_1",
	})
	if err != nil {
		t.Fatalf("an absent row is not an error: %v", err)
	}
	if out.Allowed {
		t.Fatal("must stay denied")
	}
	if res.reads != 1 {
		t.Fatalf("the row should have been read exactly once, got %d", res.reads)
	}
	if az.contextualCalls != 0 {
		t.Fatalf("no facts means no second Check, got %d", az.contextualCalls)
	}
	if len(out.DenyReasons) == 0 {
		t.Fatal("a deny must still carry its reason")
	}
}

func TestStructuralFallback_UnreadableRowIsAnOutageNotADenial(t *testing.T) {
	res := &cfResolver{
		derivable: map[string]bool{"iam_access_binding": true},
		err:       errors.New("connection refused"),
	}
	az := &cfAuthorizer{mockRelations: mockRelations{checkResp: false}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: az, ModelID: "m1", StructuralFacts: res,
	})

	for _, tc := range []struct {
		name string
		call func() (*CheckResult, error)
	}{
		{"CheckRelation", func() (*CheckResult, error) {
			return svc.CheckRelation(context.Background(), CheckRelationRequest{
				Subject: "user:usr_x", Relation: "v_delete", Object: "iam_access_binding:abn_1",
			})
		}},
		{"Check", func() (*CheckResult, error) {
			return svc.Check(context.Background(), CheckRequest{
				Subject:  "user:usr_x",
				Resource: ResourceRef{Type: "iam_access_binding", ID: "abn_1"},
				Action:   "iam.access_bindings.delete",
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.call()
			if err == nil {
				t.Fatal("an unreadable structural fact must not be reported as a clean denial: " +
					"the caller would read a terminal 403 where the answer is simply unknown")
			}
			if !errors.Is(err, iamerr.ErrUnavailable) {
				t.Fatalf("want ErrUnavailable (retryable), got %v", err)
			}
			if out.Allowed {
				t.Fatal("fail-closed: an outage must never allow")
			}
		})
	}
}

func TestStructuralFallback_SuppliesTheFactsAndAllows(t *testing.T) {
	facts := []authztypes.ConditionalTuple{
		{User: "account:acc_1", Relation: "account", Object: "iam_access_binding:abn_1"},
	}
	res := &cfResolver{derivable: map[string]bool{"iam_access_binding": true}, facts: facts}
	az := &cfAuthorizer{mockRelations: mockRelations{checkResp: false}, contextualAllow: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: az, ModelID: "m1", StructuralFacts: res,
	})

	out, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_x", Relation: "v_delete", Object: "iam_access_binding:abn_1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !out.Allowed {
		t.Fatal("the cascade must resolve over the supplied structural fact")
	}
	if az.contextualCalls != 1 {
		t.Fatalf("want exactly one contextual Check, got %d", az.contextualCalls)
	}
	if len(az.gotContextual) != 1 || az.gotContextual[0] != facts[0] {
		t.Fatalf("the fact must reach OpenFGA verbatim, got %+v", az.gotContextual)
	}
}

func TestStructuralFallback_NotReachableWithoutBothHalves(t *testing.T) {
	res := &cfResolver{derivable: map[string]bool{"iam_access_binding": true}}
	cases := []struct {
		name string
		cfg  AuthorizeServiceConfig
		want bool
	}{
		{"resolver and contextual Check", AuthorizeServiceConfig{
			Relations: &cfAuthorizer{}, ModelID: "m1", StructuralFacts: res}, true},
		{"no resolver", AuthorizeServiceConfig{
			Relations: &cfAuthorizer{}, ModelID: "m1"}, false},
		{"Authorizer cannot carry contextual tuples", AuthorizeServiceConfig{
			Relations: &mockRelations{}, ModelID: "m1", StructuralFacts: res}, false},
		{"no Authorizer", AuthorizeServiceConfig{ModelID: "m1", StructuralFacts: res}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewAuthorizeService(tc.cfg).StructuralFallbackReachable(); got != tc.want {
				t.Fatalf("StructuralFallbackReachable() = %v, want %v — the composition root "+
					"refuses to start on false, so a wrong answer here is how the cascade would "+
					"quietly go back to waiting for the queue", got, tc.want)
			}
		})
	}
}

func TestSplitFGAObject_KeepsColonsInsideTheID(t *testing.T) {
	// registry_repository ids carry their own colon (`<reg>/<repo>:<tag>`), so only
	// the FIRST colon separates type from id.
	for _, tc := range []struct{ in, wantType, wantID string }{
		{"iam_access_binding:abn_1", "iam_access_binding", "abn_1"},
		{"registry_repository:reg_1/app:v1", "registry_repository", "reg_1/app:v1"},
	} {
		gotType, gotID, ok := splitFGAObject(tc.in)
		if !ok || gotType != tc.wantType || gotID != tc.wantID {
			t.Fatalf("splitFGAObject(%q) = (%q, %q, %v)", tc.in, gotType, gotID, ok)
		}
	}
	for _, bad := range []string{"", "no_colon", ":leading", "trailing:"} {
		if _, _, ok := splitFGAObject(bad); ok {
			t.Fatalf("splitFGAObject(%q) must not parse", bad)
		}
	}
}
