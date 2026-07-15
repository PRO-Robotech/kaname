// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authorize_context_test.go — the CEL condition-context handed to OpenFGA must
// be server-authoritative for principal/connection attributes. AuthorizeService
// is reachable on the PUBLIC listener and the inner caller-authority gate allows
// a self-query, so a tenant could otherwise forge acr_value / amr_claims /
// mfa_at / client_ip in the request body and satisfy a mfa_fresh /
// source_ip_in_range condition without actually holding the assurance
// (CWE-807 / security.md "no reliance on untrusted inputs in a security
// decision"). These tests pin that the service strips those keys and only
// server-derived values (current_time, trusted acr) reach FGA.
package service

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

func TestAuthorize_Check_StripsForgedSecurityContext(t *testing.T) {
	m := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	_, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.update",
		Context: map[string]any{
			// Forged principal/connection assurance a self-querying tenant could send.
			"acr_value":          "3",
			"amr_claims":         []any{"webauthn"},
			"mfa_at":             int64(9_999_999_999),
			"client_ip":          "10.0.0.1",
			"source_ip":          "10.0.0.1",
			"valid_until":        int64(9_999_999_999),
			"device_attestation": "trusted",
			// A genuinely request-scoped, non-security attribute is allowed through.
			"tenant_hint": "keep-me",
		},
	})
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	cc := m.lastCondCtx
	if cc == nil {
		t.Fatal("no condCtx captured")
	}
	for _, k := range []string{"amr_claims", "mfa_at", "client_ip", "source_ip", "valid_until", "device_attestation"} {
		if _, ok := cc[k]; ok {
			t.Errorf("server-authoritative key %q must be stripped from client context, got %v", k, cc[k])
		}
	}
	// No trusted acr in ctx → the forged acr_value must NOT survive.
	if v, ok := cc["acr_value"]; ok {
		t.Errorf("forged acr_value must not reach FGA without a trusted source, got %v", v)
	}
	// current_time is always server-forced.
	if _, ok := cc["current_time"]; !ok {
		t.Error("current_time must be server-forced into condCtx")
	}
	// Non-security request-scoped attributes pass through unchanged.
	if cc["tenant_hint"] != "keep-me" {
		t.Errorf("non-security attribute dropped: %v", cc["tenant_hint"])
	}
}

func TestAuthorize_Check_OverlaysTrustedACROverForgedValue(t *testing.T) {
	m := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	// The interceptor chain places the FD-4-trusted acr on ctx.
	ctx := grpcsrv.WithTrustedACR(context.Background(), "2", true)
	_, err := svc.Check(ctx, CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.update",
		Context:  map[string]any{"acr_value": "3"}, // forged higher assurance
	})
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if got := m.lastCondCtx["acr_value"]; got != "2" {
		t.Errorf("acr_value = %v; want the trusted ctx value \"2\", never the forged \"3\"", got)
	}
}

func TestAuthorize_ListObjects_StripsForgedSecurityContext(t *testing.T) {
	m := &mockRelations{listResp: []string{"vpcn_a"}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m, ModelID: "m1"})

	_, err := svc.ListObjects(context.Background(), ListObjectsRequest{
		Subject:      "user:usr_alice",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
		Context:      map[string]any{"client_ip": "10.0.0.1", "acr_value": "3"},
	})
	if err != nil {
		t.Fatalf("ListObjects err: %v", err)
	}
	if _, ok := m.lastCondCtx["client_ip"]; ok {
		t.Error("client_ip must be stripped from ListObjects client context")
	}
	if _, ok := m.lastCondCtx["acr_value"]; ok {
		t.Error("forged acr_value must not reach FGA on ListObjects without a trusted source")
	}
	if _, ok := m.lastCondCtx["current_time"]; !ok {
		t.Error("current_time must be server-forced into ListObjects condCtx")
	}
}
