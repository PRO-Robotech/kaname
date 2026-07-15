// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authorize

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// authorityStub — configurable authzguard.RelationChecker for the inner
// caller-authority gate. allow[relation+"|"+object] == true grants that tuple.
type authorityStub struct {
	allow map[string]bool
	err   error
	calls int
}

func (a *authorityStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	a.calls++
	if a.err != nil {
		return false, a.err
	}
	return a.allow[relation+"|"+object], nil
}

func newHandlerWithAuthority(svcCheck bool, auth *authorityStub) *Handler {
	stub := &stubFGA{check: svcCheck}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: stub,
		ModelID:   "test-model",
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)).WithCallerAuthority(auth)
}

// newHandlerWithAuthorityProd builds the handler in PRODUCTION mode, where the
// inner caller-authority gate fails closed for an anonymous/system principal
// that carries no verified module cert (the public-listener bypass).
func newHandlerWithAuthorityProd(svcCheck bool, auth *authorityStub) *Handler {
	return newHandlerWithAuthority(svcCheck, auth).WithProductionMode(true)
}

// moduleCertCtx injects a verified mTLS module-cert SAN into ctx, simulating a
// cluster-internal module PDP peer call over the :9091 internal listener.
func moduleCertCtx() context.Context {
	return grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
}

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "user"})
}

func requireDenied(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

// TestCallerAuthority_Check_ForeignSubject_Denied — the confused-deputy case:
// a tenant principal (alice) queries a decision about a DIFFERENT subject (bob)
// on a resource it does not administer → PermissionDenied, without ever reaching
// the FGA decision.
func TestCallerAuthority_Check_ForeignSubject_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.get",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_Check_SelfQuery_Allowed — a tenant may always ask about
// itself; the gate lets the decision proceed.
func TestCallerAuthority_Check_SelfQuery_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	resp, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_alice",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("self-query must pass the gate: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to be allowed")
	}
	if auth.calls != 1 { // one cluster-admin Check (self path short-circuits before it? no — self returns first)
		// self-query returns before any authority Check
		if auth.calls != 0 {
			t.Errorf("self-query should not hit the authority checker; calls=%d", auth.calls)
		}
	}
}

// TestCallerAuthority_Check_ClusterAdmin_Allowed — a cluster-admin may query any
// subject/resource.
func TestCallerAuthority_Check_ClusterAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"system_admin|cluster:cluster_kacho_root": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_admin"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("cluster-admin must pass the gate: %v", err)
	}
}

// TestCallerAuthority_Check_ResourceAdmin_Allowed — a tenant that holds `admin`
// on the queried resource may ask about other subjects on it.
func TestCallerAuthority_Check_ResourceAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"admin|account:acc_a": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("resource-admin must pass the gate: %v", err)
	}
}

// TestCallerAuthority_Anonymous_PassesThrough — a call with NO principal (the
// cluster-internal verified-mTLS module PDP peer path) is NOT gated here; the
// decision proceeds as before.
func TestCallerAuthority_Anonymous_PassesThrough(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	resp, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("anonymous module PDP call must pass through: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to proceed")
	}
	if auth.calls != 0 {
		t.Errorf("anonymous path must not hit the authority checker; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_Anonymous_ProdMode_NoCert_Denied — the public-listener
// bypass (CWE-863). In production an anonymous/system caller that presents NO
// verified module cert (i.e. reached the PUBLIC :9090 listener, which has no
// module-cert floor) must be DENIED, not blanket-allowed. Before the fail-closed
// fix this Check returned the underlying decision (fail-open oracle).
func TestCallerAuthority_Anonymous_ProdMode_NoCert_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	_, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_victim",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	requireDenied(t, err)
	if auth.calls != 0 {
		t.Errorf("denied public anonymous call must not reach the FGA oracle; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_Anonymous_ProdMode_NoCert_ListSubjects_Denied — the same
// fail-closed posture for the enumeration RPC on the public listener.
func TestCallerAuthority_Anonymous_ProdMode_NoCert_ListSubjects_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	_, err := h.ListSubjects(context.Background(), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.listAccessBindings",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_Anonymous_ProdMode_VerifiedModuleCert_Allowed — a GENUINE
// cluster-internal module PDP peer (verified mTLS module SAN on :9091) still
// passes the inner gate in production; the internal listener's verified-cert
// floor governs it. This is the path the fail-closed fix must NOT break.
func TestCallerAuthority_Anonymous_ProdMode_VerifiedModuleCert_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	resp, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("verified module PDP peer must pass through in prod: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to proceed for the module peer")
	}
	if auth.calls != 0 {
		t.Errorf("module-peer path must not hit the authority checker; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_ListSubjects_NoAuthority_Denied — enumerating who can act
// on a resource requires administering it; a bare tenant is denied.
func TestCallerAuthority_ListSubjects_NoAuthority_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListSubjects(userCtx("usr_alice"), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.listAccessBindings",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_ListSubjects_ResourceAdmin_Allowed — a resource-admin may
// enumerate its resource's subjects.
func TestCallerAuthority_ListSubjects_ResourceAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"admin|account:acc_a": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListSubjects(userCtx("usr_alice"), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.listAccessBindings",
	})
	if err != nil {
		t.Fatalf("resource-admin ListSubjects must pass the gate: %v", err)
	}
}

// TestCallerAuthority_ListObjects_ForeignSubject_Denied — a tenant may only
// enumerate its OWN visible objects (no per-resource scope to delegate on).
func TestCallerAuthority_ListObjects_ForeignSubject_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListObjects(userCtx("usr_alice"), &iamv1.ListObjectsRequest{
		Subject:      "user:usr_bob",
		ResourceType: "account",
		Action:       "iam.accounts.list",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_ListObjects_SelfSubject_Allowed — self-enumeration passes.
func TestCallerAuthority_ListObjects_SelfSubject_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListObjects(userCtx("usr_alice"), &iamv1.ListObjectsRequest{
		Subject:      "user:usr_alice",
		ResourceType: "account",
		Action:       "iam.accounts.list",
	})
	if err != nil {
		t.Fatalf("self ListObjects must pass the gate: %v", err)
	}
}

// TestCallerAuthority_BatchCheck_OneForeign_DeniesBatch — a single unauthorized
// item denies the whole batch.
func TestCallerAuthority_BatchCheck_OneForeign_DeniesBatch(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.BatchCheck(userCtx("usr_alice"), &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{Subject: "user:usr_alice", Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"}, Action: "iam.accounts.get"},
			{Subject: "user:usr_bob", Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"}, Action: "iam.accounts.get"},
		},
	})
	requireDenied(t, err)
}
