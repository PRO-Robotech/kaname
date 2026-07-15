// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// SAN constants for the caller-policy table. The gateway SA is the single
// legitimate caller of the gateway-fronted privileged admin RPCs; any other
// module SAN (e.g. kacho-vpc) is a non-gateway module.
const (
	gatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	vpcSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"

	// gatewayOnlyMethod — a representative gateway-fronted privileged admin RPC.
	gatewayOnlyMethod = "/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin"
	// floorOnlyMethod — a non-gateway RPC: any verified module may call it.
	floorOnlyMethod = "/kacho.cloud.iam.v1.InternalIAMService/Check"

	// authorizeListObjectsMethod — the AuthorizeService.ListObjects RPC the RBAC
	// rules-model D consumer per-object List filter (kacho-vpc / kacho-compute /
	// kacho-nlb) calls service→service over the verified-mTLS :9091 edge. It is
	// NOT gateway-fronted: any verified module SA may call it (the explicit
	// subject in the request is the authz view, NOT the caller's access).
	authorizeListObjectsMethod = "/kacho.cloud.iam.v1.AuthorizeService/ListObjects"
	// authorizeBatchCheckMethod / authorizeCheckMethod — the other two
	// AuthorizeService RPCs consumers reuse on the same edge.
	authorizeBatchCheckMethod = "/kacho.cloud.iam.v1.AuthorizeService/BatchCheck"
	authorizeCheckMethod      = "/kacho.cloud.iam.v1.AuthorizeService/Check"
)

// okHandler is a no-op unary handler returning a sentinel so a "pass" is
// observable.
func okHandler(_ context.Context, _ any) (any, error) { return "ok", nil }

func okStreamHandler(_ any, _ grpc.ServerStream) error { return nil }

// fakeStream is a minimal grpc.ServerStream carrying a custom context.
type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeStream) Context() context.Context { return s.ctx }

// newGatewayCtx returns a ctx carrying a verified api-gateway module cert SAN.
func newGatewayCtx() context.Context {
	return grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, true)
}

// newVPCCtx returns a ctx carrying a verified kacho-vpc module cert SAN.
func newVPCCtx() context.Context {
	return grpcsrv.WithCertIdentity(context.Background(), vpcSAN, true)
}

// testPolicy builds a CallerPolicy with the canonical gateway-only set.
func testPolicy(prod bool) *CallerPolicy {
	return NewCallerPolicy(prod, GatewayFrontedInternalRPCs())
}

// ── allow(): gateway-only RPC ──────────────────────────────────────────────

// TestCallerPolicy_GatewayOnly_GatewayCert — a verified api-gateway cert may
// call a gateway-only RPC in prod (and dev).
func TestCallerPolicy_GatewayOnly_GatewayCert(t *testing.T) {
	for _, prod := range []bool{true, false} {
		p := testPolicy(prod)
		if err := p.allow(newGatewayCtx(), gatewayOnlyMethod); err != nil {
			t.Errorf("prod=%v gateway cert on gateway-only RPC: unexpected error %v", prod, err)
		}
	}
}

// TestCallerPolicy_GatewayOnly_NonGatewayCert_Prod — a verified non-gateway
// module (kacho-vpc) calling a gateway-only RPC in prod → PermissionDenied
// (closes audit C1/C3: a compromised data-plane module cannot escalate).
func TestCallerPolicy_GatewayOnly_NonGatewayCert_Prod(t *testing.T) {
	p := testPolicy(true)
	err := p.allow(newVPCCtx(), gatewayOnlyMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod vpc cert on gateway-only RPC: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_GatewayOnly_NonGatewayCert_Dev — same call in dev → no-op pass
// (insecure back-compat).
func TestCallerPolicy_GatewayOnly_NonGatewayCert_Dev(t *testing.T) {
	p := testPolicy(false)
	if err := p.allow(newVPCCtx(), gatewayOnlyMethod); err != nil {
		t.Errorf("dev vpc cert on gateway-only RPC: unexpected error %v", err)
	}
}

// TestCallerPolicy_GatewayOnly_NoCert_Prod — no verified module cert + prod →
// PermissionDenied (floor fail-closed).
func TestCallerPolicy_GatewayOnly_NoCert_Prod(t *testing.T) {
	p := testPolicy(true)
	err := p.allow(context.Background(), gatewayOnlyMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod no cert on gateway-only RPC: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_GatewayOnly_NoCert_Dev — no cert + dev → no-op pass.
func TestCallerPolicy_GatewayOnly_NoCert_Dev(t *testing.T) {
	p := testPolicy(false)
	if err := p.allow(context.Background(), gatewayOnlyMethod); err != nil {
		t.Errorf("dev no cert on gateway-only RPC: unexpected error %v", err)
	}
}

// ── allow(): non-gateway RPC (floor only) ──────────────────────────────────

// TestCallerPolicy_FloorOnly_AnyModuleCert — any verified module (kacho-vpc) may
// call a non-gateway RPC, prod and dev.
func TestCallerPolicy_FloorOnly_AnyModuleCert(t *testing.T) {
	for _, prod := range []bool{true, false} {
		p := testPolicy(prod)
		if err := p.allow(newVPCCtx(), floorOnlyMethod); err != nil {
			t.Errorf("prod=%v vpc cert on non-gateway RPC: unexpected error %v", prod, err)
		}
	}
}

// TestCallerPolicy_FloorOnly_NoCert_Prod — no verified cert + prod →
// PermissionDenied (floor fail-closed even for non-gateway RPCs).
func TestCallerPolicy_FloorOnly_NoCert_Prod(t *testing.T) {
	p := testPolicy(true)
	err := p.allow(context.Background(), floorOnlyMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod no cert on non-gateway RPC: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_FloorOnly_NoCert_Dev — no cert + dev → no-op pass.
func TestCallerPolicy_FloorOnly_NoCert_Dev(t *testing.T) {
	p := testPolicy(false)
	if err := p.allow(context.Background(), floorOnlyMethod); err != nil {
		t.Errorf("dev no cert on non-gateway RPC: unexpected error %v", err)
	}
}

// TestCallerPolicy_UnverifiedCert_Prod — a present-but-UNVERIFIED cert is treated
// as "no module cert" → PermissionDenied in prod.
func TestCallerPolicy_UnverifiedCert_Prod(t *testing.T) {
	p := testPolicy(true)
	ctx := grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, false)
	if err := p.allow(ctx, gatewayOnlyMethod); status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod unverified cert: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_NonModuleSAN_Prod — a verified but non-module SAN (not
// kacho-<svc>) is treated as "no module cert" → PermissionDenied in prod.
func TestCallerPolicy_NonModuleSAN_Prod(t *testing.T) {
	p := testPolicy(true)
	ctx := grpcsrv.WithCertIdentity(context.Background(), "spiffe://kacho.cloud/ns/x/sa/not-a-module", true)
	if err := p.allow(ctx, gatewayOnlyMethod); status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod non-module SAN: code = %v, want PermissionDenied", status.Code(err))
	}
}

// ── Unary interceptor ──────────────────────────────────────────────────────

// TestCallerPolicy_Unary_GatewayOnly_NonGatewayCert_Prod — the unary interceptor
// reads info.FullMethod and denies a non-gateway module on a gateway-only RPC.
func TestCallerPolicy_Unary_GatewayOnly_NonGatewayCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.UnaryServerInfo{FullMethod: gatewayOnlyMethod}
	_, err := p.Unary()(newVPCCtx(), nil, info, okHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("unary prod vpc on gateway-only: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_Unary_GatewayOnly_GatewayCert_Prod — gateway cert passes
// through to the handler.
func TestCallerPolicy_Unary_GatewayOnly_GatewayCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.UnaryServerInfo{FullMethod: gatewayOnlyMethod}
	out, err := p.Unary()(newGatewayCtx(), nil, info, okHandler)
	if err != nil {
		t.Fatalf("unary prod gateway on gateway-only: unexpected error %v", err)
	}
	if out != "ok" {
		t.Errorf("unary prod gateway on gateway-only: handler not reached (out=%v)", out)
	}
}

// TestCallerPolicy_Unary_FloorOnly_AnyModule_Prod — any verified module passes a
// non-gateway RPC.
func TestCallerPolicy_Unary_FloorOnly_AnyModule_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.UnaryServerInfo{FullMethod: floorOnlyMethod}
	out, err := p.Unary()(newVPCCtx(), nil, info, okHandler)
	if err != nil {
		t.Fatalf("unary prod vpc on non-gateway: unexpected error %v", err)
	}
	if out != "ok" {
		t.Errorf("unary prod vpc on non-gateway: handler not reached (out=%v)", out)
	}
}

// ── Stream interceptor ─────────────────────────────────────────────────────

// TestCallerPolicy_Stream_GatewayOnly_NonGatewayCert_Prod — the stream
// interceptor enforces the same policy.
func TestCallerPolicy_Stream_GatewayOnly_NonGatewayCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.StreamServerInfo{FullMethod: gatewayOnlyMethod}
	err := p.Stream()(nil, fakeStream{ctx: newVPCCtx()}, info, okStreamHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("stream prod vpc on gateway-only: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_Stream_GatewayOnly_GatewayCert_Prod — gateway cert passes the
// stream interceptor.
func TestCallerPolicy_Stream_GatewayOnly_GatewayCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.StreamServerInfo{FullMethod: gatewayOnlyMethod}
	if err := p.Stream()(nil, fakeStream{ctx: newGatewayCtx()}, info, okStreamHandler); err != nil {
		t.Errorf("stream prod gateway on gateway-only: unexpected error %v", err)
	}
}

// TestGatewayFrontedInternalRPCs_Membership — the canonical gateway-only set
// contains the privileged admin RPCs and excludes the floor-only / fga-proxy
// RPCs (guards against accidental drift).
func TestGatewayFrontedInternalRPCs_Membership(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range GatewayFrontedInternalRPCs() {
		set[m] = struct{}{}
	}

	mustHave := []string{
		"/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"/kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin",
		"/kacho.cloud.iam.v1.InternalClusterService/ListAdmins",
		"/kacho.cloud.iam.v1.InternalClusterService/Get",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/WriteTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReadTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReloadModel",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/GetFGAStoreInfo",
		"/kacho.cloud.iam.v1.InternalIAMService/ForceLogout",
		// SessionRevocations admin/gateway-fronted RPCs: Revoke is driven by
		// the api-gateway logout handler; ListByUser is admin-UI fronted.
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke",
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		"/kacho.cloud.iam.v1.InternalUserService/OnRecoveryCompleted",
	}
	for _, m := range mustHave {
		if _, ok := set[m]; !ok {
			t.Errorf("gateway-only set is missing %q", m)
		}
	}

	mustNotHave := []string{
		"/kacho.cloud.iam.v1.InternalIAMService/Check",
		"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kacho.cloud.iam.v1.InternalIAMService/PollSubjectChanges",
		"/kacho.cloud.iam.v1.InternalIAMService/GetJWKSStatus",
		"/kacho.cloud.iam.v1.InternalIAMService/RegisterResource",
		"/kacho.cloud.iam.v1.InternalIAMService/UnregisterResource",
		"/kacho.cloud.iam.v1.InternalIAMService/WriteCreatorTuple",
		// IsRevoked is the api-gateway hot-path lookup (chicken-and-egg: runs
		// before authz can possibly run) → floor-only, NOT gateway-restricted.
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked",
		"/kacho.cloud.iam.v1.InternalUserService/Get",
	}
	for _, m := range mustNotHave {
		if _, ok := set[m]; ok {
			t.Errorf("gateway-only set must NOT contain %q (floor-only / fga-proxy)", m)
		}
	}
}

// ── RBAC rules-model D: AuthorizeService consumer list-filter edge ───────────
//
// AuthorizeService (ListObjects / BatchCheck / Check) is registered ALSO on the
// internal listener (grpc_register.go) so consumers (vpc/compute/nlb) reach it
// over the verified-mTLS :9091 edge they already reuse for InternalIAMService.
// Check. These tests pin the AUTHZ-ALLOWANCE: the internal caller-policy admits
// a verified module SA on AuthorizeService RPCs (they are NOT gateway-fronted),
// and denies anonymous in prod (fail-closed floor). No new exempt/allowance
// entry is required — the existing floor already permits any verified module SA
// on a non-gateway-fronted RPC. These tests guard against a future change that
// would accidentally gateway-front (or floor-gate) AuthorizeService and break
// the consumer list-filter edge.

// TestCallerPolicy_AuthorizeService_ModuleCert_Allowed — a verified module SA
// (kacho-vpc) may call AuthorizeService.{ListObjects,BatchCheck,Check} on the
// internal listener, prod AND dev (they are floor-only, not gateway-fronted).
func TestCallerPolicy_AuthorizeService_ModuleCert_Allowed(t *testing.T) {
	methods := []string{authorizeListObjectsMethod, authorizeBatchCheckMethod, authorizeCheckMethod}
	for _, prod := range []bool{true, false} {
		p := testPolicy(prod)
		for _, m := range methods {
			if err := p.allow(newVPCCtx(), m); err != nil {
				t.Errorf("prod=%v vpc cert on %s: unexpected error %v (consumer list-filter edge must be admitted)", prod, m, err)
			}
		}
	}
}

// TestCallerPolicy_AuthorizeService_NoCert_Prod — anonymous (no verified module
// cert) calling AuthorizeService.ListObjects in prod → PermissionDenied
// (fail-closed floor). The consumer edge requires a verified module cert.
func TestCallerPolicy_AuthorizeService_NoCert_Prod(t *testing.T) {
	p := testPolicy(true)
	err := p.allow(context.Background(), authorizeListObjectsMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod no cert on AuthorizeService.ListObjects: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_AuthorizeService_Unary_ModuleCert_Prod — the unary
// interceptor lets a verified module SA through to the handler on ListObjects.
func TestCallerPolicy_AuthorizeService_Unary_ModuleCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.UnaryServerInfo{FullMethod: authorizeListObjectsMethod}
	out, err := p.Unary()(newVPCCtx(), nil, info, okHandler)
	if err != nil {
		t.Fatalf("unary prod vpc on AuthorizeService.ListObjects: unexpected error %v", err)
	}
	if out != "ok" {
		t.Errorf("unary prod vpc on AuthorizeService.ListObjects: handler not reached (out=%v)", out)
	}
}

// TestAuthorizeService_NotGatewayFronted — drift-guard: the AuthorizeService RPCs
// consumers reuse on the internal edge must NOT be in the gateway-only set, else
// a non-gateway module SA (vpc/compute/nlb) would be denied and the per-object
// List filter would fail-closed (empty List for every caller).
func TestAuthorizeService_NotGatewayFronted(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range GatewayFrontedInternalRPCs() {
		set[m] = struct{}{}
	}
	for _, m := range []string{authorizeListObjectsMethod, authorizeBatchCheckMethod, authorizeCheckMethod,
		"/kacho.cloud.iam.v1.AuthorizeService/ListSubjects"} {
		if _, ok := set[m]; ok {
			t.Errorf("AuthorizeService RPC %q must NOT be gateway-fronted (consumer module-SA edge would be denied)", m)
		}
	}
}

// TestAuthorizeService_NotSystemViewerFloored — drift-guard: the AuthorizeService
// RPCs must NOT be in the system_viewer ReadFloorRPCs. They are NOT in that set,
// so the floor is a no-op pass for them; gating them would require every consumer
// module-SA to hold `system_viewer@cluster` (which it may not) and break the
// list-filter edge. (The per-user authz is the EXPLICIT subject in the request,
// resolved by FGA inside the handler — not the caller module-SA.)
func TestAuthorizeService_NotSystemViewerFloored(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range ReadFloorRPCs() {
		set[m] = struct{}{}
	}
	for _, m := range []string{authorizeListObjectsMethod, authorizeBatchCheckMethod, authorizeCheckMethod,
		"/kacho.cloud.iam.v1.AuthorizeService/ListSubjects"} {
		if _, ok := set[m]; ok {
			t.Errorf("AuthorizeService RPC %q must NOT be system_viewer-floored (consumer module-SA may not hold system_viewer)", m)
		}
	}
}
