// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// SAN для таблицы политики вызывающего. Учётка края — единственный законный
// вызывающий привилегированных админских RPC за краем; SAN любого другого
// модуля (например, модуля vpc) — модуль не-край.
const (
	gatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/mod-api-gateway"
	vpcSAN     = "spiffe://kacho.cloud/ns/kacho/sa/mod-vpc"

	// gatewayOnlyMethod — a representative gateway-fronted privileged admin RPC.
	gatewayOnlyMethod = "/kaname.cloud.iam.v1.InternalClusterService/GrantAdmin"
	// floorOnlyMethod — a non-gateway RPC: any verified module may call it.
	floorOnlyMethod = "/kaname.cloud.iam.v1.InternalIAMService/Check"

	// authorizeBatchCheckMethod — RPC, которым пообъектный фильтр страницы
	// (модули vpc / compute / nlb) судит идентификаторы СВОЕЙ страницы
	// service→service по ребру проверенного mTLS (:9091). НЕ gateway-fronted:
	// звать вправе любая проверенная модульная SA — явный субъект в запросе есть
	// авторизационный вид, а НЕ доступ вызывающего.
	//
	// Здесь стоял `AuthorizeService/ListObjects`, и он был представителем этого
	// ребра. RPC снят вместе с внешним движком: перечисление у чужого хранилища
	// имело жёсткий предел и не имело продолжения, поэтому объекты сверх предела
	// становились владельцу невидимы навсегда при живых правах. Утверждение о
	// снятом имени ничего не защищает — представителем ребра стал тот вызов,
	// который его сегодня несёт.
	authorizeBatchCheckMethod = "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"
	// authorizeCheckMethod / authorizeListSubjectsMethod — остальные RPC
	// AuthorizeService, которые потребители держат на том же ребре.
	authorizeCheckMethod        = "/kaname.cloud.iam.v1.AuthorizeService/Check"
	authorizeListSubjectsMethod = "/kaname.cloud.iam.v1.AuthorizeService/ListSubjects"
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
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), gatewaySAN, true)
}

// newVPCCtx — контекст с SAN проверенного сертификата модуля vpc.
func newVPCCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), vpcSAN, true)
}

// testPolicy builds a CallerPolicy with the canonical gateway-only set.
func testPolicy(prod bool) *CallerPolicy {
	return NewCallerPolicy(prod, GatewayFrontedInternalRPCs()).WithModuleRoster(testModuleRoster())
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

// TestCallerPolicy_GatewayOnly_NonGatewayCert_Prod — проверенный модуль не-край
// (vpc) зовёт RPC «только край» в боевой посадке → PermissionDenied (закрывает
// C1/C3 аудита: скомпрометированный модуль плоскости данных прав не поднимает).
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

// TestCallerPolicy_FloorOnly_AnyModuleCert — любой проверенный модуль (vpc)
// вправе звать RPC не за краем, в боевой посадке и в посадке разработки.
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
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), gatewaySAN, false)
	if err := p.allow(ctx, gatewayOnlyMethod); status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod unverified cert: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_NonModuleSAN_Prod — проверенный, но не модульный SAN (учётка
// не объявленной формы имени службы) считается «сертификата модуля нет» →
// PermissionDenied в боевой посадке.
func TestCallerPolicy_NonModuleSAN_Prod(t *testing.T) {
	p := testPolicy(true)
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/x/sa/not-a-module", true)
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
		"/kaname.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"/kaname.cloud.iam.v1.InternalClusterService/RevokeAdmin",
		"/kaname.cloud.iam.v1.InternalClusterService/ListAdmins",
		"/kaname.cloud.iam.v1.InternalClusterService/Get",
		"/kaname.cloud.iam.v1.InternalIAMService/ForceLogout",
		// SessionRevocations admin/gateway-fronted RPCs: Revoke is driven by
		// the api-gateway logout handler; ListByUser is admin-UI fronted.
		"/kaname.cloud.iam.v1.InternalSessionRevocationsService/Revoke",
		"/kaname.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
	}
	for _, m := range mustHave {
		if _, ok := set[m]; !ok {
			t.Errorf("gateway-only set is missing %q", m)
		}
	}

	mustNotHave := []string{
		"/kaname.cloud.iam.v1.InternalIAMService/Check",
		"/kaname.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kaname.cloud.iam.v1.InternalIAMService/PollSubjectChanges",
		"/kaname.cloud.iam.v1.InternalIAMService/RegisterResource",
		"/kaname.cloud.iam.v1.InternalIAMService/UnregisterResource",
		// Здесь стояла WriteCreatorTuple. Запись снята вместе с RPC (kacho#788):
		// имени, которого нет в контракте, отрицание не о чем утверждать —
		// оно проходило бы всегда и ничего не проверяло.
		// IsRevoked is the api-gateway hot-path lookup (chicken-and-egg: runs
		// before authz can possibly run) → floor-only, NOT gateway-restricted.
		"/kaname.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked",
		"/kaname.cloud.iam.v1.InternalUserService/Get",
	}
	for _, m := range mustNotHave {
		if _, ok := set[m]; ok {
			t.Errorf("gateway-only set must NOT contain %q (floor-only / fga-proxy)", m)
		}
	}
}

// ── RBAC rules-model D: AuthorizeService consumer list-filter edge ───────────
//
// AuthorizeService (BatchCheck / Check / ListSubjects) is registered ALSO on the
// internal listener (grpc_register.go) so consumers (vpc/compute/nlb) reach it
// over the verified-mTLS :9091 edge they already reuse for InternalIAMService.
// Check. These tests pin the AUTHZ-ALLOWANCE: the internal caller-policy admits
// a verified module SA on AuthorizeService RPCs (they are NOT gateway-fronted),
// and denies anonymous in prod (fail-closed floor). No new exempt/allowance
// entry is required — the existing floor already permits any verified module SA
// on a non-gateway-fronted RPC. These tests guard against a future change that
// would accidentally gateway-front (or floor-gate) AuthorizeService and break
// the consumer list-filter edge.

// TestCallerPolicy_AuthorizeService_ModuleCert_Allowed — проверенная учётка
// модуля (vpc) вправе звать AuthorizeService.{BatchCheck,Check} на внутреннем
// слушателе в боевой посадке И в посадке разработки: за краем они не стоят и
// входят в профиль модуля-владельца. ListSubjects в этот профиль не входит
// (kaname#984): его не зовёт ни один модуль, и в боевой посадке он отвергается —
// см. соседнюю пробу ниже.
func TestCallerPolicy_AuthorizeService_ModuleCert_Allowed(t *testing.T) {
	methods := []string{authorizeBatchCheckMethod, authorizeCheckMethod}
	for _, prod := range []bool{true, false} {
		p := testPolicy(prod)
		for _, m := range methods {
			if err := p.allow(newVPCCtx(), m); err != nil {
				t.Errorf("prod=%v vpc cert on %s: unexpected error %v (consumer list-filter edge must be admitted)", prod, m, err)
			}
		}
	}
}

// TestCallerPolicy_AuthorizeService_ListSubjectsOutsideModuleProfile — a
// module-writer identity on AuthorizeService.ListSubjects (outside its profile,
// kaname#984): prod → PermissionDenied; the edge, whose profile names it, passes.
func TestCallerPolicy_AuthorizeService_ListSubjectsOutsideModuleProfile(t *testing.T) {
	p := testPolicy(true)
	if err := p.allow(newVPCCtx(), authorizeListSubjectsMethod); status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod vpc on ListSubjects: code = %v, want PermissionDenied", status.Code(err))
	}
	if err := p.allow(newGatewayCtx(), authorizeListSubjectsMethod); err != nil {
		t.Errorf("prod gateway on ListSubjects: unexpected error %v", err)
	}
}

// TestCallerPolicy_AuthorizeService_NoCert_Prod — anonymous (no verified module
// cert) calling AuthorizeService.BatchCheck in prod → PermissionDenied
// (fail-closed floor). The consumer edge requires a verified module cert.
func TestCallerPolicy_AuthorizeService_NoCert_Prod(t *testing.T) {
	p := testPolicy(true)
	err := p.allow(context.Background(), authorizeBatchCheckMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("prod no cert on AuthorizeService.BatchCheck: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestCallerPolicy_AuthorizeService_Unary_ModuleCert_Prod — the unary
// interceptor lets a verified module SA through to the handler on BatchCheck.
func TestCallerPolicy_AuthorizeService_Unary_ModuleCert_Prod(t *testing.T) {
	p := testPolicy(true)
	info := &grpc.UnaryServerInfo{FullMethod: authorizeBatchCheckMethod}
	out, err := p.Unary()(newVPCCtx(), nil, info, okHandler)
	if err != nil {
		t.Fatalf("unary prod vpc on AuthorizeService.BatchCheck: unexpected error %v", err)
	}
	if out != "ok" {
		t.Errorf("unary prod vpc on AuthorizeService.BatchCheck: handler not reached (out=%v)", out)
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
	for _, m := range []string{authorizeBatchCheckMethod, authorizeCheckMethod, authorizeListSubjectsMethod} {
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
	for _, m := range []string{authorizeBatchCheckMethod, authorizeCheckMethod, authorizeListSubjectsMethod} {
		if _, ok := set[m]; ok {
			t.Errorf("AuthorizeService RPC %q must NOT be system_viewer-floored (consumer module-SA may not hold system_viewer)", m)
		}
	}
}
