// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

import (
	"context"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// acr_floor_test.go — unit tests for ACRFloor.
//
// The floor enforces `acr >= required_acr_min` for gateway-fronted internal RPCs
// (those whose caller-context = api-gateway acting for an end user) whose catalog
// `required_acr_min > 0`. acr is read from the trusted ctx
// (grpcsrv.TrustedACRFromContext).
//
// Drives the floor through a fake catalog (FQN→acr_min) + a fabricated trusted
// acr ctx (grpcsrv.WithCertIdentity + x-kacho-token-acr metadata) — no Postgres,
// no FGA, no live handshake.

// ── fixtures ────────────────────────────────────────────────────────────────

const (
	// grantAdminMethod — a gateway-fronted RPC with required_acr_min=2 (immediate effect).
	grantAdminMethod = "/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin"
	// revokeMethod — a gateway-fronted RPC with required_acr_min=0 today.
	revokeMethod = "/kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke"
	// registerNonGateway — a NON-gateway-fronted internal RPC (module SA caller).
	registerNonGateway = "/kacho.cloud.iam.v1.InternalIAMService/RegisterResource"
	// forceLogoutMethod — gateway-fronted, acr_min=0 in prod (raised to 2 only in the fixture).
	forceLogoutMethod = "/kacho.cloud.iam.v1.InternalIAMService/ForceLogout"
)

// fakeACRCatalog maps gRPC full-method (catalog FQN without the leading slash)
// → required_acr_min. Mirrors the embedded permission catalog for the test.
type fakeACRCatalog map[string]string

// RequiredACRMin satisfies the ACRRequirementLookup port. The key is the catalog
// FQN (no leading slash), so the floor must strip the gRPC full-method's slash.
func (c fakeACRCatalog) RequiredACRMin(fqn string) string { return c[fqn] }

func realisticCatalog() fakeACRCatalog {
	return fakeACRCatalog{
		"kacho.cloud.iam.v1.InternalClusterService/GrantAdmin":        "2",
		"kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin":       "2",
		"kacho.cloud.iam.v1.InternalClusterService/ListAdmins":        "2",
		"kacho.cloud.iam.v1.InternalClusterService/Get":               "2",
		"kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke": "", // acr_min 0
		"kacho.cloud.iam.v1.InternalIAMService/ForceLogout":           "", // acr_min 0 (prod)
	}
}

// gatewayACRCtx returns a ctx as the trust-aware extract would leave it for a
// verified api-gateway peer forwarding the given acr.
func gatewayACRCtx(acr string) context.Context {
	ctx := grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, true)
	return grpcsrv.WithTrustedACR(ctx, acr, true)
}

func newACRFloor(prod bool) *ACRFloor {
	return NewACRFloor(realisticCatalog(), GatewayFrontedInternalRPCs()).WithProductionMode(prod)
}

// ── acr ≥ required → allowed ────────────────────────────────────────────────

func TestACRFloor_0401_AcrMeetsFloor_Allowed(t *testing.T) {
	f := newACRFloor(true)
	if err := f.allow(gatewayACRCtx("2"), grantAdminMethod); err != nil {
		t.Fatalf("acr=2 ≥ required=2 must pass, got %v", err)
	}
	if err := f.allow(gatewayACRCtx("3"), grantAdminMethod); err != nil {
		t.Fatalf("acr=3 ≥ required=2 must pass, got %v", err)
	}
}

// ── acr < required → PermissionDenied + step-up signal ───────────────────────

func TestACRFloor_0402_AcrBelowFloor_Denied(t *testing.T) {
	f := newACRFloor(true)
	err := f.allow(gatewayACRCtx("1"), grantAdminMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("acr=1 < required=2 must be PermissionDenied, got %v", err)
	}
	// Stable non-leaking message.
	if got := status.Convert(err).Message(); got != "permission denied" {
		t.Fatalf("message must be verbatim 'permission denied', got %q", got)
	}
	// Step-up signal in details (PreconditionFailure with acr_values), consistent
	// with the public buildGRPCDenyStatus precedent.
	assertStepUpDetail(t, err, "2")
}

// ── acr metadata absent on an acr-requiring RPC → fail-closed deny ───────────

func TestACRFloor_0403_AcrAbsent_FailClosed(t *testing.T) {
	f := newACRFloor(true)
	// Trusted gateway peer but NO acr forwarded (TrustedACR present-but-empty).
	ctx := grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, true)
	ctx = grpcsrv.WithTrustedACR(ctx, "", true)
	err := f.allow(ctx, grantAdminMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("absent acr on acr-requiring RPC must be PermissionDenied (fail-closed), got %v", err)
	}
	assertStepUpDetail(t, err, "2")
}

// ── gateway-fronted RPC with required_acr_min=0 → not checked ────────────────

func TestACRFloor_0404_AcrMinZero_NotChecked(t *testing.T) {
	f := newACRFloor(true)
	// acr=0 (or absent) on an acr_min=0 RPC → pass (no-op floor).
	if err := f.allow(gatewayACRCtx("0"), revokeMethod); err != nil {
		t.Fatalf("acr_min=0 RPC must pass regardless of acr, got %v", err)
	}
	ctx := grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, true)
	ctx = grpcsrv.WithTrustedACR(ctx, "", true)
	if err := f.allow(ctx, revokeMethod); err != nil {
		t.Fatalf("acr_min=0 RPC with absent acr must pass, got %v", err)
	}
}

// ── non-gateway service-caller on a non-gateway internal RPC → exempt ────────

func TestACRFloor_0405_NonGatewayRPC_Exempt(t *testing.T) {
	f := newACRFloor(true)
	// kacho-vpc module SA, no user-acr, calling a non-gateway-fronted RPC.
	ctx := grpcsrv.WithCertIdentity(context.Background(), vpcSAN, true)
	ctx = grpcsrv.WithTrustedACR(ctx, "", true)
	if err := f.allow(ctx, registerNonGateway); err != nil {
		t.Fatalf("non-gateway-fronted RPC must be acr-exempt (service→service), got %v", err)
	}
}

// ── dev-mode no-op (default-OFF), even on an acr_min=2 RPC ───────────────────

func TestACRFloor_0407_DevMode_NoOp(t *testing.T) {
	f := newACRFloor(false) // dev
	// Any/absent acr on the acr_min=2 RPC → pass (byte-identical to today).
	if err := f.allow(gatewayACRCtx("0"), grantAdminMethod); err != nil {
		t.Fatalf("dev-mode acr-floor must be a no-op, got %v", err)
	}
	if err := f.allow(gatewayACRCtx(""), grantAdminMethod); err != nil {
		t.Fatalf("dev-mode acr-floor must be a no-op (absent acr), got %v", err)
	}
}

// ── fixture raises required_acr_min>0 on a previously-0 RPC ──────────────────

func TestACRFloor_0408_FixtureRaisesAcrMin_FloorFires(t *testing.T) {
	// Fixture catalog: ForceLogout now requires acr_min=2.
	cat := realisticCatalog()
	cat["kacho.cloud.iam.v1.InternalIAMService/ForceLogout"] = "2"
	f := NewACRFloor(cat, GatewayFrontedInternalRPCs()).WithProductionMode(true)

	// acr=1 < 2 → denied.
	if status.Code(f.allow(gatewayACRCtx("1"), forceLogoutMethod)) != codes.PermissionDenied {
		t.Fatalf("fixture acr_min=2 on ForceLogout: acr=1 must be denied")
	}
	// acr=2 → passes the floor.
	if err := f.allow(gatewayACRCtx("2"), forceLogoutMethod); err != nil {
		t.Fatalf("fixture acr_min=2 on ForceLogout: acr=2 must pass, got %v", err)
	}
}

// ── interceptor wrapper ───────────────────────────────────────────────────────

func TestACRFloor_Unary_DeniesBeforeHandler(t *testing.T) {
	f := newACRFloor(true)
	handlerCalled := false
	final := func(_ context.Context, _ any) (any, error) { handlerCalled = true; return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: grantAdminMethod}
	_, err := f.Unary()(gatewayACRCtx("1"), nil, info, final)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if handlerCalled {
		t.Fatal("handler must NOT be called on acr-deny (no side-effect)")
	}
}

// ── helper: assert the step-up detail (PreconditionFailure with acr_values) ───

func assertStepUpDetail(t *testing.T, err error, wantACRValues string) {
	t.Helper()
	st := status.Convert(err)
	for _, d := range st.Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				if v.GetType() == "authz.step_up" {
					if v.GetSubject() != "acr_values:"+wantACRValues {
						t.Fatalf("step-up violation must carry acr_values:%s, got subject %q", wantACRValues, v.GetSubject())
					}
					return
				}
			}
		}
	}
	t.Fatalf("expected a step-up PreconditionFailure violation (acr_values=%s) in status details", wantACRValues)
}
