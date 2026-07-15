// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// system_viewer_floor_test.go — unit tests for SystemViewerFloor.
//
// Drives the floor through a fake RelationChecker (no Postgres / no FGA, mirror
// of the RelationWriteGate tests) + a fabricated grpcsrv.CertIdentity context.
// Scenarios map 1:1 to the SystemViewerFloor invariants (INV-FLOOR-1..8).

// ── fake RelationChecker ────────────────────────────────────────────────────

// recordingChecker records the (subject, relation, object) of every Check and
// returns canned (allowed, err). It is the only collaborator the floor needs.
type recordingChecker struct {
	allowed bool
	err     error

	calls    int
	subject  string
	relation string
	object   string
}

func (c *recordingChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	c.calls++
	c.subject, c.relation, c.object = subject, relation, object
	return c.allowed, c.err
}

// ── SAN / FQN test fixtures ─────────────────────────────────────────────────

const (
	apiGatewayFloorSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	vpcFloorSAN        = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	someOtherSAN       = "spiffe://kacho.cloud/ns/kacho/sa/kacho-someother"

	// readFloorMethod — a representative READ-RPC under the floor.
	readFloorMethod = "/kacho.cloud.iam.v1.InternalIAMService/LookupSubject"
	// checkMethod — the PDP, exempt from the floor (INV-FLOOR-5).
	checkMethod = "/kacho.cloud.iam.v1.InternalIAMService/Check"
	// recoveryMethod — secret-authed Kratos hook, exempt (INV-FLOOR-6).
	recoveryMethod = "/kacho.cloud.iam.v1.InternalUserService/OnRecoveryCompleted"
	// isRevokedMethod — hot-path, exempt (INV-FLOOR-6).
	isRevokedMethod = "/kacho.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked"
	// registerMethod — mutation, exempt from READ-floor (INV-FLOOR-8).
	registerMethod = "/kacho.cloud.iam.v1.InternalIAMService/RegisterResource"
)

// ctxWithSAN returns a ctx carrying a verified module cert SAN.
func ctxWithSAN(san string) context.Context {
	return grpcsrv.WithCertIdentity(context.Background(), san, true)
}

// 01-unit — dev-mode (prod=false), READ-FQN → pass; checker NOT consulted.
func TestSystemViewerFloor_DevMode_NoOp(t *testing.T) {
	ck := &recordingChecker{allowed: false, err: errors.New("must not be called")}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(false)
	if err := f.allow(ctxWithSAN(apiGatewayFloorSAN), readFloorMethod); err != nil {
		t.Fatalf("dev-mode READ-FQN: unexpected error %v", err)
	}
	if ck.calls != 0 {
		t.Errorf("dev-mode must short-circuit before checker (calls=%d, want 0)", ck.calls)
	}
}

// 02-unit — prod-mode, verified api-gateway SAN, checker→allowed → pass; assert
// the EXACT Check triple (subject = derived sva, relation, cluster object).
func TestSystemViewerFloor_Prod_LegitimateReaderSA_Allowed(t *testing.T) {
	ck := &recordingChecker{allowed: true}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	if err := f.allow(ctxWithSAN(apiGatewayFloorSAN), readFloorMethod); err != nil {
		t.Fatalf("prod legitimate reader-SA: unexpected error %v", err)
	}
	wantSubject := "service_account:" + ServiceAccountIDForService("api-gateway")
	if ck.subject != wantSubject {
		t.Errorf("Check subject = %q, want %q (caller module-SA, NOT end-user)", ck.subject, wantSubject)
	}
	if ck.relation != "system_viewer" {
		t.Errorf("Check relation = %q, want %q", ck.relation, "system_viewer")
	}
	if ck.object != "cluster:cluster_kacho_root" {
		t.Errorf("Check object = %q, want %q", ck.object, "cluster:cluster_kacho_root")
	}
}

// 03-unit — prod-mode, verified SAN, checker→allowed=false → PermissionDenied.
func TestSystemViewerFloor_Prod_NoSystemViewer_Denied(t *testing.T) {
	ck := &recordingChecker{allowed: false}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	err := f.allow(ctxWithSAN(someOtherSAN), readFloorMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prod module-SA without system_viewer: code = %v, want PermissionDenied", status.Code(err))
	}
	if got := status.Convert(err).Message(); got != "permission denied" {
		t.Errorf("message = %q, want verbatim %q", got, "permission denied")
	}
}

// 03-unit no-cert sub-case — prod-mode, no verified module SAN → PermissionDenied
// (fail-closed; checker NOT consulted).
func TestSystemViewerFloor_Prod_NoCert_Denied(t *testing.T) {
	ck := &recordingChecker{allowed: true} // would pass if (wrongly) consulted
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	err := f.allow(context.Background(), readFloorMethod) // no cert identity
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prod no-cert: code = %v, want PermissionDenied", status.Code(err))
	}
	if ck.calls != 0 {
		t.Errorf("prod no-cert must fail closed before checker (calls=%d, want 0)", ck.calls)
	}
}

// 03-unit unverified-cert sub-case — present-but-UNVERIFIED cert → PermissionDenied.
func TestSystemViewerFloor_Prod_UnverifiedCert_Denied(t *testing.T) {
	ck := &recordingChecker{allowed: true}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	ctx := grpcsrv.WithCertIdentity(context.Background(), apiGatewayFloorSAN, false)
	if err := f.allow(ctx, readFloorMethod); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prod unverified cert: code = %v, want PermissionDenied", status.Code(err))
	}
	if ck.calls != 0 {
		t.Errorf("prod unverified cert must fail closed before checker (calls=%d)", ck.calls)
	}
}

// 03-unit foreign-SAN sub-case — verified but non-module SAN → PermissionDenied.
func TestSystemViewerFloor_Prod_NonModuleSAN_Denied(t *testing.T) {
	ck := &recordingChecker{allowed: true}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	ctx := ctxWithSAN("spiffe://other.domain/ns/x/sa/not-a-module")
	if err := f.allow(ctx, readFloorMethod); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prod foreign SAN: code = %v, want PermissionDenied", status.Code(err))
	}
	if ck.calls != 0 {
		t.Errorf("prod foreign SAN must fail closed before checker (calls=%d)", ck.calls)
	}
}

// 03b-unit — prod-mode, checker→error → Unavailable (NOT pass, NOT PermissionDenied);
// message verbatim.
func TestSystemViewerFloor_Prod_BackendError_Unavailable(t *testing.T) {
	ck := &recordingChecker{err: errors.New("fga 503")}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	err := f.allow(ctxWithSAN(apiGatewayFloorSAN), readFloorMethod)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("prod backend error: code = %v, want Unavailable", status.Code(err))
	}
	if got := status.Convert(err).Message(); got != "authz backend unavailable" {
		t.Errorf("message = %q, want verbatim %q (no backend leak)", got, "authz backend unavailable")
	}
}

// 03b-unit nil-checker sub-case — prod-mode, checker not wired → PermissionDenied
// (fail-closed, never silently allow).
func TestSystemViewerFloor_Prod_NilChecker_Denied(t *testing.T) {
	f := NewSystemViewerFloor(nil, ReadFloorRPCs()).WithProductionMode(true)
	if err := f.allow(ctxWithSAN(apiGatewayFloorSAN), readFloorMethod); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prod nil checker: code = %v, want PermissionDenied", status.Code(err))
	}
}

// 04-unit — InternalIAMService/Check (NON-floor FQN) → pass without consulting
// the checker, even in prod-mode (PDP-exempt regression guard, INV-FLOOR-5).
func TestSystemViewerFloor_Prod_CheckExempt(t *testing.T) {
	ck := &recordingChecker{allowed: false} // would DENY if (wrongly) consulted
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	if err := f.allow(ctxWithSAN(vpcFloorSAN), checkMethod); err != nil {
		t.Fatalf("prod Check (PDP): unexpected error %v — must NOT be floor-gated", err)
	}
	if ck.calls != 0 {
		t.Errorf("Check must not consult the floor checker (calls=%d, want 0)", ck.calls)
	}
}

// 05/06-unit — secret-authed webhook OnRecoveryCompleted + hot-path IsRevoked
// (NON-floor FQNs) → pass without consulting the checker (INV-FLOOR-6).
func TestSystemViewerFloor_Prod_ExemptWebhookAndHotPath(t *testing.T) {
	for _, m := range []string{recoveryMethod, isRevokedMethod} {
		ck := &recordingChecker{allowed: false}
		f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
		if err := f.allow(ctxWithSAN(apiGatewayFloorSAN), m); err != nil {
			t.Errorf("prod exempt %s: unexpected error %v", m, err)
		}
		if ck.calls != 0 {
			t.Errorf("prod exempt %s must not consult checker (calls=%d)", m, ck.calls)
		}
	}
}

// 09-unit — RegisterResource (NON-floor FQN) → floor pass; the floor adds NO
// system_viewer requirement on the write-RPC (write-gate is independent).
func TestSystemViewerFloor_Prod_MutationExempt(t *testing.T) {
	ck := &recordingChecker{allowed: false}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	if err := f.allow(ctxWithSAN(vpcFloorSAN), registerMethod); err != nil {
		t.Fatalf("prod RegisterResource: floor must NOT impose system_viewer (err=%v)", err)
	}
	if ck.calls != 0 {
		t.Errorf("floor must not gate the mutation RPC (calls=%d)", ck.calls)
	}
}

// set-membership-unit — every READ-FQN is gated; every exempt FQN is NOT.
func TestReadFloorRPCs_Membership(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range ReadFloorRPCs() {
		set[m] = struct{}{}
	}

	mustHave := []string{
		"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kacho.cloud.iam.v1.InternalIAMService/GetJWKSStatus",
		"/kacho.cloud.iam.v1.InternalIAMService/PollSubjectChanges",
		"/kacho.cloud.iam.v1.InternalUserService/Get",
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReadTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/GetFGAStoreInfo",
	}
	for _, m := range mustHave {
		if _, ok := set[m]; !ok {
			t.Errorf("ReadFloorRPCs is missing READ-RPC %q", m)
		}
	}

	mustNotHave := []string{
		// PDP — never floor-gated (INV-FLOOR-5).
		"/kacho.cloud.iam.v1.InternalIAMService/Check",
		// secret-authed webhook (INV-FLOOR-6).
		"/kacho.cloud.iam.v1.InternalUserService/OnRecoveryCompleted",
		// hot-path chicken-and-egg (INV-FLOOR-6).
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked",
		// mutations — fga_writer-gated in-handler, not READ-floor (INV-FLOOR-8).
		"/kacho.cloud.iam.v1.InternalIAMService/RegisterResource",
		"/kacho.cloud.iam.v1.InternalIAMService/UnregisterResource",
		"/kacho.cloud.iam.v1.InternalIAMService/WriteCreatorTuple",
		// gateway-only / admin-tier mutations — not READ-floor.
		"/kacho.cloud.iam.v1.InternalIAMService/ForceLogout",
		"/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"/kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/WriteTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReloadModel",
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke",
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
	}
	for _, m := range mustNotHave {
		if _, ok := set[m]; ok {
			t.Errorf("ReadFloorRPCs must NOT contain %q (exempt)", m)
		}
	}
}

// ── Unary / Stream interceptor wrappers ─────────────────────────────────────

// fakeFloorStream is a minimal grpc.ServerStream carrying a custom context.
type fakeFloorStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeFloorStream) Context() context.Context { return s.ctx }

func floorOkHandler(_ context.Context, _ any) (any, error) { return "ok", nil }

func floorOkStream(_ any, _ grpc.ServerStream) error { return nil }

// Unary — denied READ-RPC short-circuits before the handler in prod.
func TestSystemViewerFloor_Unary_Denied_Prod(t *testing.T) {
	ck := &recordingChecker{allowed: false}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	info := &grpc.UnaryServerInfo{FullMethod: readFloorMethod}
	out, err := f.Unary()(ctxWithSAN(someOtherSAN), nil, info, floorOkHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unary prod denied: code = %v, want PermissionDenied", status.Code(err))
	}
	if out != nil {
		t.Errorf("handler must not be reached on deny (out=%v)", out)
	}
}

// Unary — allowed READ-RPC reaches the handler in prod.
func TestSystemViewerFloor_Unary_Allowed_Prod(t *testing.T) {
	ck := &recordingChecker{allowed: true}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	info := &grpc.UnaryServerInfo{FullMethod: readFloorMethod}
	out, err := f.Unary()(ctxWithSAN(apiGatewayFloorSAN), nil, info, floorOkHandler)
	if err != nil {
		t.Fatalf("unary prod allowed: unexpected error %v", err)
	}
	if out != "ok" {
		t.Errorf("handler not reached (out=%v)", out)
	}
}

// Stream — denied READ-RPC short-circuits in prod.
func TestSystemViewerFloor_Stream_Denied_Prod(t *testing.T) {
	ck := &recordingChecker{allowed: false}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(true)
	info := &grpc.StreamServerInfo{FullMethod: readFloorMethod}
	err := f.Stream()(nil, fakeFloorStream{ctx: ctxWithSAN(someOtherSAN)}, info, floorOkStream)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("stream prod denied: code = %v, want PermissionDenied", status.Code(err))
	}
}

// Stream — dev-mode is a no-op pass even on a READ-RPC.
func TestSystemViewerFloor_Stream_DevNoOp(t *testing.T) {
	ck := &recordingChecker{allowed: false, err: errors.New("must not be called")}
	f := NewSystemViewerFloor(ck, ReadFloorRPCs()).WithProductionMode(false)
	info := &grpc.StreamServerInfo{FullMethod: readFloorMethod}
	if err := f.Stream()(nil, fakeFloorStream{ctx: context.Background()}, info, floorOkStream); err != nil {
		t.Errorf("stream dev no-op: unexpected error %v", err)
	}
	if ck.calls != 0 {
		t.Errorf("stream dev no-op must not consult checker (calls=%d)", ck.calls)
	}
}
