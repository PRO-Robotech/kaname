// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// caller_policy_bootstrap_mint_test.go — the bootstrap-admin token mint is gated
// by an EXPLICIT per-RPC SPIFFE allow-list, i.e. by a verified CLIENT CERTIFICATE
// of a named identity — never by network position.
//
// InternalBootstrapTokenService/MintBootstrapToken returns a Hydra-signed RS256
// Bearer for a cluster `system_admin` ServiceAccount, and it cannot carry a
// ReBAC relation gate (it exists to obtain the FIRST token, where no token
// exists yet — chicken-and-egg). The credential it DOES require is therefore the
// caller's mTLS identity: only the SANs an operator explicitly allow-lists may
// mint. "Any verified module cert" is NOT enough — a compromised data-plane
// module (kacho-vpc, kacho-compute) must not be able to mint cluster-admin.
//
// Fail-closed everywhere: an EMPTY allow-list denies every caller (the mint has
// no default caller), and the gate is enforced in dev as well as production —
// unlike the floor/gateway-only arms, whose dev no-op is insecure back-compat.
// A cluster-admin mint has no defensible insecure back-compat (core rule #16).

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

const (
	// bootstrapMintMethod — the RPC under test.
	bootstrapMintMethod = "/kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken"
	// seedRunnerSAN — the allow-listed operator/CI identity.
	seedRunnerSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-seeder"
)

// mintPolicy builds a CallerPolicy with the mint allow-list populated.
func mintPolicy(prod bool, sans ...string) *CallerPolicy {
	return NewCallerPolicy(prod, GatewayFrontedInternalRPCs()).
		WithSANAllowlist(map[string][]string{bootstrapMintMethod: sans})
}

// TestCallerPolicy_BootstrapMint_AllowlistedSAN_Allowed — the named identity may
// mint, in every mode.
func TestCallerPolicy_BootstrapMint_AllowlistedSAN_Allowed(t *testing.T) {
	for _, prod := range []bool{true, false} {
		p := mintPolicy(prod, seedRunnerSAN)
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), seedRunnerSAN, true)
		if err := p.allow(ctx, bootstrapMintMethod); err != nil {
			t.Errorf("prod=%v allow-listed SAN: unexpected error %v", prod, err)
		}
	}
}

// TestCallerPolicy_BootstrapMint_UnlistedSAN_Denied — ANY other verified module
// cert (the gateway SA included) is denied: a verified cert is not by itself a
// licence to mint cluster-admin.
func TestCallerPolicy_BootstrapMint_UnlistedSAN_Denied(t *testing.T) {
	for _, prod := range []bool{true, false} {
		for _, san := range []string{gatewaySAN, vpcSAN} {
			p := mintPolicy(prod, seedRunnerSAN)
			ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), san, true)
			err := p.allow(ctx, bootstrapMintMethod)
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("prod=%v san=%s: got %v, want PermissionDenied", prod, san, err)
			}
			if err != nil && status.Convert(err).Message() != "permission denied" {
				t.Errorf("deny message must stay the verbatim non-leaking text, got %q",
					status.Convert(err).Message())
			}
		}
	}
}

// TestCallerPolicy_BootstrapMint_NoVerifiedCert_Denied — no client certificate =
// no credential = deny, in EVERY mode (no dev no-op for the mint).
func TestCallerPolicy_BootstrapMint_NoVerifiedCert_Denied(t *testing.T) {
	for _, prod := range []bool{true, false} {
		p := mintPolicy(prod, seedRunnerSAN)
		for name, ctx := range map[string]context.Context{
			"no cert":       context.Background(),
			"unverified":    grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), seedRunnerSAN, false),
			"empty san":     grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), "", true),
			"non-spiffe id": grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), "cn=whoever", true),
		} {
			if status.Code(p.allow(ctx, bootstrapMintMethod)) != codes.PermissionDenied {
				t.Errorf("prod=%v %s: want PermissionDenied", prod, name)
			}
		}
	}
}

// TestCallerPolicy_BootstrapMint_EmptyAllowlist_DeniesEveryone — an unconfigured
// allow-list is fail-CLOSED, not fail-open (the mint simply has no caller).
func TestCallerPolicy_BootstrapMint_EmptyAllowlist_DeniesEveryone(t *testing.T) {
	for _, prod := range []bool{true, false} {
		for _, p := range []*CallerPolicy{
			mintPolicy(prod), // declared, empty
			NewCallerPolicy(prod, GatewayFrontedInternalRPCs()), // never configured
			mintPolicy(prod).WithSANAllowlist(nil),              // explicitly cleared
		} {
			ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), seedRunnerSAN, true)
			if status.Code(p.allow(ctx, bootstrapMintMethod)) != codes.PermissionDenied {
				t.Errorf("prod=%v empty allow-list must deny every caller", prod)
			}
		}
	}
}

// TestCallerPolicy_BootstrapMint_NotGatewayFronted — the mint is no longer
// reachable through the api-gateway at all, so it must not sit in the
// gateway-fronted set (which would GRANT the gateway SA).
func TestCallerPolicy_BootstrapMint_NotGatewayFronted(t *testing.T) {
	for _, rpc := range GatewayFrontedInternalRPCs() {
		if rpc == bootstrapMintMethod {
			t.Fatal("MintBootstrapToken must NOT be gateway-fronted: it has no REST route and " +
				"the api-gateway SA must not be a licence to mint cluster-admin")
		}
	}
}

// TestCallerPolicy_SANAllowlist_DoesNotLeakToOtherRPCs — the restriction is
// per-RPC: declaring the mint allow-list must not change any other RPC's arm.
func TestCallerPolicy_SANAllowlist_DoesNotLeakToOtherRPCs(t *testing.T) {
	p := mintPolicy(true, seedRunnerSAN)
	// A plain module RPC: any verified module cert still passes the floor.
	if err := p.allow(newVPCCtx(), floorOnlyMethod); err != nil {
		t.Errorf("floor-only RPC must still admit a verified module cert: %v", err)
	}
	// A gateway-fronted RPC: still gateway-SA-only.
	if err := p.allow(newGatewayCtx(), gatewayOnlyMethod); err != nil {
		t.Errorf("gateway-only RPC must still admit the gateway SA: %v", err)
	}
	if status.Code(p.allow(newVPCCtx(), gatewayOnlyMethod)) != codes.PermissionDenied {
		t.Error("gateway-only RPC must still deny a non-gateway module in prod")
	}
	// And the allow-listed seeder has no special powers elsewhere: it is a
	// verified module like any other (floor passes, gateway-only denies).
	seederCtx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), seedRunnerSAN, true)
	if status.Code(p.allow(seederCtx, gatewayOnlyMethod)) != codes.PermissionDenied {
		t.Error("the mint-allow-listed SAN must not gain gateway-fronted access")
	}
}

// TestCallerPolicy_BootstrapMint_InterceptorDenies — the deny is observable
// through the interceptor the server actually installs (unary + stream).
func TestCallerPolicy_BootstrapMint_InterceptorDenies(t *testing.T) {
	p := mintPolicy(true, seedRunnerSAN)
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), vpcSAN, true)

	_, err := p.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: bootstrapMintMethod}, okHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("unary interceptor: got %v, want PermissionDenied", err)
	}
	err = p.Stream()(nil, fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: bootstrapMintMethod}, okStreamHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("stream interceptor: got %v, want PermissionDenied", err)
	}
}
