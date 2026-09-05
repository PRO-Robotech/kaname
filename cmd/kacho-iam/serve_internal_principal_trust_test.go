// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// serve_internal_principal_trust_test.go — anti-spoof guard for BOTH gRPC
// listeners (cluster-internal :9091 and public :9090).
//
// Subject: the TRANSPORT half of the trust invariant — a peer that did not pass
// client-certificate verification must not be able to stamp
// x-kacho-principal-*. Wiring a listener with the legacy unconditional
// grpcsrv.UnaryPrincipalExtract / StreamPrincipalExtract would stamp the
// forwarded principal blindly, and the identity recorded in
// operations.principal_* / audit / granted_by would be whatever the caller typed.
//
// The OTHER half — WHICH verified peers may forward at all — is the
// forwarder allow-list, and it lives in trusted_forwarders_test.go (behaviour)
// plus trusted_forwarders_wiring_test.go (placement). The two halves are
// complementary: verification says "you are who your certificate says", the
// allow-list says "and you are one of the senders permitted to speak for a
// user". Both chains here are built by the SAME production builder the listeners
// use (identityUnary), so a change to the wiring cannot leave these locks green
// while production diverges.

import (
	"context"
	"crypto/tls"
	"net/url"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// TestPublicChain_DropsForgedPrincipal_HonorsVerified — behavioral guard over the
// exact interceptor chain the public listener wires (identityUnary): a forged
// principal from an unverified TLS peer is dropped (carrier stays SystemPrincipal);
// a listed, verified peer's principal is honored.
func TestPublicChain_DropsForgedPrincipal_HonorsVerified(t *testing.T) {
	chain := publicUnaryChainUnderTest()

	t.Run("unverified_tls_peer_forged_principal_dropped", func(t *testing.T) {
		tlsPeer := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}}
		ctx := peer.NewContext(context.Background(), tlsPeer)
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, "usr-mallory",
			grpcsrv.MDKeyPrincipalDisplay, "mallory@example.com",
		))

		var carrierID string
		var trusted, present = true, true
		final := func(c context.Context, _ any) (any, error) {
			// present comes from PrincipalFromContextOK — the only accessor that
			// tells "the carrier was scrubbed" apart from "the carrier holds the
			// system identity". PrincipalFromContext cannot: by contract both
			// states read back as SystemPrincipal, so asserting scrubbing with it
			// stays green even when an untrusted sender is handed the system
			// identity — the very identity the ownership predicate matches on
			// every system-written operation.
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}
		if trusted {
			t.Errorf("principal from unverified TLS peer must NOT be trusted on :9090")
		}
		if present {
			t.Errorf("the identity carrier survived for an untrusted sender: got %q — it must be "+
				"scrubbed, otherwise the ownership predicate treats this request as the owner of "+
				"every system-written operation", carrierID)
		}
		if carrierID == "usr-mallory" {
			t.Errorf("impersonation: forged principal id 'usr-mallory' reached the use-case carrier")
		}
	})

	t.Run("verified_mtls_peer_principal_honored", func(t *testing.T) {
		ctx := forwardedIdentity(verifiedCertPeer(t, fwdGatewaySAN), "usr-alice")

		var carrierID string
		var present bool
		final := func(c context.Context, _ any) (any, error) {
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}
		if !present {
			t.Errorf("the identity carrier must be populated for a listed, verified sender")
		}
		if carrierID != "usr-alice" {
			t.Errorf("verified principal not honored: got %q, want %q", carrierID, "usr-alice")
		}
	})
}

// TestPublicChain_HonorsVerifiedConsumerForwarder — a NON-gateway module
// (kacho-vpc) dials :9090 ProjectService.Get on the request path of its own
// Create and forwards the END-USER principal so iam applies that tenant's
// scope-filter. :9090 is therefore a MULTI-forwarder listener by design, and the
// allow-list names those consumers alongside the gateway.
//
// Note what this does NOT say: being a permitted SENDER is not permission to call
// anything. The per-RPC caller policy (authzguard.PublicCallerPolicy) admits vpc
// on ProjectService/Get and nowhere else — see its own tests.
func TestPublicChain_HonorsVerifiedConsumerForwarder(t *testing.T) {
	chain := publicUnaryChainUnderTest()
	ctx := forwardedIdentity(verifiedCertPeer(t, fwdVPCSAN), "usr-alice")

	var carrierID string
	final := func(c context.Context, _ any) (any, error) {
		carrierID = operations.PrincipalFromContext(c).ID
		return nil, nil
	}
	if _, err := chain(ctx, nil, nil, final); err != nil {
		t.Fatalf("chain returned error: %v", err)
	}
	if carrierID != "usr-alice" {
		t.Errorf("a listed consumer forwarder must be honored on :9090 (cross-service project "+
			"validation runs under the end user): got %q, want usr-alice", carrierID)
	}
}

// TestInternalChain_DropsForgedPrincipal_HonorsVerified — behavioral guard over
// the exact interceptor chain the internal listener wires (identityUnary — the
// SAME builder as the public one).
//
//   - unverified TLS peer presenting forged x-kacho-principal-* → the principal
//     carrier use-cases read (operations.PrincipalFromContext) MUST stay the
//     SystemPrincipal fallback (forged id dropped).
//   - a listed, mTLS-verified peer presenting the same metadata → principal IS
//     honored (no behavior change for legitimate senders).
func TestInternalChain_DropsForgedPrincipal_HonorsVerified(t *testing.T) {
	chain := internalUnaryChainUnderTest()

	t.Run("unverified_tls_peer_forged_principal_dropped", func(t *testing.T) {
		// TLS present but NO verified client-cert (empty VerifiedChains) — exactly
		// what an unverified/cert-less peer reaching the interceptor looks like.
		tlsPeer := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}}
		ctx := peer.NewContext(context.Background(), tlsPeer)
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, "usr-mallory",
			grpcsrv.MDKeyPrincipalDisplay, "mallory@example.com",
		))

		var carrierID string
		var trusted, present = true, true
		final := func(c context.Context, _ any) (any, error) {
			// present comes from PrincipalFromContextOK — the only accessor that
			// tells "the carrier was scrubbed" apart from "the carrier holds the
			// system identity". PrincipalFromContext cannot: by contract both
			// states read back as SystemPrincipal, so asserting scrubbing with it
			// stays green even when an untrusted sender is handed the system
			// identity — the very identity the ownership predicate matches on
			// every system-written operation.
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if trusted {
			t.Errorf("principal from unverified TLS peer must NOT be trusted on :9091")
		}
		if present {
			t.Errorf("the identity carrier survived for an untrusted sender: got %q — it must be "+
				"scrubbed, otherwise the ownership predicate treats this request as the owner of "+
				"every system-written operation", carrierID)
		}
		if carrierID == "usr-mallory" {
			t.Errorf("audit-spoof: forged principal id 'usr-mallory' reached the use-case carrier")
		}
	})

	t.Run("verified_mtls_peer_principal_honored", func(t *testing.T) {
		ctx := forwardedIdentity(verifiedCertPeer(t, fwdGatewaySAN), "usr-alice")

		var carrierID string
		var trusted, present bool
		final := func(c context.Context, _ any) (any, error) {
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if !trusted {
			t.Errorf("principal from a listed, verified mTLS peer must be trusted (no behavior change)")
		}
		if !present {
			t.Errorf("the identity carrier must be populated for a listed, verified sender")
		}
		if carrierID != "usr-alice" {
			t.Errorf("verified principal not honored: got %q, want %q", carrierID, "usr-alice")
		}
	})
}

// internalUnaryChainUnderTest / publicUnaryChainUnderTest compose the identity
// interceptors the two listeners really receive, by calling the PRODUCTION
// builder rather than re-listing them here. Re-listing was how these guards
// used to work, and it is precisely the drift that let an empty allow-list look
// like a narrowing: the wiring could change and the locks would not notice.
func internalUnaryChainUnderTest() grpc.UnaryServerInterceptor {
	return chainUnaryServer(identityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN))...)
}

func publicUnaryChainUnderTest() grpc.UnaryServerInterceptor {
	return chainUnaryServer(identityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN))...)
}

// chainUnaryServer composes unary server interceptors left-to-right around a
// final handler, mirroring grpc.ChainUnaryInterceptor semantics.
func chainUnaryServer(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			ic := interceptors[i]
			next := chained
			chained = func(c context.Context, r any) (any, error) { return ic(c, r, info, next) }
		}
		return chained(ctx, req)
	}
}

func mustParseURIs(t *testing.T, raw ...string) []*url.URL {
	t.Helper()
	out := make([]*url.URL, 0, len(raw))
	for _, r := range raw {
		u, err := url.Parse(r)
		if err != nil {
			t.Fatalf("parse uri %q: %v", r, err)
		}
		out = append(out, u)
	}
	return out
}
