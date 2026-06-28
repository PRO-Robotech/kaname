// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// serve_internal_principal_trust_test.go — anti-spoof guard for the
// cluster-internal gRPC listener (:9091).
//
// P1 SECURITY (audit): the internal listener MUST gate x-kacho-principal-*
// metadata on a VERIFIED mTLS client-cert (corelib FD-4 trust invariant).
// Wiring it with the legacy grpcsrv.UnaryPrincipalExtract /
// StreamPrincipalExtract stamps the forwarded principal UNCONDITIONALLY — a peer
// reaching :9091 without a verified client-cert can then FORGE the user identity
// recorded in operations.principal_* / audit / granted_by (audit-trail spoofing).
// The fix swaps the internal listener to the trust-aware
// grpcsrv.UnaryTrustedPrincipalExtract / StreamTrustedPrincipalExtract, which
// only exposes principal-metadata downstream when CertIdentityExtract proved the
// peer mTLS-verified.
//
// This file is two complementary guards:
//   1. wiring guard (source-level): the internal listener uses the Trusted
//      variants, NOT the legacy ones; ordering CertIdentityExtract → Trusted is
//      preserved. RED against the pre-fix legacy wiring.
//   2. behavioral guard: builds the exact internal-listener unary chain and
//      proves an unverified-TLS peer's forged principal is dropped (carrier stays
//      SystemPrincipal) while a verified-cert peer's principal IS honored.
//      RED if the chain ever uses the legacy (unconditional) extractor.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"
	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// TestInternalListener_UsesTrustAwarePrincipalExtract — source-level wiring guard.
//
// The internal grpcsrv.NewServer(...) is the SECOND NewServer call in serve.go
// (public is first). Its ChainUnaryInterceptor / ChainStreamInterceptor blocks
// MUST reference the trust-aware UnaryTrustedPrincipalExtract /
// StreamTrustedPrincipalExtract, MUST run them AFTER the CertIdentityExtract
// interceptor, and MUST NOT use the legacy unconditional UnaryPrincipalExtract /
// StreamPrincipalExtract.
//
// RED-демонстрация: вернуть на internal listener legacy
// grpcsrv.UnaryPrincipalExtract()/StreamPrincipalExtract() → этот тест падает.
func TestInternalListener_UsesTrustAwarePrincipalExtract(t *testing.T) {
	src := readFileT(t, "serve.go")

	internal := internalServerBlock(t, src)

	// Trust-aware variants must be wired on the internal listener.
	for _, want := range []string{
		"grpcsrv.UnaryTrustedPrincipalExtract()",
		"grpcsrv.StreamTrustedPrincipalExtract()",
	} {
		if !strings.Contains(internal, want) {
			t.Errorf("internal listener: missing %s — principal-metadata is NOT trust-gated "+
				"on :9091 (audit-spoof risk)", want)
		}
	}

	// Legacy unconditional extractors must NOT appear on the internal listener.
	for _, banned := range []string{
		"grpcsrv.UnaryPrincipalExtract()",
		"grpcsrv.StreamPrincipalExtract()",
	} {
		if strings.Contains(internal, banned) {
			t.Errorf("internal listener: still wires legacy %s — a peer without a verified "+
				"client-cert can FORGE the audit principal on :9091", banned)
		}
	}

	// Ordering contract: CertIdentityExtract MUST run before TrustedPrincipalExtract
	// (the Trusted variant reads the verified flag the cert-extract set).
	assertOrder(t, internal,
		"grpcsrv.UnaryCertIdentityExtract()", "grpcsrv.UnaryTrustedPrincipalExtract()")
	assertOrder(t, internal,
		"grpcsrv.StreamCertIdentityExtract()", "grpcsrv.StreamTrustedPrincipalExtract()")
}

// TestInternalListener_PublicListenerUnaffected — the PUBLIC listener path is a
// different (JWT-fronted) principal source and must keep the legacy
// UnaryPrincipalExtract / StreamPrincipalExtract. This guards against the fix
// accidentally weakening or rewiring the public path.
func TestInternalListener_PublicListenerUnaffected(t *testing.T) {
	src := readFileT(t, "serve.go")
	public := publicServerBlock(t, src)

	for _, want := range []string{
		"grpcsrv.UnaryPrincipalExtract()",
		"grpcsrv.StreamPrincipalExtract()",
	} {
		if !strings.Contains(public, want) {
			t.Errorf("public listener: %s was removed — the public JWT-fronted principal "+
				"path must be unchanged by the internal-listener fix", want)
		}
	}
}

// TestInternalChain_DropsForgedPrincipal_HonorsVerified — behavioral guard over
// the exact interceptor chain the internal listener wires
// (CertIdentityExtract → TrustedPrincipalExtract).
//
//   - unverified TLS peer presenting forged x-kacho-principal-* → the principal
//     carrier use-cases read (operations.PrincipalFromContext) MUST stay the
//     SystemPrincipal fallback (forged id dropped). RED with the legacy
//     unconditional extractor (which would stamp usr-mallory).
//   - mTLS-verified peer presenting the same metadata → principal IS honored
//     (no behavior change for verified callers).
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
		var trusted = true
		final := func(c context.Context, _ any) (any, error) {
			carrierID = operations.PrincipalFromContext(c).ID
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if trusted {
			t.Errorf("principal from unverified TLS peer must NOT be trusted on :9091")
		}
		if carrierID != operations.SystemPrincipal().ID {
			t.Errorf("forged principal leaked into operations carrier: got %q, want system fallback %q",
				carrierID, operations.SystemPrincipal().ID)
		}
		if carrierID == "usr-mallory" {
			t.Errorf("audit-spoof: forged principal id 'usr-mallory' reached the use-case carrier")
		}
	})

	t.Run("verified_mtls_peer_principal_honored", func(t *testing.T) {
		// mTLS-verified peer: a non-empty verified chain with a leaf cert.
		leaf := &x509.Certificate{URIs: mustParseURIs(t,
			"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway")}
		tlsPeer := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{leaf}},
		}}}
		ctx := peer.NewContext(context.Background(), tlsPeer)
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, "usr-alice",
			grpcsrv.MDKeyPrincipalDisplay, "alice@example.com",
		))

		var carrierID string
		var trusted bool
		final := func(c context.Context, _ any) (any, error) {
			carrierID = operations.PrincipalFromContext(c).ID
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if !trusted {
			t.Errorf("principal from a verified mTLS peer must be trusted (no behavior change)")
		}
		if carrierID != "usr-alice" {
			t.Errorf("verified principal not honored: got %q, want %q", carrierID, "usr-alice")
		}
	})
}

// internalUnaryChainUnderTest composes the SAME unary interceptors, in the same
// order, that serve.go wires on the internal listener — without standing up a
// real gRPC server. Kept in lockstep with serve.go's internal ChainUnaryInterceptor.
func internalUnaryChainUnderTest() grpc.UnaryServerInterceptor {
	return chainUnaryServer(
		grpcsrv.UnaryCertIdentityExtract(),
		grpcsrv.UnaryTrustedPrincipalExtract(),
	)
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

// --- source-slicing helpers (operate on serve.go text) ---

// publicServerBlock returns the source of the FIRST grpcsrv.NewServer(...) call
// (the public listener) up to its closing line.
func publicServerBlock(t *testing.T, src string) string {
	t.Helper()
	return nthServerBlock(t, src, 0)
}

// internalServerBlock returns the source of the SECOND grpcsrv.NewServer(...)
// call (the internal listener) up to its closing line.
func internalServerBlock(t *testing.T, src string) string {
	t.Helper()
	return nthServerBlock(t, src, 1)
}

// nthServerBlock slices the n-th (0-based) grpcsrv.NewServer( ... ) invocation by
// balancing parentheses from the opening call. Robust to interceptor lists.
func nthServerBlock(t *testing.T, src string, n int) string {
	t.Helper()
	re := regexp.MustCompile(`grpcsrv\.NewServer\(`)
	locs := re.FindAllStringIndex(src, -1)
	if len(locs) <= n {
		t.Fatalf("serve.go: expected >=%d grpcsrv.NewServer(...) calls, found %d", n+1, len(locs))
	}
	start := locs[n][1] // just after the '('
	depth := 1
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return src[start:i]
			}
		}
	}
	t.Fatalf("serve.go: unbalanced parentheses in grpcsrv.NewServer(...) #%d", n)
	return ""
}

// assertOrder fails if `before` does not appear strictly before `after` in s
// (both must be present).
func assertOrder(t *testing.T, s, before, after string) {
	t.Helper()
	bi := strings.Index(s, before)
	ai := strings.Index(s, after)
	if bi < 0 {
		t.Errorf("ordering check: %q not found", before)
		return
	}
	if ai < 0 {
		t.Errorf("ordering check: %q not found", after)
		return
	}
	if bi >= ai {
		t.Errorf("ordering violated: %q must run before %q", before, after)
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
