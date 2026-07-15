// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// acr_floor_grant_admin_integration_test.go — integration test.
//
// Exercises the cluster-internal interceptor CHAIN end-to-end over bufconn for
// the gateway-fronted privileged RPC InternalClusterService/GrantAdmin (catalog
// required_acr_min=2), proving the acr-floor + caller-policy
// ordering on a real gRPC server:
//
//   - a verified api-gateway SAN forwarding acr=2 → passes BOTH gates → reaches
//     the handler;
//   - the same gateway SAN forwarding acr=1 → DENIED by the acr-floor BEFORE the
//     handler (no side-effect);
//   - a verified NON-gateway SAN (kacho-vpc) on this gateway-fronted RPC → DENIED
//     by the caller-policy FIRST (the floor never sees it, so the module-
//     SA acr-exemption cannot be abused).
//
// The chain mirrors serve.go's internal listener (prod-mode). The mTLS-verified
// peer + forwarded acr are simulated by a tiny front interceptor that seeds the
// ctx exactly as corelib UnaryCertIdentityExtract + UnaryTrustedPrincipalExtract
// would on a verified gateway→iam edge — keeping the test to the chain logic
// (no live TLS handshake; corelib's bufconn test covers the handshake half).
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
)

const (
	acrTestGatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	acrTestVPCSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	grantAdminFQN     = "/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin"
)

// reachedClusterServer is a stub InternalClusterServiceServer recording whether
// GrantAdmin's handler was reached (i.e. the chain let the call through).
type reachedClusterServer struct {
	iamv1.UnimplementedInternalClusterServiceServer
	grantReached bool
}

func (s *reachedClusterServer) GrantAdmin(context.Context, *iamv1.GrantClusterAdminRequest) (*operationpb.Operation, error) {
	s.grantReached = true
	return &operationpb.Operation{Id: "iop-acr-test", Done: true}, nil
}

// seedVerifiedPeer simulates the corelib mTLS-verified extract: it seeds the
// verified module SAN + the FD-4-trusted forwarded acr into ctx, exactly as
// UnaryCertIdentityExtract + UnaryTrustedPrincipalExtract leave it on a verified
// gateway→iam edge.
func seedVerifiedPeer(san, acr string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = grpcsrv.WithCertIdentity(ctx, san, true)
		ctx = grpcsrv.WithTrustedACR(ctx, acr, true)
		return handler(ctx, req)
	}
}

// serveACRChain starts a bufconn gRPC server whose chain is the prod-mode
// internal chain (caller-policy → acr-floor) fronted by seedVerifiedPeer.
func serveACRChain(t *testing.T, srv iamv1.InternalClusterServiceServer, san, acr string) *grpc.ClientConn {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)

	callerPolicy := authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs())
	acrFloor := authzguard.NewACRFloor(reg, authzguard.GatewayFrontedInternalRPCs()).WithProductionMode(true)

	lis := bufconn.Listen(1024 * 1024)
	gsrv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		seedVerifiedPeer(san, acr), // stand-in for the mTLS cert-identity + trusted-acr extract
		callerPolicy.Unary(),
		acrFloor.Unary(),
	))
	iamv1.RegisterInternalClusterServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// 5.4-01: gateway SAN + acr=2 → reaches the GrantAdmin handler.
func TestACRFloorIntegration_0401_GatewayAcr2_Reaches(t *testing.T) {
	stub := &reachedClusterServer{}
	conn := serveACRChain(t, stub, acrTestGatewaySAN, "2")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr-target"})
	require.NoError(t, err, "acr=2 ≥ acr_min=2 must pass the floor to the handler")
	require.True(t, stub.grantReached, "handler must be reached on a sufficient acr")
}

// 5.4-02: gateway SAN + acr=1 → DENIED by the acr-floor before the handler.
func TestACRFloorIntegration_0402_GatewayAcr1_DeniedNoSideEffect(t *testing.T) {
	stub := &reachedClusterServer{}
	conn := serveACRChain(t, stub, acrTestGatewaySAN, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr-target"})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"acr=1 < acr_min=2 must be denied by the acr-floor")
	require.False(t, stub.grantReached, "handler must NOT be reached on acr-deny (no side-effect, 5.4-02)")
}

// 5.4-06: a verified NON-gateway SAN (kacho-vpc) on a gateway-fronted RPC →
// DENIED by the caller-policy FIRST (the acr-floor never runs; a module SA's
// acr-exemption cannot be abused on a gateway-fronted RPC).
func TestACRFloorIntegration_0406_NonGatewaySAN_CallerPolicyDeniesFirst(t *testing.T) {
	stub := &reachedClusterServer{}
	// Even a spoofed-high acr=3 from a non-gateway peer must not help.
	conn := serveACRChain(t, stub, acrTestVPCSAN, "3")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr-target"})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a non-gateway module on a gateway-fronted RPC must be denied (caller-policy first)")
	require.False(t, stub.grantReached, "handler must NOT be reached")
}
