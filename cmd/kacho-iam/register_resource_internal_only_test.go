// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource_internal_only_test.go — Internal-only contract for the
// FGA-proxy RPCs.
//
// RegisterResource / UnregisterResource are Internal-only FGA-proxy RPCs
// (ban #6: Internal.* must not be exposed on the external endpoint). This pins
// the gRPC-registration contract that serve.go relies on:
//
//   - on the PUBLIC (external) server they are NOT registered → calling them
//     returns codes.Unimplemented (route does not exist on the external mux);
//   - on the INTERNAL (:9091) server they ARE registered → the call reaches
//     the handler's authz gate (here, fail-closed PermissionDenied because no
//     FGA-proxy gate is wired) — anything other than Unimplemented proves the
//     route exists internally.
//
// This is a pure registration/transport test (bufconn, no DB / no FGA): it
// guards registerPublicServices / registerInternalServices against an
// accidental future move of the FGA-proxy RPC onto the external surface.
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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	internaliamapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
)

// serveBufconn starts a gRPC server fed by the given registrar over an
// in-memory bufconn listener and returns a connected client + cleanup.
func serveBufconn(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	register(srv)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRegisterResource_A09_InternalOnly_NotOnExternalListener(t *testing.T) {
	// A minimal internal IAM handler. No FGA-proxy gate is wired, so the
	// RegisterResource authz step fails closed (PermissionDenied) — that is
	// enough to prove the route is REACHABLE on the internal mux (it is not
	// Unimplemented). DB / FGA are never touched.
	internalHandler := internaliamapp.NewHandler(nil, nil)
	svcs := &services{internalIAMHandler: internalHandler}

	// PUBLIC server: RegisterResource/UnregisterResource are NOT
	// registered (registerPublicServices never touches internalIAMHandler).
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewInternalIAMServiceClient(pubConn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := pubClient.RegisterResource(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp1",
	})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"A-09a: RegisterResource must NOT exist on the external listener (ban #6)")

	_, err = pubClient.UnregisterResource(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp1",
	})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"A-09a: UnregisterResource must NOT exist on the external listener (ban #6)")

	// INTERNAL server: the RPCs ARE registered and reach the handler's
	// authz gate (fail-closed PermissionDenied here, NOT Unimplemented).
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})
	intClient := iamv1.NewInternalIAMServiceClient(intConn)

	_, err = intClient.RegisterResource(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp1",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"A-09b: RegisterResource must be reachable on the internal listener")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"A-09b: with no FGA-proxy gate wired the internal RPC fails closed (reached authz gate)")

	_, err = intClient.UnregisterResource(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp1",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"A-09b: UnregisterResource must be reachable on the internal listener")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"A-09b: UnregisterResource fails closed without a wired gate (reached authz gate)")
}
