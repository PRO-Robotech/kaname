// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// session_revocations_internal_only_test.go — pins the gRPC-registration
// contract for InternalSessionRevocationsService (ban #6: internal-only).
//
// Before this fix the api-gateway logout handler called Revoke, but kacho-iam
// never registered the service → codes.Unimplemented at runtime → token
// revocation was INERT (refresh-hook IsRevoked gate had nothing written to it).
// This test guards both halves:
//
//	on the PUBLIC (external) server it is NOT registered → Unimplemented
//	   (must never appear on the external surface, ban #6);
//	on the INTERNAL (:9091) server it IS registered → the route exists
//	   (anything other than Unimplemented proves reachability).
//
// Pure registration/transport test (bufconn, no DB).
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	sessionrevapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/session_revocations"
)

func TestSessionRevocations_InternalOnly_NotOnExternalListener(t *testing.T) {
	// A handler with no writer/reader wired is enough: the route either exists
	// (reaches the handler → fail-closed Unavailable) or returns Unimplemented
	// (not registered). A nil use-case + nil reader makes both RPCs fail closed
	// without touching a DB.
	handler := sessionrevapp.NewHandler(nil, nil)
	svcs := &services{sessionRevocationsHandler: handler}

	// PUBLIC server: NOT registered → Unimplemented.
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewInternalSessionRevocationsServiceClient(pubConn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := pubClient.IsRevoked(ctx, &iamv1.IsRevokedRequest{TokenJti: "jti-1"})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"IsRevoked must NOT exist on the external listener (ban #6)")

	_, err = pubClient.Revoke(ctx, &iamv1.RevokeRequest{UserId: "usr_x", TokenJti: "jti-1", Reason: "x"})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"Revoke must NOT exist on the external listener (ban #6)")

	// INTERNAL server: registered → reachable (NOT Unimplemented).
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})
	intClient := iamv1.NewInternalSessionRevocationsServiceClient(intConn)

	_, err = intClient.IsRevoked(ctx, &iamv1.IsRevokedRequest{TokenJti: "jti-1"})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"IsRevoked must be reachable on the internal listener")

	_, err = intClient.Revoke(ctx, &iamv1.RevokeRequest{UserId: "usr_x", TokenJti: "jti-1", Reason: "x"})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"Revoke must be reachable on the internal listener")
}
