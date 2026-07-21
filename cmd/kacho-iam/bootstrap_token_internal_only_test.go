// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// bootstrap_token_internal_only_test.go — pins the gRPC-registration contract for
// InternalBootstrapTokenService (#58, ban #6 / IBT-06 / IBT-07):
//
//	on the PUBLIC (external) server it is NOT registered → Unimplemented
//	   (an admin-token mint must NEVER appear on the external surface, ban #6);
//	on the INTERNAL (:9091, mTLS-gated) server it IS registered → reachable
//	   (the mТLS listener boundary is the gate — a non-mТLS caller never reaches
//	   this handler because the RPC lives only on the client-cert-verified
//	   internal listener; the listener's mТLS enforcement is covered by
//	   serve_mtls_wiring_test.go).
//
// Pure registration/transport test (bufconn, no DB). A use-case with no signing
// key wired makes Execute fail closed (Unavailable) without touching any
// store/Hydra — enough to prove reachability without a DB.
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

	bootstraptoken "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/bootstrap_token"
)

func TestBootstrapToken_InternalOnly_NotOnExternalListener(t *testing.T) {
	// No signing key → Execute fails closed (Unavailable) without touching the
	// store/Hydra: reachable but no side effects, no DB.
	handler := bootstraptoken.NewHandler(
		bootstraptoken.NewMintUseCase(nil, nil, nil, nil, bootstraptoken.Config{}))
	svcs := &services{internalBootstrapTokenHandler: handler}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// PUBLIC server: NOT registered → Unimplemented (ban #6, IBT-06).
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewInternalBootstrapTokenServiceClient(pubConn)
	_, err := pubClient.MintBootstrapToken(ctx, &iamv1.MintBootstrapTokenRequest{})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"MintBootstrapToken must NOT exist on the external listener (ban #6, IBT-06)")

	// INTERNAL server: registered → reachable (NOT Unimplemented). The internal
	// listener is mТLS-gated in production (IBT-07); a non-mТLS caller never gets
	// this far because the RPC lives only here.
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})
	intClient := iamv1.NewInternalBootstrapTokenServiceClient(intConn)
	_, err = intClient.MintBootstrapToken(ctx, &iamv1.MintBootstrapTokenRequest{})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"MintBootstrapToken must be reachable on the internal listener")
	require.Equal(t, codes.Unavailable, status.Code(err),
		"with no signing key wired the reachable handler fails closed (Unavailable)")
}
