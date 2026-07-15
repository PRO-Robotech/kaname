// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authorize_internal_listener_test.go — RBAC consumer list-filter
// architectural gap on the internal listener.
//
// PROBLEM: consumer per-object List-filter (kacho-vpc / kacho-compute / kacho-nlb)
// calls AuthorizeService.ListObjects(subject, relation, objectType) service→service
// to compute the per-object filter set. But AuthorizeService (ListObjects /
// BatchCheck / Check) was registered ONLY on the PUBLIC listener (:9090). The
// cluster-internal listener (:9091) — the verified-mTLS service→service edge the
// modules already reuse for InternalIAMService.Check — did NOT carry
// AuthorizeService. A consumer reusing its :9091 conn to call ListObjects hit
// codes.Unimplemented → fail-closed → empty List for every caller. There was no
// single service→service path to ListObjects.
//
// FIX (minimal, production-grade): register AuthorizeService ALSO on the internal
// listener (registerInternalServices) IN ADDITION to public (additive; the SAME
// handler instance). This does NOT violate ban #6 — ban #6 forbids Internal.*
// methods on the PUBLIC surface; here a PUBLIC service is ADDITIONALLY exposed on
// the cluster-internal :9091 (not tenant-facing), which is the established pattern
// for service→service RPCs.
//
// This is a pure registration/transport test (bufconn, no DB / no real FGA — a
// stub Authorizer backs the handler so the route reaches a real use-case rather
// than NPE-panicking on a nil svc). The interceptor chain (CallerPolicy /
// SystemViewerFloor / ACRFloor) is NOT exercised here — those are wired in
// serve.go and asserted separately; this test pins ONLY the registration
// contract that the gap fix changes.
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

	authorizeapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/authorize"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// authzStubAuthorizer — minimal service.Authorizer for the registration test.
// Returns deterministic, panic-free results so ListObjects/BatchCheck/Check
// reach a real use-case and the assertion is purely "route exists" (NOT
// Unimplemented), never tripping a nil-svc NPE.
type authzStubAuthorizer struct{}

func (authzStubAuthorizer) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return true, nil
}

func (authzStubAuthorizer) ListObjects(context.Context, string, string, string, map[string]any, int) ([]string, error) {
	return []string{"vpcn_a", "vpcn_b"}, nil
}

func (authzStubAuthorizer) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return []string{"user:a"}, "", nil
}

func (authzStubAuthorizer) Expand(context.Context, string, string, string) (*clients.ExpandTree, error) {
	return &clients.ExpandTree{Leaves: []string{"user:a"}}, nil
}

func (authzStubAuthorizer) ReadTuples(context.Context, string, string, string, int, string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

// newAuthorizeServicesForRegistration builds a *services carrying a real
// AuthorizeService handler backed by the stub Authorizer (no DB / no real FGA).
func newAuthorizeServicesForRegistration() *services {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: authzStubAuthorizer{},
		ModelID:   "test-model",
	})
	// whoAmI is required by the handler builder; its deps are nil here (WhoAmI is
	// not exercised by this registration test — only the AuthorizeService RPCs).
	h := authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil))
	return &services{authorizeHandler: h}
}

// TestAuthorizeService_D_ReachableOnInternalListener — RBAC-D consumer
// list-filter gap. AuthorizeService must be reachable on the INTERNAL (:9091)
// listener (the verified-mTLS service→service edge consumers reuse for Check),
// IN ADDITION to the public listener (additive — no regression of the public
// surface).
//
//	D-1 (the gap): ListObjects reachable on INTERNAL → NOT Unimplemented.
//	              Before the fix → Unimplemented (RED). After → reachable (GREEN).
//	D-2:          BatchCheck reachable on INTERNAL (consumers may batch).
//	D-3:          Check reachable on INTERNAL (parity with the existing
//	              InternalIAMService.Check edge).
//	D-4:          AuthorizeService stays reachable on the PUBLIC listener too
//	              (additive — the user-facing surface is unchanged).
func TestAuthorizeService_D_ReachableOnInternalListener(t *testing.T) {
	svcs := newAuthorizeServicesForRegistration()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// INTERNAL listener — the edge consumers (vpc/compute/nlb) reuse for Check.
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})
	intClient := iamv1.NewAuthorizeServiceClient(intConn)

	// D-1 — ListObjects: the consumer per-object filter call. Must exist on :9091.
	_, err := intClient.ListObjects(ctx, &iamv1.ListObjectsRequest{
		Subject:      "user:usr_alice",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-1: AuthorizeService.ListObjects MUST be reachable on the internal listener (:9091) — consumer list-filter edge")
	require.NoError(t, err,
		"D-1: with the stub Authorizer ListObjects returns a deterministic object-set (route reached the use-case)")

	// D-2 — BatchCheck: consumers may batch authz queries on the same edge.
	_, err = intClient.BatchCheck(ctx, &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{{
			Subject:  "user:usr_alice",
			Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_a"},
			Action:   "vpc.networks.get",
		}},
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-2: AuthorizeService.BatchCheck MUST be reachable on the internal listener (:9091)")

	// D-3 — Check: parity with the existing InternalIAMService.Check edge.
	_, err = intClient.Check(ctx, &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_alice",
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_a"},
		Action:   "vpc.networks.get",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-3: AuthorizeService.Check MUST be reachable on the internal listener (:9091)")

	// D-4 — PUBLIC listener still carries AuthorizeService (additive; no regression).
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewAuthorizeServiceClient(pubConn)
	_, err = pubClient.ListObjects(ctx, &iamv1.ListObjectsRequest{
		Subject:      "user:usr_alice",
		ResourceType: "vpc_network",
		Action:       "vpc.networks.list",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-4: AuthorizeService.ListObjects MUST remain reachable on the public listener (additive — public surface unchanged)")
	require.NoError(t, err, "D-4: public ListObjects reached the use-case")
}
