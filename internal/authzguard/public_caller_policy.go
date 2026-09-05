// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// public_caller_policy.go — the per-RPC CALLER policy for the PUBLIC listener
// (:9090). Sibling of caller_policy.go (:9091), same shape, different table.
//
// Why the public listener needs one at all. iam deliberately does NOT re-ReBAC
// the end user on its own listeners — the api-gateway is the platform's single
// authZ front door: it validates the JWT, runs per-user ReBAC via iam.Check with
// the permission catalogue, and only then forwards the resolved identity in
// x-kacho-principal-* metadata. Everything downstream of that decision therefore
// acts with WHATEVER identity arrives in those headers.
//
// :9090 is not gateway-only, though. Five consumer services dial it on their
// request path (ProjectService.Get — project existence + owning account before a
// Create) and four of them ask it the per-page visibility question behind their
// own List (AuthorizeService.BatchCheck). All of them present a client
// certificate from the same
// internal authority as the gateway, and the port is an ordinary Service inside
// the namespace with no NetworkPolicy of its own. So before this policy, ANY
// pod holding an internal-CA certificate could reach ANY public RPC and — since
// the trust-aware extract believed any verified peer while the forwarder
// allow-list was empty — do it in a named victim's name: read and mutate that
// tenant's accounts, projects, groups, roles and grants, and mint personal
// tokens and service-account keys.
//
// Two layers, and both are needed:
//   - the forwarder allow-list (authn.trusted-forwarder-sans → corelib
//     WithTrustedForwarders) decides WHO MAY SPEAK FOR A USER at all. It narrows
//     "anyone with a certificate" down to "our modules" — but a module in that
//     list could still speak for a user on EVERY public RPC.
//   - this policy decides WHO MAY CALL WHICH RPC. It narrows the peers down to
//     the query edges they actually use, so a compromised neighbour cannot reach
//     the credential-issuing and grant-writing surface at all.
//
// Arms (evaluated in order):
//  1. Floor — every public RPC requires a VERIFIED mTLS module certificate
//     (SPIFFE SAN spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) in production.
//     dev (no verified cert) → no-op, mirroring CallerPolicy / RelationWriteGate.
//  2. Gateway — the api-gateway SA may call everything: it is the front door, and
//     the per-user ReBAC decision the whole design rests on happens there.
//  3. Peer-callable — a small, static, MUTATION-FREE table naming, per RPC, which
//     other module SAs may call it. Anything not in it is gateway-only.
//     prod → PermissionDenied; dev → no-op.
//
// The table is STATIC and lives in code, exactly like GatewayFrontedInternalRPCs:
// membership is a property of the runtime edge (recorded in the polyrepo edge
// list), not of what an operator happened to configure. A new service that needs
// a public iam RPC adds itself here, in a reviewed change — a config omission
// must never widen this.
//
// And membership is a property of an edge that EXISTS. An entry naming a caller
// with no module in the tree has the same shape as a live one, yet it admits
// nobody today and admits everything it names on the day someone issues a
// certificate with that SAN — an open surface reserved for a name.
// TestPublicPeerCallableRPCs_EveryCallerHasAModuleInTheTree derives the
// admissible callers from `services/*` and fails on the difference; the
// allowance for a module returns by itself once the module does.
package authzguard

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// Public RPC full-methods that a non-gateway module legitimately calls. Named
// constants so the table below reads as the edge list it mirrors.
const (
	// publicProjectGetMethod — the request-path project validation every
	// consumer performs before creating a placement-scoped resource
	// (services/*/internal/clients/iam*: ProjectServiceClient.Get).
	publicProjectGetMethod = "/kacho.cloud.iam.v1.ProjectService/Get"
	// publicBatchCheckMethod — the per-object visibility filter every List
	// handler in vpc/compute/nlb/storage runs (internal/authzfilter): it asks,
	// for the ids of ONE page, which the end user may see. The service→service
	// edge is meant to live on the internal listener, and most profiles put it
	// there — but at least one deployment profile points it at the public
	// address, so the public listener must admit it or the filter fails closed
	// and tenants lose their own List results.
	publicBatchCheckMethod = "/kacho.cloud.iam.v1.AuthorizeService/BatchCheck"
)

// Module service short-names (as ServiceNameFromSAN resolves them) that appear in
// the peer-callable table.
const (
	svcVPC      = "vpc"
	svcCompute  = "compute"
	svcNLB      = "nlb"
	svcStorage  = "storage"
	svcRegistry = "registry"
)

// PublicPeerCallableRPCs returns the public RPCs a NON-gateway module may call,
// mapped to the exact module service short-names permitted to call each.
//
// Every entry is a QUERY, and that is a rule rather than a coincidence: a mutating
// RPC here would hand a neighbouring service the ability to change tenant data in
// a forwarded user's name, which is the very hole this policy closes. The lock
// TestPublicPeerCallableRPCs_CarryNoMutation enforces it against the proto
// itself — in Kachō a mutation is exactly an RPC that returns an Operation, so the
// check reads the contract rather than a naming habit.
//
// The api-gateway is deliberately absent — it is admitted by its own arm, and
// naming it here too would create a second source of truth that drifts.
//
// Membership is derived from the runtime edges, not from a name search:
//   - ProjectService/Get — vpc, compute, nlb, storage and registry each hold a
//     ProjectServiceClient pointed at iam's PUBLIC address and call Get on the
//     request path of their own Create (project existence + owning account).
//   - AuthorizeService/BatchCheck — the per-page visibility filter in
//     vpc/compute/nlb/storage (internal/authzfilter, the sole AuthorizeService
//     method any of them calls). Its edge belongs on the internal listener and
//     most profiles put it there, but a profile pointing it at the public address
//     exists, and a denial there would fail the filter closed and empty a
//     tenant's own List.
func PublicPeerCallableRPCs() map[string][]string {
	return map[string][]string{
		publicProjectGetMethod: {svcVPC, svcCompute, svcNLB, svcStorage, svcRegistry},
		publicBatchCheckMethod: {svcVPC, svcCompute, svcNLB, svcStorage},
	}
}

// PublicCallerPolicy enforces the per-RPC caller policy on the public listener.
// Construct via NewPublicCallerPolicy.
type PublicCallerPolicy struct {
	// prodMode = cfg.AuthN.Mode.IsProduction(). dev (false) is a pass-through
	// (insecure back-compat: the newman stand has no mTLS at all, so there is no
	// verified certificate to decide on); production is fail-closed.
	prodMode bool
	// peerCallable — full-method → the set of non-gateway module service
	// short-names permitted to call it.
	peerCallable map[string]map[string]struct{}
}

// NewPublicCallerPolicy builds the policy. peerCallable is the per-RPC table of
// non-gateway callers (see PublicPeerCallableRPCs); prodMode comes from
// cfg.AuthN.Mode.IsProduction().
func NewPublicCallerPolicy(prodMode bool, peerCallable map[string][]string) *PublicCallerPolicy {
	m := make(map[string]map[string]struct{}, len(peerCallable))
	for method, svcs := range peerCallable {
		set := make(map[string]struct{}, len(svcs))
		for _, svc := range svcs {
			set[svc] = struct{}{}
		}
		m[method] = set
	}
	return &PublicCallerPolicy{prodMode: prodMode, peerCallable: m}
}

// allow returns nil iff the call may proceed past the policy for fullMethod:
//   - no verified module cert: prod → PermissionDenied (floor fail-closed);
//     dev → nil (insecure back-compat).
//   - api-gateway → nil (the front door, where per-user ReBAC happens).
//   - another module on an RPC that names it in the peer-callable table → nil.
//   - any other module: prod → PermissionDenied; dev → nil.
//
// Message text is the verbatim, non-leaking "permission denied" — identical to
// the internal policy, so a denial reveals nothing about which arm produced it.
func (p *PublicCallerPolicy) allow(ctx context.Context, fullMethod string) error {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)

	svc, ok := "", false
	if verified && san != "" {
		svc, ok = ServiceNameFromSAN(san)
	}
	if !ok {
		// No verified module cert. Dev → no-op; prod → fail-closed.
		if !p.prodMode {
			return nil
		}
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if svc == gatewayServiceName {
		return nil
	}
	if _, listed := p.peerCallable[fullMethod][svc]; listed {
		return nil
	}
	// A verified module that this RPC does not name. Dev → no-op; prod →
	// fail-closed (a data-plane module cannot reach the tenant CRUD, grant and
	// credential-issuing surface, in a forwarded user's name or otherwise).
	if !p.prodMode {
		return nil
	}
	return status.Error(codes.PermissionDenied, "permission denied")
}

// Unary returns the unary interceptor enforcing the public caller policy.
func (p *PublicCallerPolicy) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := p.allow(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream interceptor enforcing the public caller policy.
func (p *PublicCallerPolicy) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := p.allow(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
