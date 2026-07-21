// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// caller_policy.go — the per-RPC CALLER policy for the cluster-internal listener
// (:9091). It does NOT re-ReBAC the end user — that is the api-gateway's job (the
// platform's single authZ front door validates the JWT and runs per-user ReBAC
// via iam.Check). iam's :9091 enforces only WHO MAY CALL each RPC:
//
//  1. Floor — every internal RPC requires a VERIFIED mTLS module cert (SPIRE SAN
//     spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) in production. dev (no verified
//     cert) → no-op (insecure back-compat, mirror RelationWriteGate).
//  2. Gateway-only — the gateway-fronted privileged admin RPCs
//     (GatewayFrontedInternalRPCs) may ONLY be called by the api-gateway SA. A
//     direct call from any other module (e.g. a compromised kacho-vpc) → DENY in
//     prod (a data-plane module cannot escalate via :9091).
//     dev → no-op.
//
// WHY this replaces the former cert-bound ReBAC interceptor: the api-gateway
// re-dials :9091 with ITS OWN client cert (SAN .../sa/kacho-api-gateway) and
// forwards the end-user principal in x-kacho-principal-* metadata. A cert-bound
// ReBAC Check on the gateway SA would DENY legitimate admin calls (system_admin@
// cluster is held by the user, not the gateway SA); ReBAC-ing the forwarded user
// would couple iam to the gateway's relation map. So iam does NO ReBAC and trusts
// NO metadata here — it only verifies the caller IS the gateway for admin RPCs.
//
// The fga-proxy write RPCs (RegisterResource / UnregisterResource /
// WriteCreatorTuple) are NOT gateway-only — their callers are vpc/compute/nlb
// MODULE SAs — and stay gated IN-HANDLER by RelationWriteGate (fga_writer),
// unchanged. They satisfy the floor like any other module RPC.
package authzguard

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// gatewayServiceName — the module service short-name of the api-gateway SA
// (SPIRE SAN .../sa/kacho-api-gateway → "api-gateway"). The single legitimate
// caller of the gateway-fronted privileged admin RPCs.
const gatewayServiceName = "api-gateway"

// GatewayFrontedInternalRPCs returns the full-method set of internal RPCs that
// the api-gateway fronts on behalf of an end user (admin UI / admin tooling).
// These privileged RPCs may ONLY be called by the api-gateway SA — a direct call
// from any other module is a privilege-escalation attempt.
//
// NOT in this set (any verified module — floor only):
//   - InternalIAMService/{Check,LookupSubject,PollSubjectChanges,
//     GetJWKSStatus} — hot-path service→service RPCs.
//   - InternalSessionRevocationsService/IsRevoked — the gateway's own hot-path
//     lookup, runs before per-user authz can possibly run (chicken-and-egg).
//   - InternalUserService/Get — service→service lookup.
//   - InternalIamHooksService/* — Hydra hook callbacks.
//   - the fga-proxy writes InternalIAMService/{RegisterResource,UnregisterResource,
//     WriteCreatorTuple} — gated in-handler by RelationWriteGate (module SAs).
func GatewayFrontedInternalRPCs() []string {
	return []string{
		// InternalClusterService — cluster admin RBAC (admin UI).
		"/kacho.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"/kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin",
		"/kacho.cloud.iam.v1.InternalClusterService/ListAdmins",
		"/kacho.cloud.iam.v1.InternalClusterService/Get",
		// InternalAuthorizeService — tuple/model administration (admin tooling).
		"/kacho.cloud.iam.v1.InternalAuthorizeService/WriteTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReadTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReloadModel",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/GetFGAStoreInfo",
		// InternalIAMService — cluster admin mutation (admin tooling). The
		// fga-proxy writes are NOT here (module SAs, in-handler gate).
		"/kacho.cloud.iam.v1.InternalIAMService/ForceLogout",
		// InternalOperationsService — cluster-wide admin operations feed
		// (admin UI). Gateway-fronted: only the api-gateway SA may
		// dial it, AND the acr-floor enforces the catalog acr_min for it. The
		// in-handler system_admin@cluster ReBAC Check is the additional per-user
		// gate (AuthN+AuthZ on every RPC — internal not exempt).
		"/kacho.cloud.iam.v1.InternalOperationsService/ListIamOperations",
		// InternalSessionRevocationsService — Revoke is driven by the
		// api-gateway logout handler on behalf of a user; ListByUser is the
		// admin-UI revocation history. Both are gateway-fronted. IsRevoked is
		// the hot-path lookup the gateway makes BEFORE authz can run
		// (chicken-and-egg) → floor-only, deliberately NOT in this set.
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/Revoke",
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
		// InternalUserService — identity provisioning fronted by the gateway
		// lazy-mirror / recovery flow.
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		"/kacho.cloud.iam.v1.InternalUserService/OnRecoveryCompleted",
		// InternalBootstrapTokenService — non-interactive bootstrap token mint
		// (#58). Gateway-fronted: only the api-gateway SA may dial :9091 for it
		// (the operator/CI reaches it through the internal sub-mux). permission=
		// "<exempt>" → no acr-floor requirement in the catalog, so the acr-floor
		// passes; the mTLS listener + this caller-policy are the gate.
		"/kacho.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken",
	}
}

// CallerPolicy enforces the per-RPC caller policy on the internal listener.
// Construct via NewCallerPolicy.
type CallerPolicy struct {
	// prodMode = production AuthN mode (cfg.AuthN.Mode.IsProduction()). dev-mode
	// (false) is a no-op (insecure back-compat); production is fail-closed.
	prodMode bool
	// gatewayOnly — full-method set restricted to the api-gateway SA.
	gatewayOnly map[string]struct{}
}

// NewCallerPolicy builds the caller policy. gatewayOnlyRPCs is the set of
// full-method names restricted to the api-gateway SA (see
// GatewayFrontedInternalRPCs). prodMode comes from cfg.AuthN.Mode.IsProduction().
func NewCallerPolicy(prodMode bool, gatewayOnlyRPCs []string) *CallerPolicy {
	m := make(map[string]struct{}, len(gatewayOnlyRPCs))
	for _, rpc := range gatewayOnlyRPCs {
		m[rpc] = struct{}{}
	}
	return &CallerPolicy{prodMode: prodMode, gatewayOnly: m}
}

// allow returns nil iff the call may proceed past the policy for fullMethod:
//   - no verified module cert: prod → PermissionDenied (floor fail-closed);
//     dev → nil (insecure back-compat).
//   - gateway-only RPC called by a non-gateway module: prod → PermissionDenied;
//     dev → nil.
//   - otherwise (any verified module for a non-gateway RPC, or the gateway for a
//     gateway-only RPC) → nil.
//
// Message text is the verbatim, non-leaking "permission denied".
func (p *CallerPolicy) allow(ctx context.Context, fullMethod string) error {
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
	if _, gw := p.gatewayOnly[fullMethod]; gw && svc != gatewayServiceName {
		// Gateway-only RPC from a non-gateway module. Dev → no-op; prod →
		// fail-closed (a data-plane module cannot escalate via :9091).
		if !p.prodMode {
			return nil
		}
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// Any verified module for a non-gateway RPC, or the gateway for a
	// gateway-only RPC → allow.
	return nil
}

// Unary returns the unary interceptor enforcing the caller policy.
func (p *CallerPolicy) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := p.allow(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream interceptor enforcing the caller policy.
func (p *CallerPolicy) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := p.allow(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
