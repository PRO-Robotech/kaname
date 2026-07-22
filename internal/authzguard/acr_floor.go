// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// acr_floor.go — the per-RPC `required_acr_min` (step-up / MFA-freshness floor)
// enforcement on the cluster-internal listener (:9091) for the GATEWAY-FRONTED
// privileged RPCs.
//
// AuthN+AuthZ-everywhere invariant ("Internal = trusted, mTLS is enough" is a
// FORBIDDEN assumption): `required_acr_min` is enforced on the public path
// (api-gateway StepUpGate) but the gateway DROPS the acr when it re-dials :9091,
// so a privileged gateway-fronted internal RPC (notably
// InternalClusterService/{Get,GrantAdmin,RevokeAdmin,ListAdmins}, which already
// carry required_acr_min=2) is NOT acr-enforced on the internal route. This
// interceptor closes that arm.
//
// For each RPC in the GATEWAY-FRONTED set (GatewayFrontedInternalRPCs — caller-
// context = api-gateway acting for an end user) whose catalog
// `required_acr_min > 0`, it enforces `acr >= required_acr_min` via
// grpcsrv.ACRSatisfies (the iam-side ACR ranking). The public gateway StepUpGate
// maintains a SEPARATE, functionally-identical ranking table (its own acrRank) —
// the two are NOT shared, but read the same catalog value; their identical
// pass/deny verdict is locked by a verdict-parity test (SEC-ACR-16) so they
// cannot drift. The presented acr is read from the trusted ctx
// (grpcsrv.TrustedACRFromContext): on the mTLS-verified gateway→iam edge the
// gateway forwards x-kacho-token-acr; on an unverified/foreign-SAN peer the acr
// is dropped upstream (corelib) → treated as rank 0 → denied (anti-spoof).
//
// EXEMPT (deliberately not enforced here):
//   - Non-gateway-fronted internal RPCs (InternalIAMService/Check,
//     /RegisterResource, /InternalAddressService/Allocate*, …) — called by MODULE
//     SAs (vpc/compute/nlb), not by a user. SAs have no MFA / no acr; they are
//     acr-EXEMPT by design (edges/vpc-operator-to-vpc-mtls.md). The floor never
//     touches an RPC outside the gateway-fronted set.
//   - gateway-fronted RPCs whose required_acr_min == 0 — no requirement
//     (latent-until-policy: the floor fires for them the moment policy raises
//     their acr_min, proving the mechanism is generic).
//
// Ordering (serve.go): chained AFTER UnaryTrustedPrincipalExtract (sets the
// trusted acr) AND internalCallerPolicy (which already DENIES a non-gateway SAN
// on a gateway-fronted RPC BEFORE the acr-floor — so a compromised module cannot
// reach the floor with a spoofed acr; the acr-exemption of module SAs cannot be
// abused). Mirrors the SystemViewerFloor: default-OFF
// (dev/newman no-op, byte-identical), fail-closed in production.
package authzguard

import (
	"context"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// ACRRequirementLookup — narrow port resolving an RPC's `required_acr_min` from
// the permission catalog. The key is the catalog FQN (NO leading slash, e.g.
// "kacho.cloud.iam.v1.InternalClusterService/GrantAdmin"); an unknown FQN or an
// RPC without an acr requirement returns "". Satisfied by an adapter over
// seed.PermissionRegistry in the composition root; a fake in tests.
type ACRRequirementLookup interface {
	RequiredACRMin(fqn string) string
}

// ACRFloor enforces the gateway-fronted `required_acr_min` step-up floor on the
// internal listener. Construct via NewACRFloor.
type ACRFloor struct {
	// catalog — FQN → required_acr_min resolver. nil → no RPC has a requirement
	// (every gateway-fronted RPC's acr_min resolves to "" → no-op), which keeps
	// the floor inert if the catalog is unwired (the gateway-only caller-policy
	// + in-handler ReBAC still gate these RPCs).
	catalog ACRRequirementLookup
	// prodMode = production AuthN mode (cfg.AuthN.Mode.IsProduction()). dev-mode
	// (false) is a NO-OP pass-through (default-OFF back-compat); production is
	// fail-closed. Mirrors CallerPolicy / SystemViewerFloor.
	prodMode bool
	// gatewayFronted — the full-method set whose caller-context is the api-gateway
	// acting for an end user; acr applies only to these.
	gatewayFronted map[string]struct{}
}

// NewACRFloor builds the floor over the gateway-fronted RPC set. Defaults to
// dev-mode (no-op); use WithProductionMode to enable strict enforcement.
func NewACRFloor(catalog ACRRequirementLookup, gatewayFrontedRPCs []string) *ACRFloor {
	m := make(map[string]struct{}, len(gatewayFrontedRPCs))
	for _, rpc := range gatewayFrontedRPCs {
		m[rpc] = struct{}{}
	}
	return &ACRFloor{catalog: catalog, gatewayFronted: m}
}

// WithProductionMode toggles strict fail-closed enforcement (production AuthN).
func (f *ACRFloor) WithProductionMode(prod bool) *ACRFloor {
	f.prodMode = prod
	return f
}

// requiredACRMin resolves the catalog `required_acr_min` for a gRPC full-method.
// The catalog is keyed by FQN without the leading slash, so the gRPC
// "/pkg.Service/Method" is normalized by trimming the leading '/'.
func (f *ACRFloor) requiredACRMin(fullMethod string) string {
	if f.catalog == nil {
		return ""
	}
	return f.catalog.RequiredACRMin(strings.TrimPrefix(fullMethod, "/"))
}

// allow returns nil iff the call may proceed past the acr-floor for fullMethod:
//
//  1. fullMethod ∉ gateway-fronted set → pass (service→service caller; acr-exempt).
//  2. !prodMode → pass (no-op dev/newman back-compat).
//  3. required_acr_min == 0/"" → pass (no requirement; latent-until-policy).
//  4. prod, required > 0: acr from the trusted ctx must satisfy the floor
//     (grpcsrv.ACRSatisfies). Absent/insufficient/untrusted acr → PermissionDenied
//     with a step-up signal in the status details.
//
// Message text is the verbatim, non-leaking "permission denied"; the step-up
// intent rides in a PreconditionFailure violation (acr_values), consistent with
// the public buildGRPCDenyStatus, so the gateway can translate it into an
// RFC 9470 challenge.
func (f *ACRFloor) allow(ctx context.Context, fullMethod string) error {
	// 1. Not a gateway-fronted RPC — acr-exempt (service→service).
	if _, gated := f.gatewayFronted[fullMethod]; !gated {
		return nil
	}
	// 2. Dev-mode — no-op pass (default-OFF; catalog NOT consulted).
	if !f.prodMode {
		return nil
	}
	// 3. No acr requirement for this RPC — pass.
	required := f.requiredACRMin(fullMethod)
	if grpcsrv.ACRRank(required) == 0 {
		return nil
	}
	// 4. Production + acr_min > 0: the trusted, forwarded acr must satisfy the
	// floor. On an untrusted peer the acr was dropped upstream (rank 0) → deny.
	acr, _ := grpcsrv.TrustedACRFromContext(ctx)
	if grpcsrv.ACRSatisfies(acr, required) {
		return nil
	}
	return acrStepUpDenied(required)
}

// acrStepUpDenied builds the PermissionDenied status with a step-up signal in
// the details (PreconditionFailure violation type "authz.step_up" carrying the
// required acr_values), so the gateway can emit an RFC 9470 challenge. Mirrors
// the public buildGRPCDenyStatus shape (PermissionDenied + PreconditionFailure).
func acrStepUpDenied(requiredACR string) error {
	st := status.New(codes.PermissionDenied, "permission denied")
	pf := &errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{
			Type:        "authz.step_up",
			Subject:     "acr_values:" + requiredACR,
			Description: "insufficient_user_authentication: higher ACR required",
		}},
	}
	if withDetails, err := st.WithDetails(pf); err == nil {
		return withDetails.Err()
	}
	// WithDetails should never fail for a well-known type; fall back to the bare
	// PermissionDenied (still fail-closed, just without the step-up hint).
	return st.Err()
}

// Unary returns the unary interceptor enforcing the acr-floor.
func (f *ACRFloor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := f.allow(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream interceptor enforcing the acr-floor.
func (f *ACRFloor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := f.allow(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
