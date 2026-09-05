// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor.go — the per-RPC `required_acr_min` (step-up / MFA-freshness floor)
// enforcement on the cluster-internal listener (:9091) for the GATEWAY-FRONTED
// privileged RPCs.
//
// AuthN+AuthZ-everywhere invariant ("Internal = trusted, mTLS is enough" is a
// FORBIDDEN assumption): `required_acr_min` is enforced on the public path
// (api-gateway StepUpGate), but the gateway does NOT re-run that gate when it
// re-dials :9091 on the caller's behalf — so a privileged gateway-fronted
// internal RPC (notably InternalClusterService/{Get,GrantAdmin,RevokeAdmin,
// ListAdmins}, which already carry required_acr_min=2) would be un-enforced on
// the internal route. This interceptor closes that arm: the gateway forwards the
// validated acr as trusted metadata (grpcsrv.MDKeyTokenACR) and the floor
// enforces the catalog requirement here too.
//
// For each RPC in the GATEWAY-FRONTED set (GatewayFrontedInternalRPCs — caller-
// context = api-gateway acting for an end user) whose catalog
// `required_acr_min > 0`, it applies THE step-up rule — grpcsrv.EvaluateStepUp,
// the single implementation the public api-gateway StepUpGate calls too. This
// floor decides nothing itself: it selects WHICH calls are subject to the rule
// (gateway-fronted ∧ production ∧ acr_min>0), reads the inputs from the trusted
// ctx, and renders the verdict as a gRPC status. It must never re-derive the
// ranking or the machine exemption — that split is precisely what let a machine
// principal clear the front door and then be denied here forever
// (acr_floor_stepup_parity_test.go drives this entrypoint against the shared
// rule, machine principal included).
//
// Inputs are read ONLY under the trust invariant: grpcsrv.TrustedACRFromContext
// for the acr and grpcsrv.TrustedPrincipalFromContext for the principal type. On
// the mTLS-verified gateway→iam edge the gateway forwards x-kacho-token-acr and
// x-kacho-principal-type; on an unverified/foreign-SAN peer the acr is dropped
// upstream (corelib) and the principal is flagged untrusted — this floor then
// passes an EMPTY principal type to the rule, so a forged
// `service_account` header cannot buy the exemption (anti-spoof), and the absent
// acr ranks 0 → denied.
//
// EXEMPT (deliberately not enforced here):
//   - Non-gateway-fronted internal RPCs (InternalIAMService/Check,
//     /RegisterResource, /InternalAddressService/Allocate*, …) — called by MODULE
//     SAs (vpc/compute/nlb), not by a user. The floor never touches an RPC
//     outside the gateway-fronted set (selection arm, independent of who calls).
//   - MACHINE principals on gateway-fronted RPCs — exempt via the shared rule,
//     not via a local branch. A service account has no interactive ceremony and
//     can never present acr ≥ 1, so the floor would deny it permanently rather
//     than protect anything. The exemption lifts assurance only: the in-handler
//     ReBAC Check and internalCallerPolicy (gateway-SAN-only) are untouched.
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
//  4. prod, required > 0: THE shared step-up rule (grpcsrv.EvaluateStepUp)
//     decides on the trusted acr + trusted principal type. A machine principal
//     is exempt by that rule; an absent/insufficient/untrusted acr on a
//     non-machine principal → PermissionDenied with a step-up signal in the
//     status details.
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
	// 4. Production + acr_min > 0 — hand the inputs to THE shared rule.
	//
	// The acr was already scrubbed upstream on an untrusted peer (rank 0 → deny).
	// The principal is NOT scrubbed there (only flagged), so the trust flag is
	// applied here: an untrusted peer yields an EMPTY principal type, which the
	// rule never exempts. Forging `x-kacho-principal-type: service_account`
	// therefore buys nothing (internalCallerPolicy already denied a non-gateway
	// SAN before this floor — this is the second lock on the same door).
	acr, _ := grpcsrv.TrustedACRFromContext(ctx)
	principalType := ""
	if p, trusted := grpcsrv.TrustedPrincipalFromContext(ctx); trusted {
		principalType = p.Type
	}
	if grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
		PrincipalType: principalType,
		PresentedACR:  acr,
		RequiredACR:   required,
		// No MFA-freshness arm on this listener: the catalog port exposes only
		// required_acr_min, so MFAMaxAge stays 0 (no window). The public gate
		// enforces freshness where the catalog carries it.
	}) == grpcsrv.StepUpAllow {
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
