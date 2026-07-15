// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// system_viewer_floor.go — the per-RPC `system_viewer`-FLOOR on
// the cluster-internal listener's READ RPCs.
//
// The AuthN+AuthZ-everywhere invariant requires EVERY internal RPC (not only
// public) to pass a per-RPC authz-Check beyond mTLS: read-RPC gate viewer-tier
// (system_viewer). Today :9091 READ-RPCs are gated ONLY by the coarse mTLS
// caller-policy floor (CallerPolicy) — no relation-tier Check. This interceptor
// closes that gap.
//
// For the READ-RPC set (ReadFloorRPCs), it requires the CALLER MODULE
// ServiceAccount (derived from the verified mTLS cert SAN, the SAME
// SAN→sva derivation as fgaproxy) to hold a COARSE cluster relation
// `system_viewer` on the singleton `cluster:cluster_kacho_root`, checked via the
// SAME RelationChecker port used by RelationWriteGate / InternalIAMService.Check.
//
// This is a COARSE "is this a legitimate internal reader" gate (defense-in-depth
// against a compromised module holding a valid cert but not authorized to read
// IAM) — NOT a per-resource viewer-check. Per-user authz is the api-gateway's
// job, run BEFORE it forwards to :9091. The floor never ReBACs the forwarded
// end-user principal (x-kacho-principal-*) — the subject of the Check is the
// caller MODULE-SA, not the end user.
//
// Default-OFF / production-mode-only: in dev/newman (no mTLS, FGA-on-internal
// disabled) the floor is a NO-OP pass-through, byte-identical to today — the
// same prodMode signal the CallerPolicy / RelationWriteGate use. This keeps the
// newman E2E stand green.
//
// Fail-closed in production-mode: an unverified/absent SAN → PermissionDenied;
// a checker/FGA backend error → Unavailable (retryable). Mirrors
// RelationWriteGate error semantics verbatim.
//
// EXEMPT from the floor (see ReadFloorRPCs / the exemption rationale below):
//   - InternalIAMService.Check — the PDP. The caller acts on behalf of an
//     end-user, NOT as the subject; floor-gating it on "caller has viewer"
//     would break the core authz path (every downstream Check would deny). It
//     stays on the mTLS-module floor only.
//   - InternalUserService.OnRecoveryCompleted — Kratos recovery hook,
//     HMAC/secret-authed; Kratos is not a kacho-seeded SA → relation-Check
//     inapplicable. (Hydra token/refresh hooks live on the separate :9092 HTTP
//     listener, not this gRPC chain — N/A by construction.)
//   - InternalSessionRevocationsService.IsRevoked — refresh-hook hot-path
//     chicken-and-egg (runs before per-user authz can run); a per-call FGA
//     round-trip here would add latency + an outage would mass-fail token
//     refresh. Stays on the mTLS-module floor.
//   - all mutations (Register/Unregister/WriteCreatorTuple stay fga_writer-
//     gated; ForceLogout/GrantAdmin/… stay system_admin / gateway-only) — this
//     is a READ floor; the mutation surface is unchanged.
package authzguard

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

const (
	// systemViewerRelation — the coarse cluster read-legitimacy relation a
	// reader module-SA must hold. cluster.system_viewer is [user,
	// service_account] with NO `user:*` wildcard (FGA model), so an
	// arbitrary user:<rando> can never satisfy it.
	systemViewerRelation = "system_viewer"
	// clusterRootObject — the singleton cluster object, the same root
	// used by cluster-scope AccessBindings and the operator tuple.
	clusterRootObject = "cluster:cluster_kacho_root"
)

// ReadFloorRPCs returns the full-method set of cluster-internal READ RPCs that
// must pass the `system_viewer@cluster` floor. Membership is
// the single source of truth for the floor; the exemption set is
// expressed by ABSENCE from this list and asserted by TestReadFloorRPCs_Membership.
//
// NOT in this set (exempt — see the package doc-comment for the rationale):
//   - InternalIAMService/Check — PDP, never floor-gated.
//   - InternalUserService/OnRecoveryCompleted — Kratos secret-authed hook.
//   - InternalSessionRevocationsService/IsRevoked — hot-path chicken-and-egg.
//   - InternalIAMService/{RegisterResource,UnregisterResource,WriteCreatorTuple}
//     — fga_writer-gated mutations.
//   - ForceLogout / Cluster GrantAdmin/RevokeAdmin / Authorize
//     WriteTuples/ReloadModel / SessionRevocations Revoke /
//     UpsertFromIdentity — gateway-only / admin-tier mutations.
func ReadFloorRPCs() []string {
	return []string{
		// InternalIAMService — service→service read lookups.
		"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kacho.cloud.iam.v1.InternalIAMService/GetJWKSStatus",
		"/kacho.cloud.iam.v1.InternalIAMService/PollSubjectChanges",
		// InternalUserService — service→service user mirror read.
		"/kacho.cloud.iam.v1.InternalUserService/Get",
		// InternalSessionRevocationsService — admin-UI revocation history. (Both
		// the floor AND the gateway-only restriction apply — see CallerPolicy.)
		"/kacho.cloud.iam.v1.InternalSessionRevocationsService/ListByUser",
		// InternalAuthorizeService — admin-tooling tuple/store reads (gateway-
		// fronted; floor AND gateway-only both apply).
		"/kacho.cloud.iam.v1.InternalAuthorizeService/ReadTuples",
		"/kacho.cloud.iam.v1.InternalAuthorizeService/GetFGAStoreInfo",
	}
}

// SystemViewerFloor enforces the `system_viewer@cluster` floor on the READ-RPC
// set. Construct via NewSystemViewerFloor.
type SystemViewerFloor struct {
	// checker — the FGA relation-check port (same one used by RelationWriteGate
	// and InternalIAMService.Check). nil in prod → fail-closed PermissionDenied.
	checker RelationChecker
	// prodMode = production AuthN mode (cfg.AuthN.Mode.IsProduction()). dev-mode
	// (false) is a NO-OP pass-through (default-OFF back-compat); production is
	// fail-closed. Mirrors CallerPolicy / RelationWriteGate.
	prodMode bool
	// readFloor — the set of full-method names under the floor.
	readFloor map[string]struct{}
}

// NewSystemViewerFloor builds the floor over the given READ-RPC set. Defaults to
// dev-mode (no-op); use WithProductionMode to enable strict enforcement.
func NewSystemViewerFloor(checker RelationChecker, readFloorRPCs []string) *SystemViewerFloor {
	m := make(map[string]struct{}, len(readFloorRPCs))
	for _, rpc := range readFloorRPCs {
		m[rpc] = struct{}{}
	}
	return &SystemViewerFloor{checker: checker, readFloor: m}
}

// WithProductionMode toggles strict fail-closed enforcement (production AuthN).
func (f *SystemViewerFloor) WithProductionMode(prod bool) *SystemViewerFloor {
	f.prodMode = prod
	return f
}

// allow returns nil iff the call may proceed past the floor for fullMethod:
//
//  1. fullMethod ∉ ReadFloorRPCs → pass (not our concern — caller-policy /
//     in-handler gate already ran).
//  2. !prodMode → pass (no-op dev/newman back-compat; checker NOT consulted).
//  3. prod, no verified module-cert SAN (unverified / absent / malformed /
//     foreign-trust-domain) → PermissionDenied (fail-closed).
//  4. prod, valid SAN → derive sva → Check(service_account:<sva>,
//     system_viewer, cluster:cluster_kacho_root):
//     - err != nil (FGA outage / 5xx / network / ErrNotConfigured) → Unavailable
//     (retryable, fail-closed — NOT allow; parity with RelationWriteGate).
//     - allowed == false → PermissionDenied.
//     - allowed == true → pass.
//
// nil checker in prod → fail-closed PermissionDenied (never silently allow).
// Message texts are the verbatim, non-leaking "permission denied" /
// "authz backend unavailable" (parity with RelationWriteGate.Authorize).
func (f *SystemViewerFloor) allow(ctx context.Context, fullMethod string) error {
	// 1. Not a READ-floor RPC — pass.
	if _, gated := f.readFloor[fullMethod]; !gated {
		return nil
	}
	// 2. Dev-mode — no-op pass (default-OFF; checker NOT consulted).
	if !f.prodMode {
		return nil
	}
	// 3. Production-mode: a verified module-cert SAN is mandatory (fail-closed).
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	sva, ok := SANToServiceAccountID(san)
	if !ok {
		// Malformed / foreign-trust-domain SAN → not a module identity.
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if f.checker == nil {
		// ReBAC backend not wired → fail-closed (never silently allow).
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// 4. ReBAC the CALLER MODULE-SA (NOT the forwarded end-user) on the coarse
	// cluster read-legitimacy relation.
	allowed, err := f.checker.Check(ctx, "service_account:"+sva, systemViewerRelation, clusterRootObject)
	if err != nil {
		// Backend failure (FGA 5xx / network / ErrNotConfigured) is a transient
		// outage, NOT an authorization decision → Unavailable (retryable,
		// fail-closed). Collapsing it to PermissionDenied would mis-signal a
		// permanent deny; allowing it would be fail-open. Raw error is
		// logged-not-leaked: the message is the fixed, non-leaking text.
		return status.Error(codes.Unavailable, "authz backend unavailable")
	}
	if !allowed {
		// Explicit deny: the SA holds no system_viewer relation → PermissionDenied.
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// Unary returns the unary interceptor enforcing the floor.
func (f *SystemViewerFloor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := f.allow(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream interceptor enforcing the floor.
func (f *SystemViewerFloor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := f.allow(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
