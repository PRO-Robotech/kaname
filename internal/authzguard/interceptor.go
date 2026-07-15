// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// interceptor.go — gRPC unary/stream interceptor for kacho-iam, a
// defence-in-depth anti-anonymous floor in front of every mutating RPC.
//
// This is NOT the platform's per-user PDP: the api-gateway is the single
// authZ front door — it validates the JWT and runs per-user ReBAC via
// iam.Check with the permission catalogue (seed.LoadPermissionRegistry).
// iam does NOT re-ReBAC the end user on its own listeners (see serve.go
// "iam does NOT re-ReBAC the end user here"). This gate exists only to
// fail closed against an *unauthenticated* principal reaching a mutating
// RPC (defence-in-depth against a mis-wired listener / direct dial),
// blocking anonymous mutation of Account/Project/AccessBinding/Group/SA/
// Role/custom-Role-with-iam.*.* resources.
//
// Policy: default-deny anonymous unless (a) FullMethod is in
// whitelistFullMethod, or (b) the method-name ends in a read-only suffix
// (Get/List/Watch/Resolve/BatchGet/Search/Check/Whoami). Object-scoped
// authZ and read-path scope-filtering live inside the use-cases; this gate
// does not attempt them.

package authzguard

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// readonlySuffixes — explicit read-only allowlist. Methods whose name ends
// in one of these suffixes do NOT require an authenticated principal —
// anonymous callers may invoke them.
//
// Any method NOT matching this suffix list (regardless of whether it ends in
// Create/Update/Delete/Approve/Deny/Issue/Revoke/Generate/Cancel/Activate/…)
// is treated as a mutating / sensitive RPC and denied for anonymous callers.
// This default-deny posture avoids the gap a mutating-suffix allowlist would
// open (anything not in the list — Approve*/Deny*/Issue/Revoke/Generate*/
// Cancel*/ActivateJIT — would be reachable by anonymous).
//
// Matching is strings.HasSuffix ONLY. HasPrefix would let methods like
// `ListAndDelete` slip through the gate via the `List` prefix — dangerous.
// Suffix-only is the secure default.
//
// Update with extreme caution: every entry expands the anonymous attack
// surface. Reviewer sign-off required.
var readonlySuffixes = []string{
	"Get", "List", "Watch", "Resolve",
	"BatchGet", "Search", "Check", "Whoami",
}

// whitelistFullMethod — RPCs that do NOT require an authenticated principal
// (bootstrap-flow, internal-listener-only RPCs).
//
// Minimal set: register-myself, federation login/callback, OIDC discovery,
// JWKS, health, internal bootstrap. Anything else — even legitimate
// self-registration — must come through an explicit allow.
var whitelistFullMethod = map[string]struct{}{
	// UpsertFromIdentity is invoked by api-gateway middleware on first login —
	// at that moment the Principal is still anonymous. This is a legitimate
	// "register-myself" operation. (In production-strict deployments it is
	// additionally protected by mTLS / NetworkPolicy.)
	"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity": {},
	// LookupSubject — internal helper, invoked by api-gateway without an
	// auth-context.
	"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject": {},
	// Check — internal RPC.
	"/kacho.cloud.iam.v1.InternalIAMService/Check": {},
	// AuthorizeService.{ListObjects,ListSubjects} bypass: cluster-internal
	// peer calls (kacho-vpc/cmd/vpc/main.go bootstrap-time peer call,
	// kacho-compute idem) arrive with NO PerRPCCredentials — they are not
	// user-requests but preflight authz-queries: "which resource_ids are
	// <verb>-accessible to caller X?" (ListObjects) and the inverse "who
	// may <verb> this resource?" (ListSubjects). The suffix matcher on
	// "List" does NOT cover them — "ListObjects" / "ListSubjects" do not
	// end in "List" (HasSuffix is the only permitted matcher per the
	// readonlySuffixes contract above), so an explicit FullMethod entry is
	// required. Defence-in-depth for production-strict (cross-pod authn)
	// is delivered later via mTLS — this whitelist is the interim guard.
	"/kacho.cloud.iam.v1.AuthorizeService/ListObjects":  {},
	"/kacho.cloud.iam.v1.AuthorizeService/ListSubjects": {},
}

// isReadOnly — true iff method-name ends in one of the readonlySuffixes.
// SUFFIX-ONLY; do NOT add prefix-matching (see readonlySuffixes doc above
// for the rationale — `ListAndDelete` would slip past a `List` prefix).
func isReadOnly(fullMethod string) bool {
	parts := strings.Split(fullMethod, "/")
	if len(parts) < 3 {
		return false
	}
	name := parts[len(parts)-1]
	for _, s := range readonlySuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// AntiAnonymousUnary — gRPC unary server interceptor. Policy:
// default-deny anonymous unless (a) FullMethod is in whitelistFullMethod, or
// (b) method-name ends in a read-only suffix (Get/List/Watch/Resolve/…).
// Everything else (Create/Update/Delete/Approve/Deny/Issue/Revoke/Generate/
// Cancel/Activate/…) is rejected for anonymous principals.
func AntiAnonymousUnary(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := whitelistFullMethod[info.FullMethod]; ok {
			return handler(ctx, req)
		}
		if isReadOnly(info.FullMethod) {
			return handler(ctx, req)
		}
		if IsAnonymous(ctx) {
			if logger != nil {
				p := operations.PrincipalFromContext(ctx)
				logger.Warn("authz_anonymous_mutation_denied",
					slog.String("method", info.FullMethod),
					slog.String("principal_type", p.Type),
					slog.String("principal_id", p.ID),
				)
			}
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}
		return handler(ctx, req)
	}
}

// AntiAnonymousStream — symmetric stream-RPC interceptor (same policy).
func AntiAnonymousStream(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if _, ok := whitelistFullMethod[info.FullMethod]; ok {
			return handler(srv, ss)
		}
		if isReadOnly(info.FullMethod) {
			return handler(srv, ss)
		}
		if IsAnonymous(ss.Context()) {
			if logger != nil {
				logger.Warn("authz_anonymous_stream_denied", slog.String("method", info.FullMethod))
			}
			return status.Error(codes.PermissionDenied, "permission denied")
		}
		return handler(srv, ss)
	}
}
