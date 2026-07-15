// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authzguard — minimal per-use-case authz guard for kacho-iam,
// covering the gap until a full OpenFGA interceptor (permission_map–based)
// replaces these inline checks.
//
// Use-cases call RequireAuthenticated(ctx) in the first sync step, BEFORE
// creating an Operation. If principal-type == "anonymous" (or missing) →
// PermissionDenied. The bootstrap admin (system/bootstrap) is rejected too —
// it is only used by backend-internal paths and tests, which bypass guards
// via WithPrincipal directly.
//
// This is a transitional guard layer until the full OpenFGA interceptor with
// permission_map is in place; once that lands, these checks collapse into a
// single Check call.
package authzguard

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// RequireAuthenticated returns PermissionDenied if the principal in ctx is
// anonymous or absent. user / service_account / system-bootstrap are passed
// through.
//
// Message text is the Kachō canonical `"permission denied"` (no leak of
// internal details).
//
// IMPORTANT: kacho-api-gateway injects an anonymous request as
// Principal{Type:"system", ID:"anonymous"} (see auth.go:189 — injectAnonymous).
// A principal with ID="anonymous" MUST NOT have privileges — despite
// type=system. Both fields are checked.
func RequireAuthenticated(ctx context.Context) error {
	if IsAnonymous(ctx) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// IsSelf — true if principal.ID == targetID.
func IsSelf(ctx context.Context, targetID string) bool {
	p := operations.PrincipalFromContext(ctx)
	return p.ID != "" && targetID != "" && p.ID == targetID
}

// PermissionDenied — canonical PermissionDenied gRPC error (Kachō error text).
func PermissionDenied() error {
	return status.Error(codes.PermissionDenied, "permission denied")
}

// RequireOwnerMatchesPrincipal — anti-hijacking guard for Account.Create.
// An authenticated user may create an Account ONLY with themselves as
// owner_user_id; otherwise that would be privilege escalation by claiming
// an account with another user-id as owner. Cluster-admin tooling must go
// through the internal listener (bypass guard).
//
// Returns InvalidArgument (3) when owner_user_id != principal, not
// PermissionDenied (7): this is a request-body validation failure — the
// caller is supplying an owner_user_id that doesn't match their identity —
// not an authz failure (they have no permission).
func RequireOwnerMatchesPrincipal(ctx context.Context, ownerUserID string) error {
	p := operations.PrincipalFromContext(ctx)
	if p.ID == "" || ownerUserID == "" {
		return status.Error(codes.InvalidArgument, "owner_user_id must match the authenticated principal")
	}
	if p.ID != ownerUserID {
		return status.Error(codes.InvalidArgument, "owner_user_id must match the authenticated principal")
	}
	return nil
}

// IsAnonymous — true if the principal is anonymous / empty / system+anonymous
// / system+bootstrap-fallback.
//
// api-gateway injects anonymous as {Type:"system", ID:"anonymous"};
// api-gateway may also fail to forward principal-headers entirely — in that
// case PrincipalFromContext returns SystemPrincipal{Type:"system",
// ID:"bootstrap"} (fallback). In a gRPC handler both cases = anonymous.
//
// **Internal background-job bootstrap** uses `WithPrincipal` directly with a
// concrete {Type, ID} — never the empty-ctx fallback. So rejecting
// system/bootstrap here is safe.
func IsAnonymous(ctx context.Context) bool {
	p := operations.PrincipalFromContext(ctx)
	if p.ID == "" || p.Type == "" {
		return true
	}
	if p.Type == "anonymous" {
		return true
	}
	// api-gateway injectAnonymous → Type=system, ID=anonymous.
	if p.ID == "anonymous" {
		return true
	}
	// SystemPrincipal()-fallback: ctx didn't contain a Principal — typical
	// "api-gateway did not forward x-kacho-principal-* headers", equivalent
	// to an anonymous request.
	if p.Type == "system" && p.ID == "bootstrap" {
		return true
	}
	return false
}
