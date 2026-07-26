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

// RequireOwnerMatchesPrincipal is GONE (2026-07-27). It was written as
// request-body validation for ONE operation — Account.Create anti-hijacking
// ("you may not create an account naming someone else as owner") — and was then
// copied into 12 other use-cases where the same comparison means a DECISION
// ABOUT ACCESS, not validation.
//
// Both halves are now obsolete:
//
//   - Account.Create no longer needs it. `owner_user_id` is OUTPUT-ONLY: supplying
//     ANY value is a sync InvalidArgument and the owner is derived from the
//     verified principal (account/create.go). There is nothing left to hijack —
//     a stronger, structural guarantee than the comparison ever gave.
//   - The other 12 are decided by the MODEL. Each carries a permission-catalog
//     entry pinning a per-object relation (`v_delete@account`,
//     `v_update@iam_group`, …) that the api-gateway Checks before iam is dialed.
//     The comparison sat on top of that working system as a second, coarser one:
//     it keyed on `accounts.owner_user_id`, so it could not be granted, scoped,
//     revoked or audited; it voided delegation the owner had deliberately made
//     through an AccessBinding; it rejected cluster-admins on accounts they do
//     not own; and because a service-account id can never equal an account's
//     owner user-id, it made all 12 unreachable for ANY machine principal by
//     construction — answering with InvalidArgument naming a field the caller
//     never sent.
//
// See security.md «Авторизация живёт в МОДЕЛИ, а не в самодельных проверках».
// Do not reintroduce an identity-equality gate next to a catalog entry: express
// the policy as a relation in the model instead.

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
