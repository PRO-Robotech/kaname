// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

// scope.go — Scope-relation defense-in-depth guard for mutating use-cases
// (Account/Project Update etc.).
//
// Background: an identity-equality guard ("only the Account owner may
// mutate") double-gates with the api-gateway per-RPC FGA Check, which
// already evaluates an editor/admin relation on the scope object —
// project-editors authorised by the gateway were then wrongly re-denied
// inside the use-case.
//
// Model: kacho-iam keeps a defense-in-depth check, but it is a *relation*
// check (the same model the gateway uses), NOT identity-equality:
//
//	authority = principal owns the owning Account            (bootstrap path)
//	         OR principal holds an FGA `editor`/`admin` relation on the scope.
//
// This is NOT a security regression: a non-member still has neither the owner
// row nor an FGA relation → denied; anonymous is still rejected upstream by
// RequireAuthenticated. owner-equality is simply no longer the SOLE criterion.

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RelationChecker — narrow port for an FGA relation check. Satisfied by
// clients.RelationStore (same Check signature). Use-cases depend on this
// narrow interface, not the full OpenFGA client (Interface Segregation).
type RelationChecker interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// MutateRelations — FGA relations that grant authority to mutate a resource.
// `editor` is sufficient for Update; `admin` (a superset) is accepted too.
var MutateRelations = []string{"editor", "admin"}

// RequireScopeRelation — defense-in-depth authority gate for a mutating
// use-case. Authority is granted when EITHER:
//
//   - the principal owns the owning Account (ownerUserID, bootstrap path), OR
//   - the principal holds one of `relations` on the FGA scope object
//     (delegated administration — e.g. a project-editor who is not the owner).
//
// `scopeType`/`scopeID` identify the FGA object (`project:<id>`,
// `account:<id>`). `ownerUserID` is the owning Account's owner_user_id (may be
// empty for scopes without an owning Account — then only the FGA path applies).
//
// When `checker` is nil (unit tests / degraded mode) the guard falls back to
// owner-only and DENIES non-owners — fail-closed, never fail-open.
func RequireScopeRelation(
	ctx context.Context,
	checker RelationChecker,
	scopeType, scopeID, ownerUserID string,
	relations ...string,
) error {
	// Path 1 — owner of the owning Account (bootstrap path).
	if ownerUserID != "" && IsSelf(ctx, ownerUserID) {
		return nil
	}

	// Path 2 — delegated admin: principal holds one of `relations` on the
	// scope object in FGA.
	if checker != nil {
		if subject, ok := PrincipalSubject(ctx); ok {
			object := fmt.Sprintf("%s:%s", strings.ToLower(scopeType), scopeID)
			rels := relations
			if len(rels) == 0 {
				rels = MutateRelations
			}
			for _, rel := range rels {
				allowed, err := checker.Check(ctx, subject, rel, object)
				if err != nil {
					// Backend outage (FGA 5xx / network / timeout), NOT an
					// authorization decision → Unavailable (retryable,
					// fail-closed). Mirrors RelationWriteGate / SystemViewerFloor:
					// a transient flap must not become a terminal PermissionDenied
					// that the client would never retry.
					return status.Error(codes.Unavailable, "authz backend unavailable")
				}
				if allowed {
					return nil
				}
			}
		}
	}

	return PermissionDenied()
}
