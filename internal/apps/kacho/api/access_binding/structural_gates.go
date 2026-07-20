// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// structural_gates.go — redesign-2026 F9 (IAM-1-24/25/26): the 3 SYNC structural
// gates of AccessBinding.Create, run as FIRST statements before any Operation is
// minted (Operation.error is reserved for truly-async FGA per-object tuple-emission
// failures). The gates are a pre-check with NO TOCTOU — they read the role's
// immutable scope + rules, not the state of other bindings:
//
//   1. scope well-formedness — a malformed scope id → INVALID_ARGUMENT
//      "invalid access binding scope id '<x>'".
//   2. IsRoleAssignable — the role's definition tier must be compatible with the
//      scope anchor → actionable FAILED_PRECONDITION otherwise.
//   3. RoleCoversType — every per-object target type must be covered by the role's
//      authored rules → actionable FAILED_PRECONDITION otherwise.

import (
	"context"
	stderrors "errors"
	"regexp"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// scopeIDRe — well-formedness of a scope-anchor id. The strict prefix→type router
// (`acc-`/`prj-`) is B3-gated (Phase-0); pre-Phase-0 the gate rejects only the
// obviously-malformed (empty / non-id characters, e.g. `!!!`) — an id-safe charset
// `[A-Za-z0-9_.-]`.
var scopeIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validateStructuralGates runs the role-reading structural gates 2 & 3 (gate 1,
// scope well-formedness, runs earlier in Execute — before domain.Validate). Reads
// the role once (immutable scope + rules), so both gates share a single read; no
// TOCTOU.
func (u *CreateAccessBindingUseCase) validateStructuralGates(ctx context.Context, b domain.AccessBinding) error {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	role, err := rd.Roles().Get(ctx, b.RoleID)
	if err != nil {
		// A missing role keeps the FK-RESTRICT contract as FAILED_PRECONDITION
		// (parity with the async doCreate role-read: both missing and mis-scoped
		// roles are FAILED_PRECONDITION on Create).
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return status.Errorf(codes.FailedPrecondition, "Role %s not found", b.RoleID)
		}
		return shared.MapRepoErr(err)
	}

	// Gate 2 — IsRoleAssignable: the role's definition tier ↔ scope anchor.
	if !domain.IsRoleAssignable(role, string(b.ResourceType), b.ResourceID) {
		tier := roleTierDotted(role)
		scope := domain.ScopeTypeToDotted(string(b.ResourceType))
		return status.Errorf(codes.FailedPrecondition,
			"role %s (definitionTier %s) is not assignable on %s:%s; assign at %s or %s tier of this account",
			b.RoleID, tier, scope, b.ResourceID, scope, tier)
	}

	// Gate 3 — RoleCoversType: every per-object target type must be granted verbs by
	// the role's authored rules. allInScope carries no specific type (coverage is
	// checked at materialization); a permissions-only role (no authored rules) is not
	// gated here (its coverage lives in the compiled permissions, out of F9 scope).
	if len(role.Rules) > 0 {
		for _, ref := range b.Target.Resources {
			if !role.Rules.CoversType(ref.Type) {
				return status.Errorf(codes.FailedPrecondition,
					"role %s does not grant verbs on %s; target type must be covered by role.rules",
					b.RoleID, ref.Type)
			}
		}
	}
	return nil
}

// validateScopeID checks the scope-anchor id is well-formed for its tier (IAM-1-26,
// gate 1). A malformed id → INVALID_ARGUMENT "invalid access binding scope id '<x>'".
// The cluster tier is a singleton (exact id); account/project ids are format-checked
// against the id-safe charset (prefix→type routing is B3-gated, Phase-0).
func validateScopeID(resourceType, resourceID string) error {
	switch resourceType {
	case "cluster":
		if resourceID != domain.ClusterSingletonID {
			return status.Errorf(codes.InvalidArgument, "invalid access binding scope id '%s'", resourceID)
		}
	case "account", "project":
		if resourceID == "" || !scopeIDRe.MatchString(resourceID) {
			return status.Errorf(codes.InvalidArgument, "invalid access binding scope id '%s'", resourceID)
		}
	default:
		// A non-hierarchy scope type is rejected upstream by domain.Validate
		// (validResourceTypes) — no scope-id format contract here.
	}
	return nil
}

// roleTierDotted projects the role's server-computed scope group onto the dotted
// definition-tier form for the actionable IsRoleAssignable message.
func roleTierDotted(r domain.Role) string {
	switch domain.ScopeGroupOf(r) {
	case domain.RoleScopeGroupAccount:
		return "iam.account"
	case domain.RoleScopeGroupProject:
		return "iam.project"
	default:
		return "iam.cluster"
	}
}
