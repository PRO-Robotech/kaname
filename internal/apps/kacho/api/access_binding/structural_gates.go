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

	// Gate 2 — IsRoleAssignable: the role's definition tier ↔ scope anchor. The
	// stateless STRICT predicate runs first (system / own-account / own-project); if it
	// rejects, an iam.account-tier role may still be assignable on a project NESTED in
	// the role's account (hierarchy-down, IAM-1-25) — a case the stateless predicate
	// cannot decide (it holds no repo), so resolve the project's owning account here and
	// re-check via IsRoleAssignableInAccount. The account boundary is never crossed: a
	// role of a DIFFERENT account stays rejected with the same actionable text.
	assignable, err := u.roleAssignableOnScope(ctx, rd, role, b)
	if err != nil {
		return err
	}
	if !assignable {
		tier := roleTierDotted(role)
		scope := domain.ScopeTypeToDotted(string(b.ResourceType))
		return status.Errorf(codes.FailedPrecondition,
			"role %s (definitionTier %s) is not assignable on %s:%s; assign at %s or %s tier of this account",
			b.RoleID, tier, scope, b.ResourceID, scope, tier)
	}

	// Gate 3a — per-object target requires a RULES role (least-priv; sibling of the
	// Finding-1 reconciler fix). A per-object target materializes per-object v_* tuples
	// from role.rules via the reconciler. A rules-less LEGACY permissions-only role (not
	// creatable in IAM-1 — RoleService.Create requires rules[] — but a pre-rules-model row
	// may survive back-compat read) has NO per-object materialization path: its access is
	// scope-level tier (buildBindingTuples → tuplesForBinding). Honouring a per-object
	// target on it is impossible, so it would SILENTLY grant the WHOLE scope (over-grant,
	// same class as Finding 1). Reject it fail-closed; an allInScope target on the same
	// role stays valid (scope-level access is the legacy role's intended semantics).
	if len(b.Target.Resources) > 0 && len(role.Rules) == 0 {
		return status.Errorf(codes.FailedPrecondition,
			"role %s has no rules; a per-object target requires a rules-role "+
				"(a permissions-only role grants scope-level access — use target.allInScope)",
			b.RoleID)
	}

	// Gate 3 — RoleCoversType: every per-object target type must be granted verbs by
	// the role's authored rules. allInScope carries no specific type (coverage is
	// checked at materialization); a permissions-only role (no authored rules) is
	// rejected above when it carries a per-object target (Gate 3a) and needs no
	// coverage check for an allInScope grant (its coverage lives in compiled permissions).
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

// roleAssignableOnScope decides gate 2 (IsRoleAssignable) with the IAM-1-25
// hierarchy-down resolution the stateless domain predicate cannot do. The stateless
// STRICT predicate is tried first (system / own-account / own-project — no repo). Only
// when it rejects AND the role is iam.account-tier AND the scope is a project does this
// resolve the project's OWNING account (a single same-DB read) and re-check via
// domain.IsRoleAssignableInAccount — admitting an account-role on a project NESTED in
// the role's account while never crossing the account boundary. A well-formed-but-
// missing project yields not-assignable (the same reject; scope existence + grant
// authority are enforced downstream by requireGrantAuthority).
func (u *CreateAccessBindingUseCase) roleAssignableOnScope(ctx context.Context, rd Reader, role domain.Role, b domain.AccessBinding) (bool, error) {
	if domain.IsRoleAssignable(role, string(b.ResourceType), b.ResourceID) {
		return true, nil
	}
	// Hierarchy-down is admissible ONLY for an iam.account-tier role on a project scope.
	if b.ResourceType != "project" || domain.ScopeGroupOf(role) != domain.RoleScopeGroupAccount {
		return false, nil
	}
	prj, err := rd.Projects().Get(ctx, domain.ProjectID(b.ResourceID))
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			// Cannot confirm nesting → not assignable (fail-closed; no over-grant).
			return false, nil
		}
		return false, shared.MapRepoErr(err)
	}
	return domain.IsRoleAssignableInAccount(role, string(b.ResourceType), b.ResourceID, string(prj.AccountID)), nil
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
