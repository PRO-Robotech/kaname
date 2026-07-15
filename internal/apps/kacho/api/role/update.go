// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// update.go — UpdateRoleUseCase. Только custom; account_id / is_system immutable.
// system-role update reject'ится sync ("system role is read-only").

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

type UpdateRoleInput struct {
	ID          domain.RoleID
	Name        *domain.RoleName
	Description *domain.Description
	Rules       domain.Rules
	// Labels — own-resource tenant-facing метки самого ресурса Role (НЕ путать с
	// Rule.MatchLabels, отбирающим объекты под грантом). mutable; делают Role
	// label-selectable наравне с account/project (iam-direct ARM_LABELS).
	Labels     domain.Labels
	UpdateMask []string
	// ResourceVersion — xmin OCC token echoed from a prior Get/List; when set on a
	// rules-changing Update it guards against a concurrent edit (A-08/OCC).
	ResourceVersion string
}

var roleMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"rules":       {},
	"labels":      {},
}

var roleImmutableFields = map[string]string{
	"account_id": "account_id is immutable after Role.Create",
	"accountId":  "account_id is immutable after Role.Create",
	"is_system":  "is_system is immutable after Role.Create",
	"isSystem":   "is_system is immutable after Role.Create",
	"id":         "id is immutable after Role.Create",
	"created_at": "created_at is immutable after Role.Create",
	"createdAt":  "created_at is immutable after Role.Create",
	// permissions is the compiled/derived projection — not directly mutable.
	"permissions": "permissions is immutable after Role.Create",
}

type UpdateRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// reconciler — FGA tuple reconcile fan-out for a permissions change
	// (nil-safe: when unwired the role UPDATE still succeeds but active-binding
	// tuples are not reconciled — only the case in standalone unit tests of the
	// non-permission paths). Implemented by access_binding.RoleTupleReconciler,
	// wired in the composition root.
	reconciler TupleReconciler
	// membership — RBAC rules-model: re-materializes the role.rules
	// ARM_LABELS membership of every ACTIVE binding after a rules change commits
	// (the fan-out + the bounded-limit guard). nil-safe (unit tests of the
	// non-rules paths leave it unwired; the periodic sweep also re-converges).
	membership RulesMembershipFanout
}

func NewUpdateRoleUseCase(r Repo, opsRepo operations.Repo) *UpdateRoleUseCase {
	return &UpdateRoleUseCase{repo: r, opsRepo: opsRepo}
}

// WithTupleReconciler wires the FGA tuple reconcile fan-out. nil-safe.
func (u *UpdateRoleUseCase) WithTupleReconciler(r TupleReconciler) *UpdateRoleUseCase {
	u.reconciler = r
	return u
}

// WithMembershipFanout wires the role.rules membership fan-out (the
// bound-check + post-commit per-binding reconcile). nil-safe.
func (u *UpdateRoleUseCase) WithMembershipFanout(m RulesMembershipFanout) *UpdateRoleUseCase {
	u.membership = m
	return u
}

func (u *UpdateRoleUseCase) Execute(ctx context.Context, in UpdateRoleInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, roleMutableFields, roleImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Read the role WITH its xmin OCC token so the worker-tx UPDATE
	// is guarded against a concurrent Role.Update (two updates each deriving the
	// FGA fan-out from their own role projection → ledger↔FGA drift). The token is
	// captured on the sync path and echoed into UpdateCAS inside the worker-tx; the
	// loser fails FAILED_PRECONDITION and its whole writer-tx (UPDATE + reconcile
	// fan-out) rolls back atomically (ban #10).
	current, version, err := rd.Roles().GetWithVersion(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	if current.IsSystem {
		_ = rd.Rollback(ctx)
		return nil, shared.InvalidArg("id", "System role is read-only and cannot be updated")
	}
	// Custom role: проверяем ownership account.
	acct, err := rd.Accounts().Get(ctx, current.AccountID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(acct.OwnerUserID)); err != nil {
		return nil, err
	}

	target := current
	var changed []string
	if in.Name != nil && shared.MaskAllows(in.UpdateMask, "name") && *in.Name != current.Name {
		target.Name = *in.Name
		changed = append(changed, "name")
	}
	if in.Description != nil && shared.MaskAllows(in.UpdateMask, "description") && *in.Description != current.Description {
		target.Description = *in.Description
		changed = append(changed, "description")
	}
	// RBAC rules-model: rules are the authored, mutable field. When they
	// change, recompile the INTERNAL permissions projection (anchor/names; matchLabels
	// excluded; ≤1024 cap) and store both. permissions itself is immutable input
	// (rejected in update_mask above).
	if in.Rules != nil && shared.MaskAllows(in.UpdateMask, "rules") {
		// Validate the new rules first (specific cardinality/wildcard/feed errors),
		// then compile (enforces the ≤1024 compiled-cap).
		if verr := in.Rules.Validate(current.IsSystem); verr != nil {
			return nil, shared.MapValidationErr(verr)
		}
		compiled, cerr := domain.CompileRules(in.Rules)
		if cerr != nil {
			return nil, shared.MapValidationErr(cerr)
		}
		target.Rules = in.Rules
		target.Permissions = compiled
		changed = append(changed, "rules")
	}
	// labels — own-resource метки. Применяются, только если mask их разрешает
	// (или пустой mask = full-PATCH) И значение изменилось. Изменение labels
	// триггерит iam-direct re-материализацию (см. doUpdate reconcile-event).
	if newLabels, apply := shared.ResolveLabelsUpdate(in.UpdateMask, in.Labels); apply && !shared.LabelsEqual(newLabels, current.Labels) {
		target.Labels = newLabels
		changed = append(changed, "labels")
	}
	if err := target.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// OCC: when the caller supplies a resource_version AND the rules are
	// changing, it must match the version read on the sync path; a stale token →
	// FAILED_PRECONDITION (the role was edited concurrently). When omitted, the
	// xmin worker-tx CAS below is the sole guard (last-writer, back-compat).
	if in.ResourceVersion != "" && slices.Contains(changed, "rules") && in.ResourceVersion != version {
		return nil, shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Role was modified concurrently, retry"))
	}

	// Bound-check: a rules change fans out a per-binding reconcile over
	// the role's ACTIVE bindings. A role carried by more than the contract limit is
	// rejected SYNC (before the Operation) — a single Role.Update must not trigger
	// an unbounded fan-out. Checked only when the rules actually change + the fanout
	// is wired (nil-safe). NOTE: this is a best-effort soft guard (a count read here,
	// the fan-out later), NOT a hard cap — a concurrent grant can push the count past
	// the limit between this check and the fan-out. That is acceptable: the bound only
	// protects against grossly-oversized fan-out, and the per-binding reconcile is
	// idempotent + bounded per binding, so a small overshoot is harmless.
	if u.membership != nil && slices.Contains(changed, "rules") {
		n, cerr := u.membership.CountActiveBindings(ctx, in.ID)
		if cerr != nil {
			return nil, shared.MapRepoErr(cerr)
		}
		if n > MaxRoleFanoutBindings {
			return nil, status.Errorf(codes.FailedPrecondition,
				"role carried by too many bindings to update atomically; split role")
		}
	}

	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update role %s", in.ID),
		&iamv1.UpdateRoleMetadata{RoleId: string(in.ID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	maskCopy := append([]string{}, in.UpdateMask...)
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, target, maskCopy, actor, changedCopy, version)
	})
	return &op, nil
}

func (u *UpdateRoleUseCase) doUpdate(ctx context.Context, r domain.Role, mask []string, actor string, changed []string, expectedVersion string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Role, error) {
			// xmin-CAS: the worker-tx UPDATE is guarded by the version
			// captured on the sync path. A concurrent Role.Update that committed first
			// bumped xmin → this CAS matches 0 rows → ErrFailedPrecondition and the
			// whole writer-tx (incl. the reconcile fan-out below) rolls back.
			upd, uerr := w.RolesW().UpdateCAS(ctx, r, mask, expectedVersion)
			if uerr != nil {
				return domain.Role{}, uerr
			}
			if len(changed) == 0 {
				return upd, nil
			}
			// When the rules (→ compiled permissions) changed, reconcile the
			// FGA tuples of the role's ACTIVE bindings to the new permissions IN THIS
			// writer-tx (atomic with the role UPDATE, ban #10). Without this an active
			// binding keeps its old-tier FGA tuple after a downgrade (orphan = standing
			// privilege). Bounded fan-out (active bindings of this single role),
			// idempotent (unchanged tier → empty delta). nil-safe: in unit tests of
			// the non-rules paths the reconciler may be unwired.
			if u.reconciler != nil && slices.Contains(changed, "rules") {
				if rerr := u.reconciler.ReconcileRoleTuples(ctx, w, upd.ID, upd); rerr != nil {
					return domain.Role{}, rerr
				}
			}
			// RBAC explicit-model: sync role_rule_selectors with the new
			// UNIFIED materializing rules (anchor/names/labels) in the SAME writer-tx
			// (ban #10) so the post-commit membership fan-out (and the reconciler
			// fast-path / sweep) see the new selectors. A removed rule drops its
			// selector here; the per-binding membership re-materialize (eager-revoke by
			// rule_fp) runs post-commit.
			if slices.Contains(changed, "rules") {
				if serr := w.RolesW().ReplaceRuleSelectors(ctx, upd.ID, upd.Rules.MaterializingSelectors()); serr != nil {
					return domain.Role{}, serr
				}
			}
			// changed_fields records WHAT changed (e.g. ["permissions"]) — the
			// full permissions set is intentionally NOT embedded.
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventRoleUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "role",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.Role{}, aerr
			}
			// Изменение own-resource labels может изменить membership iam-direct
			// селектора (правило, матчащее iam.role по меткам). Co-commit reconcile-event
			// в ЭТОЙ writer-tx (ban #10, паритет с user/SA Update) — reconciler ре-оценит
			// затронутые iam.role selector-биндинги (≤2s): label add → грант появляется,
			// label remove/change → eager fall-out. Только при изменении labels.
			if slices.Contains(changed, "labels") {
				if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", string(upd.ID)); rerr != nil {
					return domain.Role{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}

	// Membership fan-out: after the rules change + selector-sync committed,
	// re-materialize the role.rules ARM_LABELS membership of every ACTIVE binding of
	// the role (each in its OWN writer-tx, idempotent). A removed rule's per-object
	// members are eager-revoked by rule_fp (no residual); new/edited rules'
	// matched objects are materialized. Runs in the Operation worker so the Operation
	// reports done only once membership has converged. Bounded by the sync count-check
	// above. nil-safe + fatal-to-Operation (a fan-out error fails the Operation so the
	// caller learns the membership did not converge; the sweep also re-converges).
	if u.membership != nil && slices.Contains(changed, "rules") {
		if ferr := u.membership.ReconcileActiveBindings(ctx, updated.ID); ferr != nil {
			return nil, shared.MapRepoErr(ferr)
		}
	}
	return marshalRole(updated)
}
