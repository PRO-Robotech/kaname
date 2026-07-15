// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// rules_membership_fanout.go — role.rules ARM_LABELS membership fan-out after
// a role's rules change.
//
// RulesMembershipFanout drives the role.rules ARM_LABELS membership reconcile of
// EVERY ACTIVE binding of a role after the role's rules change (Role.Update). It is
// the post-commit half of the fan-out: the in-tx tier delta is RoleTupleReconciler;
// THIS re-materializes the per-rule membership (a removed ARM_LABELS rule's members
// are eager-revoked by rule_fp, new/edited rules' matched objects are materialized).
//
// It implements role.RulesMembershipFanout. It depends ONLY on:
//   - a membershipReconciler (γ reconcile.Reconciler — ReconcileBinding per binding,
//     each in its own writer-tx, idempotent), and
//   - a Reader to list/count the role's ACTIVE bindings.
// No pgx/grpc here (Clean Architecture: the reconcile-store + pgx live in the
// adapter the reconciler holds).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// membershipReconciler — the per-binding membership reconcile entry point (the γ
// reconcile.Reconciler satisfies it). Each call opens its own writer-tx.
type membershipReconciler interface {
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// RoleMembershipFanout — the role.RulesMembershipFanout implementation.
type RoleMembershipFanout struct {
	repo       kachorepo.Repository
	reconciler membershipReconciler
}

// NewRoleMembershipFanout constructs the fan-out over the repo + the reconciler.
func NewRoleMembershipFanout(repo kachorepo.Repository, reconciler membershipReconciler) *RoleMembershipFanout {
	return &RoleMembershipFanout{repo: repo, reconciler: reconciler}
}

// CountActiveBindings returns the number of ACTIVE/PENDING bindings of a role
// (the bound-check). Read-only, pool-scoped.
func (f *RoleMembershipFanout) CountActiveBindings(ctx context.Context, roleID domain.RoleID) (int, error) {
	rd, err := f.repo.Reader(ctx)
	if err != nil {
		return 0, fmt.Errorf("fanout: open reader: %w", err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	return rd.AccessBindings().CountActiveByRole(ctx, roleID)
}

// ReconcileActiveBindings re-materializes the role.rules membership of every ACTIVE
// binding of the role. Each binding is reconciled in its OWN writer-tx (the
// reconciler opens it), so a slow fan-out does not hold one long lock; the per-
// binding diff is idempotent (a re-run converges). The list is read once
// (pool-scoped); a binding revoked mid-fan-out is a no-op in ReconcileBinding
// (LoadBinding sees !Active). Bounded by the sync count-check upstream.
func (f *RoleMembershipFanout) ReconcileActiveBindings(ctx context.Context, roleID domain.RoleID) error {
	rd, err := f.repo.Reader(ctx)
	if err != nil {
		return fmt.Errorf("fanout: open reader: %w", err)
	}
	bindings, err := rd.AccessBindings().ListActiveByRole(ctx, roleID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return fmt.Errorf("fanout: list active bindings of role %s: %w", roleID, err)
	}
	for i := range bindings {
		if rerr := f.reconciler.ReconcileBinding(ctx, bindings[i].ID); rerr != nil {
			return fmt.Errorf("fanout: reconcile binding %s of role %s: %w", bindings[i].ID, roleID, rerr)
		}
	}
	return nil
}
