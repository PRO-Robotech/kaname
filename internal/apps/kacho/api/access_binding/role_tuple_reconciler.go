// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// role_tuple_reconciler.go — role-permission tuple reconciler.
//
// RoleTupleReconciler implements role.TupleReconciler: a ROLE-PERMISSION fan-out.
// When a role's permissions/rules change (Role.Update), it reconciles the FGA
// tuples of the role's ACTIVE bindings to the new tier via buildBindingTuples (the
// thin-binding scope-anchor / per-rule scope_grant projection). The RBAC
// rules-model clean-cut removed the per-binding target arms (resources[]/
// selector), so the binding is thin and buildBindingTuples is the whole story for
// the in-tx tier delta.
//
// The role.rules ARM_LABELS per-object MEMBERSHIP retiering is the complementary
// half handled by RoleMembershipFanout (rules_membership_fanout.go): a rule's verb
// change bumps its rule_fp, so the γ reconciler eager-revokes the old-fp members
// and re-materializes the new ones at the new tier. RoleTupleReconciler owns the
// binding-level (anchor/scope_grant) tuples; RoleMembershipFanout owns the
// per-member tuples.
//
// It lives in the access_binding package because that package owns the FGA
// tuple-builder (tuples.go) AND the persisted emitted-tuple ledger — so the role
// use-case stays free of FGA-tuple knowledge (clean-arch: role defines the port,
// access_binding implements it, the composition root wires it).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// RoleTupleReconciler — the Role.Update reconcile fan-out.
type RoleTupleReconciler struct{}

// NewRoleTupleReconciler constructs the reconciler (stateless — all state lives
// in the writer-tx passed to ReconcileRoleTuples).
func NewRoleTupleReconciler() *RoleTupleReconciler { return &RoleTupleReconciler{} }

// ReconcileRoleTuples reconciles every ACTIVE binding of roleID from its stored
// emitted-set (old) to the tuples derived from newRole (new), inside the
// caller's writer-tx (the same tx as the role UPDATE — atomic, ban #10).
//
// Per binding:
//  1. derive newTuples = buildBindingTuples(binding, newRole) — the thin-binding
//     scope-anchor / per-rule scope_grant projection,
//  2. read oldTuples = SelectEmittedTuples(binding),
//  3. diff: removed = old\new, added = new\old,
//  4. EmitRelationDelete(removed) + EmitRelationWrite(added) +
//     ReplaceEmittedTuples(binding, newTuples).
//
// Bounded: the fan-out iterates only the ACTIVE bindings of the SINGLE mutated
// role (ListActiveByRole), not all bindings. Idempotent: an unchanged tier
// yields removed=added=∅ (no fga_outbox rows, the ledger replace is a no-op
// swap) — so a re-run / replayed Operation does not double-emit.
func (r *RoleTupleReconciler) ReconcileRoleTuples(ctx context.Context, w kachorepo.Writer, roleID domain.RoleID, newRole domain.Role) error {
	bindings, err := w.AccessBindings().ListActiveByRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("list active bindings of role %s: %w", roleID, err)
	}
	for i := range bindings {
		b := bindings[i]
		// The binding is thin (rules-model clean-cut — no per-binding target);
		// buildBindingTuples is the whole binding-level projection. The per-member
		// (ARM_LABELS) tuple retiering is the complementary RoleMembershipFanout
		// half (a rule verb change bumps rule_fp → γ eager-revokes + re-materializes
		// at the new tier).
		newTuples, berr := buildBindingTuples(b, newRole)
		if berr != nil {
			return fmt.Errorf("build tuples for binding %s: %w", b.ID, berr)
		}
		// Read ONLY the binding-level subset (source='binding'). The ARM_LABELS
		// per-member tuples (source='member') are owned by RoleMembershipFanout — if
		// the diff saw them it would classify every member tuple as `removed` and
		// EmitRelationDelete would revoke live label-selected access (CRITICAL fix).
		oldTuples, serr := w.AccessBindings().SelectEmittedTuplesBySource(ctx, b.ID, "binding")
		if serr != nil {
			return fmt.Errorf("read emitted-set of binding %s: %w", b.ID, serr)
		}

		removed, added := diffTuples(oldTuples, newTuples)
		if len(removed) > 0 {
			if err := w.AccessBindingsW().EmitRelationDelete(ctx, removed); err != nil {
				return fmt.Errorf("emit relation delete for binding %s: %w", b.ID, err)
			}
		}
		if len(added) > 0 {
			if err := w.AccessBindingsW().EmitRelationWrite(ctx, added); err != nil {
				return fmt.Errorf("emit relation write for binding %s: %w", b.ID, err)
			}
		}
		// Keep the ledger in lock-step with the new emitted projection. When the
		// delta is empty this is a no-op swap (same set in, same set out).
		if len(removed) > 0 || len(added) > 0 {
			if err := w.AccessBindingsW().ReplaceEmittedTuples(ctx, b.ID, newTuples); err != nil {
				return fmt.Errorf("replace emitted-set of binding %s: %w", b.ID, err)
			}
		}
	}
	return nil
}

// diffTuples computes (removed = old\new, added = new\old) on set semantics over
// the (User, Relation, Object) natural key. Used by the reconcile fan-out to emit
// the minimal FGA delta and keep the drainer churn-free (idempotent).
func diffTuples(oldT, newT []abrepo.RelationTuple) (removed, added []abrepo.RelationTuple) {
	oldSet := make(map[abrepo.RelationTuple]struct{}, len(oldT))
	for _, t := range oldT {
		oldSet[t] = struct{}{}
	}
	newSet := make(map[abrepo.RelationTuple]struct{}, len(newT))
	for _, t := range newT {
		newSet[t] = struct{}{}
	}
	for _, t := range oldT {
		if _, ok := newSet[t]; !ok {
			removed = append(removed, t)
		}
	}
	for _, t := range newT {
		if _, ok := oldSet[t]; !ok {
			added = append(added, t)
		}
	}
	return removed, added
}
