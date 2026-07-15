// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)

// TupleReconciler — port the Role.Update use-case calls when a role's
// permissions change, to reconcile the FGA tuples of the role's ACTIVE bindings
// to the new permissions. Implemented by
// access_binding.RoleTupleReconciler (which owns the FGA tuple-builder + the
// persisted emitted-tuple store). The use-case stays free of FGA-tuple
// knowledge (clean-arch: role does NOT import access_binding; access_binding
// implements this port and is wired in the composition root).
//
// ReconcileRoleTuples runs INSIDE the caller's writer-tx (the same tx as the
// role UPDATE), so the role mutation + the per-binding FGA delta emit +
// emitted-set ledger update commit-or-rollback together (ban #10). For each
// active binding of roleID it diffs the stored emitted-set (old) against the
// tuples derived from newRole (new) and emits EmitRelationDelete(removed) +
// EmitRelationWrite(added) + ReplaceEmittedTuples. Bounded by the number of
// active bindings of the single mutated role; idempotent (an unchanged tier
// yields an empty delta).
type TupleReconciler interface {
	ReconcileRoleTuples(ctx context.Context, w Writer, roleID domain.RoleID, newRole domain.Role) error
}

// RulesMembershipFanout — port the Role.Update use-case calls AFTER a rules change
// commits, to re-materialize the role.rules ARM_LABELS membership of every ACTIVE
// binding of the role. A removed
// ARM_LABELS rule's per-object members are eager-revoked by rule_fp; a new/edited
// rule's matched objects are materialized. Implemented by the access_binding
// membership-fanout adapter (γ reconcile.Reconciler + the AB reader), wired in the
// composition root. The use-case stays free of reconcile-store knowledge.
//
// CountActiveBindings is the bound-check: a role carried by more than the
// contract limit of active bindings → the use-case fails the Operation
// FAILED_PRECONDITION BEFORE the rules change commits, so a single Role.Update
// cannot trigger an unbounded fan-out. ReconcileActiveBindings runs the per-binding
// reconcile post-commit (each in its OWN writer-tx, idempotent), so the Operation
// reports done only once the membership is converged.
type RulesMembershipFanout interface {
	CountActiveBindings(ctx context.Context, roleID domain.RoleID) (int, error)
	ReconcileActiveBindings(ctx context.Context, roleID domain.RoleID) error
}

// MaxRoleFanoutBindings — the contract bound: a Role.Update whose
// rules change is rejected FAILED_PRECONDITION when the role is carried by more
// than this many active bindings ("split role"). One constant for use-case + test.
const MaxRoleFanoutBindings = 10000
