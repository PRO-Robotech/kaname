// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// forward.go — the ADDITIVE forward fast-path for a freshly-REGISTERED object.
//
// PROBLEM (throughput, diagnosed under parallel e2e load). The full ReconcileObject
// fans out to every binding whose selector matches the changed object and, for EACH
// such binding, takes the per-binding advisory lock (pg_advisory_xact_lock) + a
// `SELECT … FOR UPDATE` on the binding row and does a FULL O(scope) desired-set
// recompute. Every resource of one project/account shares ONE editor@project /
// owner@account binding, so under N concurrent RegisterResource calls in the same
// scope ALL N reconciles SERIALIZE on that single binding's advisory lock → a queue
// forms → the creator's owner-tuple materialization lag exceeds the newman
// read-your-writes retry budget (transient 403 "lacks relation" on one's OWN fresh
// resource).
//
// FIX. On the create/register happy-path we do NOT need a full recompute: the only
// thing that changed is that ONE new object now exists, so the only new access to
// materialize is THAT object's per-object tuples for the bindings that match it.
// ReconcileObjectForward materializes EXACTLY the freshly-registered object's tuples
// for each scope-narrowed matching binding — WITHOUT MatchAllInScope, WITHOUT the full
// desired-diff, WITHOUT the FOR UPDATE binding row-lock, and — critically for
// throughput — WITHOUT the EXCLUSIVE per-binding advisory lock the full path takes. It
// holds only a SHARE advisory lock on the binding (see "LOCK CHOICE" below).
//
// WHY THE FULL PATH'S EXCLUSIVE LOCK SERIALIZES, AND WHY FORWARD DOES NOT NEED IT:
//
//   - The EXCLUSIVE advisory lock + FOR UPDATE on the full path exist to make the
//     DELETE-STALE diff consistent: a full recompute computes desired = {all in-scope
//     objects} and REVOKES every current member not in desired. Two concurrent full
//     passes of the same binding from different snapshots could revoke each other's
//     just-written members — so they serialize on the EXCLUSIVE lock (exactly-once
//     materialization under N replicas). Because every resource of one project/account
//     shares ONE binding, that EXCLUSIVE lock serializes ALL N registrations → the
//     bottleneck.
//   - The forward path is ADDITIVE: it only WRITES the one new object's ACTIVE member +
//     tuples and NEVER deletes anything. Two forward passes for DIFFERENT objects (R1,
//     R2) of the SAME binding touch DISJOINT rows (member keyed by object, fga_outbox
//     append-only, ledger keyed by (binding,user,relation,object)) → they do not
//     conflict → they need no mutual serialization. So forward does NOT take the
//     EXCLUSIVE lock; N registrations proceed CONCURRENTLY (the fix).
//   - Idempotency (forward re-run, or forward + the async full backstop both emitting
//     the SAME object's tuples) is guaranteed downstream: UpsertMember is an UPSERT,
//     RecordEmittedTuples is INSERT … ON CONFLICT, the fga_outbox drain treats
//     already_exists as applied, and the post-commit sync FGA writer reconciles by
//     read-then-write-delta. An object materialized twice is a safe no-op.
//
// LOCK CHOICE — SHARE, not "no lock" (db-architect-review, empirically forced). A pure
// no-lock forward DEADLOCKS against a concurrent FULL ReconcileObject of the same
// binding (observed 40P01): the full path holds `SELECT … FOR UPDATE` on the
// access_bindings row, while the forward path's INSERT into the FK-child tables
// (access_binding_target_members / access_binding_emitted_tuples) needs a FOR KEY SHARE
// lock on that SAME parent row — FOR UPDATE conflicts with FOR KEY SHARE, so the two
// passes cross-wait. The forward path therefore takes the SHARE advisory lock
// (AcquireBindingLockShared) FIRST:
//
//   - SHARE ∥ SHARE do NOT conflict → concurrent forwards of the same binding still run
//     fully in parallel (the throughput property is preserved — forwards never serialize
//     on each other, unlike the EXCLUSIVE full path).
//   - SHARE conflicts with the EXCLUSIVE full-path lock → a forward and a full pass of
//     the SAME binding take turns, so their row-locks never cross → no deadlock, and the
//     full recompute never runs its delete-stale diff while a forward mid-writes.
//   - Acquired in ASCENDING binding-id order (the fan-out is dedupSortBindingIDs-sorted,
//     matching the full path) → no ABBA across multiple shared bindings (ordered locking).
//
// NOTE (bounded, not a hang): PostgreSQL grants a fresh SHARE advisory even with an
// EXCLUSIVE waiter queued, so a sustained burst of overlapping forwards on one binding can
// DELAY that binding's async FULL recompute (the EXCLUSIVE waiter). This is throughput-
// only, never a deadlock or lost update: the full path is the eventual backstop (sweep +
// re-delivered reconcile events), registration bursts are bounded, and each forward pass
// is short. It is the deliberate trade — forward latency is the create-path SLO; the full
// recompute is background.
//
// CORRECTNESS ENVELOPE. Forward is an OPTIMIZATION of the happy path, not a replacement:
// the co-committed resource_reconcile_outbox event + the async worker's FULL
// ReconcileObject + the periodic sweep REMAIN the at-least-once backstop. They cover
// everything forward deliberately does NOT: delete-stale (object removed / label flipped
// off), REJECTED-containment audit, PENDING re-verify, and any binding the fast-path
// index missed. A skipped or failed forward pass is re-converged by the async full path
// — so the forward path carries a LOW correctness risk. Additionally, because forward
// only materializes an object ALREADY in the mirror (GetMirrorObject succeeded), a
// concurrent full recompute's desired set (read from the same mirror) ALSO contains that
// object → the full pass never treats it as stale. The integration Race case pins this
// (R survives a concurrent full recompute; no deadlock under the SHARE lock).

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ReconcileObjectForward is the ADDITIVE forward fast-path used by the register
// create-path (RegisterResource syncReconcile): it materializes ONLY the freshly-
// registered object's per-object tuples for each binding whose selector NOW matches it,
// holding only a SHARE advisory lock (never the EXCLUSIVE full-path lock) and no FOR
// UPDATE row-lock, and doing NO full O(scope) desired recompute (see the file-level doc
// for the lock choice and why it is the throughput fix).
//
// The full ReconcileObject REMAINS the backstop (delete-stale / audit / PENDING /
// sweep), driven by the co-committed reconcile-outbox event; forward is purely the
// happy-path accelerator.
//
// DELETE-STALE GUARD (create-only). RegisterResource is called on a label UPDATE as well
// as a create, and the additive forward CANNOT revoke a now-unmatched grant (it never
// deletes). So this method is additive ONLY for a brand-NEW object (no materialized
// members); a RE-REGISTER / label-update (the object ALREADY has members) transparently
// delegates to the FULL ReconcileObject, whose delete-stale diff synchronously revokes the
// stale grant. Without this, removing a grant-matching label leaves a standing grant (the
// T31 label-revoke `post-revoke-deny` regression). The create hot-path (new resources
// under load) has no prior members → stays on the fast additive path (throughput intact).
//
// iam-direct objects (iam.project / iam.account / iam content) are NOT registered over
// the cross-service RegisterResource edge, so the forward path is a mirror-fed concern.
// If ever called for an iam-direct type it transparently delegates to the full path
// (correctness over speed — that path is low-volume and needs the iam-direct feed +
// delete-stale semantics the forward path intentionally omits).
func (r *Reconciler) ReconcileObjectForward(ctx context.Context, objectType, objectID string) error {
	if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
		return r.ReconcileObject(ctx, objectType, objectID)
	}
	col := &syncFGACollector{}
	// needsFull is set inside the peek below when the object already has materialized
	// members (a RE-REGISTER / label-UPDATE), which requires the FULL delete-stale diff
	// that the additive forward path deliberately omits (see the DELETE-STALE GUARD note).
	needsFull := false
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		// DELETE-STALE GUARD (regression fix — T31 label-revoke `post-revoke-deny`). The
		// additive forward path only ADDS the object's tuples; it NEVER revokes. That is
		// correct ONLY for a brand-NEW object (a create — nothing stale to remove). But
		// RegisterResource is ALSO called on a label UPDATE, and removing a grant-matching
		// label must REVOKE the now-unmatched grant — a DELETE-STALE the forward path
		// cannot do. Discriminate by whether the object ALREADY has materialized members:
		//   - none  ⇒ create ⇒ fast additive forward (the throughput hot-path);
		//   - some  ⇒ re-register/update ⇒ bail to the FULL ReconcileObject (delete-stale).
		// The check is one indexed read (target_members by object); on the create hot-path
		// it is empty, so the extra cost is a single cheap SELECT in the same forward tx.
		existing, err := s.BindingsForObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("forward: bindings for object %s:%s: %w", objectType, objectID, err)
		}
		if len(existing) > 0 {
			needsFull = true
			return nil // commit the read-only peek; run the FULL path below (fresh tx).
		}
		// The registered object, with its containment parents (parent_project_id +
		// the account resolved through the project→account join) and labels — the
		// SAME same-DB projection the full path's IsContainedIn / arm match consume.
		obj, ok, err := s.GetMirrorObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("forward: get mirror object %s:%s: %w", objectType, objectID, err)
		}
		if !ok {
			// Not (yet) in the mirror — nothing to materialize on the fast-path. The
			// register writer-tx UPSERTs the mirror row BEFORE this post-commit call, so
			// in the create-path this is present; a stray call (mirror not landed / raced
			// delete) simply defers to the async backstop.
			return nil
		}
		// Scope-narrowed candidate bindings whose selector matches this object,
		// INCLUDING bindings with no member row yet (the brand-new-object case). This is
		// the SAME bounded fast-path source the full ReconcileObject uses; its ANCHOR arm
		// is already pushed-down to the containing bindings (owner + project-admin), so the
		// forward fan-out is O(containing bindings), not O(all bindings of the type).
		matching, err := s.SelectorBindingsMatchingObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("forward: selector bindings matching object %s:%s: %w", objectType, objectID, err)
		}
		for _, bID := range dedupSortBindingIDs(matching) {
			if err := r.forwardObjectForBinding(ctx, s, bID, obj, col); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Re-register / label-update: the object already had members, so the additive fast-path
	// is unsafe (it cannot delete-stale). Run the FULL ReconcileObject (its own tx, EXCLUSIVE
	// lock + delete-stale diff) so a now-unmatched grant is synchronously revoked. This keeps
	// the create hot-path on the fast additive path while restoring correct revoke-on-update.
	if needsFull {
		return r.ReconcileObject(ctx, objectType, objectID)
	}
	// AFTER commit only (a rollback returns early): apply the collected tuples to
	// OpenFGA synchronously (idempotent read-delta), so the creator's per-object grant
	// is visible without waiting for the async fga_outbox drain — the whole point of the
	// fast-path. Best-effort: an error degrades to the durable async drainer.
	r.applyAfterCommit(ctx, col)
	return nil
}

// forwardObjectForBinding materializes the ONE object's ACTIVE per-object tuples for a
// single matching binding. It takes the SHARE advisory lock (NOT the EXCLUSIVE lock the
// full path takes) and NO FOR UPDATE row-lock (LoadBindingUnlocked): the pass is
// additive-only (see file-level doc). A binding that is gone / no longer ACTIVE / whose
// (scope-aware) selectors do not match this object is a no-op. Non-ACTIVE per-object
// verdicts (REJECTED containment) are LEFT to the async full backstop — the additive
// path never writes a non-grant.
func (r *Reconciler) forwardObjectForBinding(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, obj domain.MirrorObject, col *syncFGACollector) error {
	// SHARE advisory lock FIRST (acquired in the ascending binding-id order the caller
	// sorts the fan-out into). SHARE coexists with other forwards (throughput) but
	// excludes a concurrent FULL recompute of the SAME binding — so the forward's FK
	// `FOR KEY SHARE` child INSERTs never cross the full path's `SELECT … FOR UPDATE` on
	// the parent access_bindings row (which would deadlock, 40P01).
	if err := s.AcquireBindingLockShared(ctx, bindingID); err != nil {
		return fmt.Errorf("forward: shared lock binding %s: %w", bindingID, err)
	}
	bs, ok, err := s.LoadBindingUnlocked(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("forward: load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		return nil // deleted / not ACTIVE — nothing to materialize.
	}
	subject := domain.FGASubjectRef(bs.SubjectType, bs.SubjectID)
	for _, sel := range bs.Selectors {
		// Match this ONE object against the selector's arm (scope-aware projection). A
		// cluster `*.*` binding carries selectors with EMPTY ObjectTypes (the D-9 flat
		// short-circuit owns cluster super-admin), so selectorMatchesObject returns false
		// → no per-object materialization on cluster (short-circuit preserved).
		if !selectorMatchesObject(sel, obj) {
			continue
		}
		// SHARED per-object verdict with the full recompute (byte-identical tuples).
		dm, ok := desiredMemberForObject(subject, sel, obj, bs.Scope)
		if !ok || dm.Status != domain.VerificationActive {
			// unknown FGA type (skip) OR a REJECTED containment verdict: the additive
			// forward path materializes only ACTIVE grants; the async full backstop owns
			// the REJECTED member row + containment audit.
			continue
		}
		if err := r.materializeForwardMember(ctx, s, bs, dm, col); err != nil {
			return err
		}
	}
	return nil
}

// materializeForwardMember writes ONE ACTIVE per-object member additively: UPSERT the
// member row, enqueue the per-object FGA tuple-write into fga_outbox, collect it for the
// post-commit sync OpenFGA write, and co-commit it into the emitted-tuple ledger — all
// in the caller's writer-tx (ban #10). Every step is idempotent, so a re-run (forward
// retry) or the async full backstop emitting the SAME tuples is a safe no-op.
func (r *Reconciler) materializeForwardMember(ctx context.Context, s ReconcileStore, bs BindingScope, dm DesiredMember, col *syncFGACollector) error {
	if err := s.UpsertMember(ctx, domain.TargetMember{
		BindingID: bs.BindingID, RoleID: domain.RoleID(bs.RoleID), RuleFP: dm.RuleFP,
		ObjectType: dm.ObjectType, ObjectID: dm.ObjectID, VerificationStatus: domain.VerificationActive,
	}); err != nil {
		return fmt.Errorf("forward: upsert member %s/%s:%s: %w", dm.RuleFP, dm.ObjectType, dm.ObjectID, err)
	}
	if err := s.EmitTupleWrite(ctx, dm.Tuples); err != nil {
		return fmt.Errorf("forward: emit tuple write %s:%s: %w", dm.ObjectType, dm.ObjectID, err)
	}
	// Collect for the post-commit synchronous OpenFGA write (read-after-write closer);
	// no-op when sync-FGA is unwired.
	col.collect(dm.Tuples)
	// Co-commit the emitted member-tuple into the ledger — the symmetric revoke +
	// Role.Update reconcile both rest on it (ban #10). The INSERT is
	// `ON CONFLICT (binding_id,fga_user,relation,object) DO UPDATE SET source='member'`
	// (idempotent — a re-emit / async-full-backstop overlap re-tags at most, never dups).
	if err := s.RecordEmittedTuples(ctx, bs.BindingID, dm.Tuples); err != nil {
		return fmt.Errorf("forward: record emitted tuple %s:%s: %w", dm.ObjectType, dm.ObjectID, err)
	}
	return nil
}

// selectorMatchesObject reports whether ONE materializing selector matches ONE object
// per its arm — the pure-Go mirror of the SQL predicate in
// SelectorBindingsMatchingObject, so the forward fast-path picks EXACTLY the same
// selector→object matches the fan-out query found (no drift):
//
//   - the object's dotted type must be in the selector's ObjectTypes (empty ⇒ no match,
//     which is the cluster `*.*` short-circuit — cluster super-admin is not per-object);
//   - ARM_NAMES  → the object id must be in ResourceNames;
//   - ARM_LABELS → the object labels must satisfy MatchLabels (labels @> matchLabels);
//   - ARM_ANCHOR → type membership is sufficient (containment is re-verified separately
//     by desiredMemberForObject → IsContainedIn).
func selectorMatchesObject(sel domain.RuleSelector, o domain.MirrorObject) bool {
	if !containsStringForward(sel.ObjectTypes, o.ObjectType) {
		return false
	}
	switch sel.Arm {
	case domain.ArmNames:
		return containsStringForward(sel.ResourceNames, o.ObjectID)
	case domain.ArmLabels:
		return o.MatchesLabels(sel.MatchLabels)
	default: // ArmAnchor
		return true
	}
}

// containsStringForward reports set membership (small closed lists — linear scan).
func containsStringForward(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
