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

// ReconcileBindingForward is the ADDITIVE forward fast-path used by the AccessBinding
// create-path (post-commit membership materialization, sub-phase IAM-FMB). It is the
// binding-side twin of ReconcileObjectForward: where the object-forward materializes ONE
// freshly-registered object across every matching binding, this materializes ONE freshly-
// CREATED binding's desired ACTIVE per-object members across the whole scope — holding only
// a SHARE advisory lock (never the EXCLUSIVE full-path lock) and no FOR UPDATE row-lock, and
// doing NO delete-stale diff.
//
// WHY IT IS THE THROUGHPUT FIX. The create-path previously ran the FULL EXCLUSIVE
// ReconcileBinding post-commit: it takes the per-binding EXCLUSIVE advisory lock + a
// `SELECT … FOR UPDATE` on the binding row and does an O(scope) desired recompute WITH a
// delete-stale diff (CurrentMembers read + cross-binding surviving-claims flush). That
// EXCLUSIVE lock + delete-stale exist ONLY for the Role.Update fan-out / sweep, where a
// concurrent re-materialization of the SAME binding must not race its own delete-stale. On
// a mass-binding-create burst (a role grant-wave over an account / many subjects) those
// serial O(scope) delete-stale recomputes do not keep up → grant materialization lags past
// the client read-your-writes retry budget (transient 403 «lacks relation» on one's OWN
// fresh grant). A create is PURELY additive — the binding is brand-new, so there is NOTHING
// stale to delete — so the create-forward drops the delete-stale diff, the FOR UPDATE
// row-lock, and the EXCLUSIVE advisory lock, taking only the SHARE lock.
//
// LOCK CHOICE — SHARE, not "no lock" (same rationale as ReconcileObjectForward, see the
// file-level doc): SHARE ∥ SHARE do not conflict → N concurrent create-forwards never
// serialize on each other (the throughput property), while SHARE ⊥ EXCLUSIVE → a create-
// forward and a concurrent FULL pass of the SAME binding (Role.Update fan-out / sweep) take
// turns, so the forward's FK-child `FOR KEY SHARE` INSERTs never cross the full path's
// `SELECT … FOR UPDATE` on the parent access_bindings row (which would deadlock, 40P01),
// and the full recompute never runs its delete-stale diff while a forward mid-writes.
//
// DELETE-STALE GUARD (create-only, D-4). The additive path only ADDS the binding's desired
// ACTIVE members; it NEVER delete-stale. That is correct ONLY for a brand-NEW binding (a
// create — no materialized members yet). A call on a binding that ALREADY has materialized
// members (a replay create / a call on an existing binding) transparently delegates to the
// FULL ReconcileBinding (EXCLUSIVE + delete-stale) so a now-unmatched grant is revoked. The
// check is one indexed read (CurrentMembers); on the create hot-path it is empty → the pass
// stays on the fast additive path (throughput intact).
//
// CORRECTNESS ENVELOPE (D-5). Forward is an OPTIMIZATION, not a replacement: the per-object
// member-tuples are DURABLE in fga_outbox inside the forward writer-tx (ban #10) → the async
// drainer applies them at-least-once even if the post-commit sync FGA write fails; the
// periodic sweep (FULL ReconcileBinding) re-converges any member forward skipped. A
// skipped/failed forward converges via (drainer + sweep). Operation.done does NOT wait for
// tuple visibility (ban #9). The per-object verdict is SHARED with the full recompute
// (desiredMemberForObject via desiredMembers), so the two paths derive BYTE-IDENTICAL tuples
// (no over-/under-grant; idempotent forward + async-backstop overlap).
func (r *Reconciler) ReconcileBindingForward(ctx context.Context, bindingID domain.AccessBindingID) error {
	col := &syncFGACollector{}
	// needsFull is set inside the peek below when the binding already has materialized
	// members (a replay create / a call on an existing binding), which requires the FULL
	// delete-stale diff the additive forward path deliberately omits (DELETE-STALE GUARD).
	needsFull := false
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		// DELETE-STALE GUARD (create-only). Discriminate a true create (no members) from a
		// replay / existing-binding call (has members) by ONE indexed read. On the create
		// hot-path this is empty, so the extra cost is a single cheap SELECT in the same
		// forward tx.
		existing, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("forward binding: current members %s: %w", bindingID, err)
		}
		if len(existing) > 0 {
			needsFull = true
			return nil // commit the read-only peek; run the FULL path below (fresh tx).
		}
		// SHARE advisory lock FIRST (never the EXCLUSIVE full-path lock). SHARE coexists with
		// sibling create-forwards (throughput) but excludes a concurrent FULL recompute of
		// the SAME binding — so the forward's FK `FOR KEY SHARE` child INSERTs never cross
		// the full path's `SELECT … FOR UPDATE` on the parent access_bindings row (40P01).
		if err := s.AcquireBindingLockShared(ctx, bindingID); err != nil {
			return fmt.Errorf("forward binding: shared lock %s: %w", bindingID, err)
		}
		bs, ok, err := s.LoadBindingUnlocked(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("forward binding: load %s: %w", bindingID, err)
		}
		if !ok || !bs.Active {
			return nil // deleted / not ACTIVE — nothing to materialize.
		}
		// The binding's desired member set — SHARED with the FULL recompute
		// (desiredMembers → desiredRuleMembers → desiredMemberForObject), so the forward and
		// full paths derive BYTE-IDENTICAL tuples (equivalence; idempotency across overlap).
		desired, err := r.desiredMembers(ctx, s, bs)
		if err != nil {
			return err
		}
		for _, d := range desired {
			// Additive-only: materialize ONLY ACTIVE grants. A REJECTED containment verdict
			// (cross-scope) — and its containment audit — is LEFT to the async FULL backstop
			// (the additive path never writes a non-grant).
			if d.Status != domain.VerificationActive {
				continue
			}
			if err := r.materializeForwardMember(ctx, s, bs, d, col); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Replay / existing-binding call: the additive fast-path is unsafe (it cannot delete-
	// stale). Run the FULL ReconcileBinding (its own tx, EXCLUSIVE lock + delete-stale diff)
	// so a now-unmatched grant is synchronously revoked. Keeps the create hot-path additive.
	if needsFull {
		return r.ReconcileBinding(ctx, bindingID)
	}
	// AFTER commit only (a rollback returns early): apply the collected tuples to OpenFGA
	// synchronously (idempotent read-delta), so the subject's per-object grant is visible
	// without waiting for the async fga_outbox drain — the point of the fast-path. Best-
	// effort: an error degrades to the durable async drainer (D-5 backstop).
	r.applyAfterCommit(ctx, col)
	return nil
}

// ReconcileObjectForward is the ADDITIVE forward fast-path WITH the delete-stale guard
// (the entry point for a caller that cannot prove the object carries nothing stale — a
// re-registration that replaced the projection, and every withdrawal). It materializes ONLY the freshly-
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
// iam-direct objects (iam.project / iam.account + iam content) are NOT registered over
// the cross-service RegisterResource edge — they arrive on the iam-native create-path
// (Project/AccessBinding/Role/... Create emits a reconcile event for its OWN object).
// The forward path is iam-direct-AWARE (sub-phase IAM-FMB, throughput fix for the
// iam.accessBinding / iam.project owner materialization): a brand-NEW iam-direct object
// is materialized ADDITIVELY (SHARE lock, single-object) EXACTLY like a mirror-fed one,
// reading its own-table projection (GetIAMDirectObject) and the matching bindings from
// the iam-direct fan-out (IAMDirectSelectorBindingsMatchingObject). Before this the
// create-path used the FULL EXCLUSIVE ReconcileObject, whose per-binding advisory lock +
// O(scope) recompute serialized on the SINGLE owner/account binding every resource of an
// account shares → owner-tuple materialization lag past the client read-your-writes retry
// budget (transient 403 on one's OWN fresh grant). The per-object verdict / tuple emission
// (forwardObjectForBinding → desiredMemberForObject → ruleObjectTuples) is FEED-AGNOSTIC and
// SHARED with the FULL path, so the two derive BYTE-IDENTICAL tuples (no over-/under-grant).
//
// The full ReconcileObject REMAINS the async at-least-once backstop for BOTH feeds
// (delete-stale / REJECTED-containment audit / PENDING / sweep), driven by the co-committed
// reconcile-outbox event; forward is purely the happy-path accelerator.
func (r *Reconciler) ReconcileObjectForward(ctx context.Context, objectType, objectID string) error {
	return r.reconcileObjectForward(ctx, objectType, objectID, false /* not proven — keep the delete-stale guard */)
}

// ReconcileObjectForwardNoStale is ReconcileObjectForward for an object whose caller can
// PROVE that nothing materialized on it can have gone stale. It is the SAME pass in every
// other respect (same object projection, same fan-out, same per-object verdict, same
// additive materialization, same async backstop); the ONLY difference is that the
// delete-stale guard below is skipped.
//
// TWO ADMISSIBLE PROOFS, BOTH ESTABLISHED BY THE CALLER'S OWN DATABASE — never by a flag
// on an incoming request:
//
//  1. THE ID IS BRAND-NEW: it was minted in the caller's writer-tx and that tx has just
//     committed, so the object never existed before this call (AccessBinding.Create).
//  2. THE REGISTRATION REPLACED NOTHING: the object's stored projection — parent-scope and
//     labels, the only things a selector reads — was already byte-identical to the one
//     just written, and only its source_version advanced (the cross-service
//     RegisterResource path, where the mirror UPSERT decides this in SQL).
//
// A member can only become stale when the facts that justified it change. Under (1) there
// are no earlier facts at all; under (2) the facts this pass re-derives are the same ones
// the earlier delivery derived, so the desired set it computes is the same set — an
// additive pass over it removes nothing because there is nothing to remove.
//
// WHY IT IS NEEDED (create-path starvation, measured against the Read API). Members can
// exist on the object before this pass runs — either written seconds earlier by the same
// create, or written by the FIRST of the two deliveries every consumer performs. The
// guard then finds a non-empty member set and routes the object to the FULL EXCLUSIVE
// ReconcileObject. Since every object of an account shares the single account-admin
// binding, those full passes queue on one advisory lock, and the account-admin's
// per-object verbs arrived ~67s after the create — far past a client's read-your-writes
// budget. Reordering the passes only moves the starvation; what the guard needs is the
// fact only the caller holds.
//
// WHAT IT DOES NOT LICENSE. The guard exists so a RE-REGISTER / label-UPDATE revokes a
// now-unmatched grant (delete-stale, the T31 label-revoke regression). A registration
// that REPLACED a different projection — a label flipped off, a move to another parent —
// is exactly that case and must NOT come through here: an additive pass on it would add
// the new grants and leave the old ones standing, i.e. an UNAPPLIED REVOKE. Neither may
// a withdrawal: stripping an object's tuples IS the full pass's delete-stale diff.
//
// The FULL ReconcileObject remains the at-least-once backstop (co-committed reconcile
// event + sweep) for delete-stale, REJECTED-containment audit and PENDING re-verify,
// exactly as for the ordinary forward. It does NOT gate Operation.done on tuple
// visibility (ban #9): materialization stays eventually-consistent, this only keeps it
// on the fast path.
func (r *Reconciler) ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error {
	return r.reconcileObjectForward(ctx, objectType, objectID, true /* proven — nothing stale can exist */)
}

// reconcileObjectForward is the shared implementation of the two entry points above;
// noStale lifts the delete-stale guard (see ReconcileObjectForwardNoStale).
func (r *Reconciler) reconcileObjectForward(ctx context.Context, objectType, objectID string, noStale bool) error {
	// Feed classifier: an iam.* object lives in ITS OWN table (iam-direct, never PENDING);
	// every other selectable family (compute/vpc/loadbalancer/...) is mirror-fed. The
	// object getter + the fast-path fan-out differ per feed; everything else is shared.
	iamDirect := domain.FeedSourceForType(objectType) == domain.FeedIAMDirect
	col := &syncFGACollector{}
	// needsFull is set inside the peek below when the object already has materialized
	// members (a RE-REGISTER / label-UPDATE), which requires the FULL delete-stale diff
	// that the additive forward path deliberately omits (see the DELETE-STALE GUARD note).
	needsFull := false
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		// DELETE-STALE GUARD (regression fix — T31 label-revoke `post-revoke-deny`). The
		// additive forward path only ADDS the object's tuples; it NEVER revokes. That is
		// correct ONLY for a brand-NEW object (a create — nothing stale to remove). But the
		// object may ALSO be re-materialized on a label UPDATE (mirror-fed RegisterResource
		// re-call OR iam-direct Project/AccessBinding.Update label change), and removing a
		// grant-matching label must REVOKE the now-unmatched grant — a DELETE-STALE the
		// forward path cannot do. Discriminate by whether the object ALREADY has materialized
		// members (feed-agnostic — members are keyed by object regardless of feed):
		//   - none  ⇒ create ⇒ fast additive forward (the throughput hot-path);
		//   - some  ⇒ re-register/update ⇒ bail to the FULL ReconcileObject (delete-stale).
		// The check is one indexed read (target_members by object); on the create hot-path
		// it is empty, so the extra cost is a single cheap SELECT in the same forward tx.
		//
		// SKIPPED when the caller PROVED nothing stale can exist (ReconcileObjectForwardNoStale):
		// either the id never existed before, or the registration replaced nothing — see the
		// two admissible proofs in that method's doc. The members such an object DOES carry
		// were written by the same create, or by the first of the two deliveries of the very
		// same registration; reading them would bounce the hot path onto the FULL EXCLUSIVE
		// recompute it is trying to avoid. The query is skipped rather than its result
		// ignored: it is a pure cost then.
		if !noStale {
			existing, err := s.BindingsForObject(ctx, objectType, objectID)
			if err != nil {
				return fmt.Errorf("forward: bindings for object %s:%s: %w", objectType, objectID, err)
			}
			if len(existing) > 0 {
				needsFull = true
				return nil // commit the read-only peek; run the FULL path below (fresh tx).
			}
		}
		// The registered object's same-DB projection — containment parents (parent_project_id
		// + the account resolved through the project→account join) and labels — the SAME
		// projection the full path's IsContainedIn / arm match consume. Read from the mirror
		// (consumer-owned feed) or the iam-native own table (iam-direct feed).
		var (
			obj domain.MirrorObject
			ok  bool
			err error
		)
		if iamDirect {
			obj, ok, err = s.GetIAMDirectObject(ctx, objectType, objectID)
		} else {
			obj, ok, err = s.GetMirrorObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("forward: get object %s:%s: %w", objectType, objectID, err)
		}
		if !ok {
			// Not (yet) present in its source (mirror not landed / iam row raced a delete) —
			// nothing to materialize on the fast-path. The register / create writer-tx lands
			// the source row BEFORE this post-commit call, so in the create-path this is
			// present; a stray call simply defers to the async backstop.
			return nil
		}
		// Candidate bindings whose selector matches this object, INCLUDING bindings with no
		// member row yet (the brand-new-object case). This is the SAME fast-path source the
		// full ReconcileObject uses (feed-agnostic verdict downstream). NOTE (doc-truthfulness,
		// db-review finding A): the two feeds narrow scope differently — the MIRROR-fed
		// SelectorBindingsMatchingObject pushes the containment predicate (b.resource_id =
		// parent_account) into the JOIN, so its ANCHOR arm is O(containing bindings); the
		// IAM-DIRECT IAMDirectSelectorBindingsMatchingObject anchor arm is currently
		// UN-narrowed (matches every active anchor binding of the type system-wide), so its
		// fan-out is O(anchor bindings of the type across all accounts). Correctness is
		// unaffected — the per-binding IsContainedIn re-verify (ruleObjectTuples path) is
		// authoritative and rejects foreign-scope candidates (unit ForeignScope + integration
		// scope-boundary test) — but it is an O(N-accounts) hot-path cost at tenant scale.
		// This is PRE-EXISTING (the full ReconcileObject uses the same fan-out), not a
		// regression of this fast-path; pushing the containment predicate into the iam-direct
		// anchor arm (mirroring the mirror-fed branch) is a tracked follow-up optimization.
		var matching []domain.AccessBindingID
		if iamDirect {
			matching, err = s.IAMDirectSelectorBindingsMatchingObject(ctx, objectType, objectID)
		} else {
			matching, err = s.SelectorBindingsMatchingObject(ctx, objectType, objectID)
		}
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
	// The object's desired members under this binding — derived by the SHARED
	// desiredMembersForObject (per-object target least-priv, arm match, containment
	// verdict, scope-self anchor), so the forward fast-path, the object-narrowed full
	// pass and the whole-scope recompute all derive BYTE-IDENTICAL tuples. A cluster
	// `*.*` binding carries selectors with EMPTY ObjectTypes (the D-9 flat short-circuit
	// owns cluster super-admin), so nothing matches → no per-object materialization on
	// cluster (short-circuit preserved).
	for _, dm := range desiredMembersForObject(bs, obj) {
		if dm.Status != domain.VerificationActive {
			// A REJECTED containment verdict: the additive forward path materializes only
			// ACTIVE grants; the async full backstop owns the REJECTED member row +
			// containment audit.
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
	// Enqueue ONLY the tuples this pass has not already enqueued, and collect the same set
	// for the post-commit synchronous OpenFGA write (read-after-write closer). Per-pass
	// de-dup — never across passes, so a re-grant after a revoke is always re-emitted.
	if fresh := col.collectNew(dm.Tuples); len(fresh) > 0 {
		if err := s.EmitTupleWrite(ctx, fresh); err != nil {
			return fmt.Errorf("forward: emit tuple write %s:%s: %w", dm.ObjectType, dm.ObjectID, err)
		}
	}
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
