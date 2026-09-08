// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// revoke_set.go — the tuple-set a teardown (hard Delete / soft Revoke) may actually
// remove from the rights state.
//
// THE RULE. The emitted-tuple ledger (kaname.access_binding_emitted_tuples) is
// keyed PER BINDING (binding_id, fga_user, relation, object); the tuple itself is
// NOT refcounted. Two bindings of the SAME subject on the SAME scope with the same
// verbs therefore hold TWO ledger rows for ONE live tuple. Replaying a binding's own
// ledger set verbatim as deletions consequently removes access that ANOTHER, still
// ACTIVE binding grants — silent access-loss, and self-sustaining: the ledger is
// read as the mirror of that state, so no reconcile pass ever notices the divergence
// and re-writes the tuple. A tuple may be removed only when the LAST ACTIVE binding
// claiming it releases it.
//
// This is the same rule the reconciler already enforces internally for its per-member
// eager-revoke (reconcile.ReconcileStore.TuplesStillClaimedByOtherBindings); the
// binding-level teardown paths simply did not apply it.
//
// It is NOT a widening: every retained tuple is one an ACTIVE binding independently
// entitles the subject to — the subtraction never adds a tuple, and it never retains
// anything once the last claim is gone (the converse is regression-locked). It is
// also distinct from the deliberate anti-over-grant boundary on hierarchy scopes:
// that decides which tuples are ever EMITTED, this decides only whose ledger row is
// allowed to REMOVE an already-emitted one.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// partitionRevokeSet splits a binding's persisted emitted-set into the tuples this
// teardown removes and the ones another ACTIVE binding still claims.
//
// It runs on the caller's WRITER-tx, so the answer is consistent with the delete it
// guards: for the hard Delete the probe runs BEFORE the row (and, via FK CASCADE, its
// ledger rows) disappears; for the soft Revoke the row is already REVOKED, and either
// way `excludeBinding` is filtered out explicitly — a binding never keeps its own
// tuples alive.
//
// A probe failure is returned, NOT swallowed: the caller aborts the writer-tx, so the
// teardown fails LOUDLY (Operation.error → the administrator retries) instead of
// falling back to the verbatim replay that strips a live grant. The alternative
// failure direction — a silently over-broad revoke — is exactly the access-loss this
// function exists to prevent.
//
// Order of `stored` is preserved in `remove` (the emitted-set ↔ revoke-set symmetry
// the ledger round-trip rests on). len(stored)==0 ⇒ (nil, nil, nil), no query.
//
// RESIDUAL RACE, stated rather than hidden: two bindings claiming the SAME tuple that
// are torn down CONCURRENTLY can each still see the other's ledger row (neither tx has
// committed yet) and each retain the tuple, leaving it live with no claimant — a
// bounded over-grant instead of the deterministic access-loss this function removes.
// The window is one writer-tx wide and needs two teardowns of the same subject's
// overlapping grants at the same instant. It is NOT closed by locking the other
// binding's ledger rows (`FOR UPDATE` here would serialize unrelated revokes on shared
// rows and introduce a cross-binding lock-order cycle in a security-hot path), and it
// is the same property the reconciler's own cross-binding subtraction has
// (ReconcileStore.TuplesStillClaimedByOtherBindings). Closing it belongs with a
// reclaim pass over ledger-less tuples, not with a lock here.
func partitionRevokeSet(
	ctx context.Context,
	ab abrepo.ReaderIface,
	excludeBinding domain.AccessBindingID,
	stored []abrepo.RelationTuple,
) (remove, retained []abrepo.RelationTuple, err error) {
	if len(stored) == 0 {
		return nil, nil, nil
	}
	claimed, err := ab.SelectTuplesClaimedByOtherActiveBindings(ctx, excludeBinding, stored)
	if err != nil {
		return nil, nil, err
	}
	if len(claimed) == 0 {
		return stored, nil, nil
	}
	stillClaimed := make(map[abrepo.RelationTuple]struct{}, len(claimed))
	for _, t := range claimed {
		stillClaimed[t] = struct{}{}
	}
	remove = make([]abrepo.RelationTuple, 0, len(stored))
	for _, t := range stored {
		if _, keep := stillClaimed[t]; keep {
			retained = append(retained, t)
			continue
		}
		remove = append(remove, t)
	}
	return remove, retained, nil
}
