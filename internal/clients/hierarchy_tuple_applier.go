// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/outboxtypes"
)

// HierarchyTupleApplier adapts a RelationStore onto the neutral outbox tuple shape the
// resource-registration use-case speaks, so that use-case can apply the ONE tuple it owns
// — the object→project containment pointer, and the public wildcard grant — directly to
// the store right after its writer-tx commits.
//
// WHY THE USE-CASE NEEDS ITS OWN APPLIER. The reconciler materialises the per-object
// verbs and now applies BOTH of its directions synchronously, but it knows nothing about
// the containment pointer: nothing except the registration path writes it, so nothing
// except the registration path can take it away promptly. Left on the queue alone, the
// pointer outlives the resource, and the account administrator — whose reach runs THROUGH
// that pointer rather than through any per-object grant — keeps being answered ALLOW on
// something the product already reports as gone.
//
// The mapping is the whole of it: the durable fga_outbox row is still enqueued in the
// writer-tx, and RelationStore's two methods are idempotent at the set level, so the
// drainer re-applying the identical tuple afterwards is a no-op.
type HierarchyTupleApplier struct {
	relations RelationStore
}

// NewHierarchyTupleApplier builds the adapter. nil-safe: a nil store yields nil, so the
// composition root can pass an unconfigured store and the use-case falls back to the
// queue-only path rather than to a panic.
func NewHierarchyTupleApplier(relations RelationStore) *HierarchyTupleApplier {
	if relations == nil {
		return nil
	}
	return &HierarchyTupleApplier{relations: relations}
}

// WriteTuples applies the registration direction. Idempotent: a tuple the drainer already
// landed counts as applied.
func (a *HierarchyTupleApplier) WriteTuples(ctx context.Context, tuples []outboxtypes.RelationTuple) error {
	if a == nil || len(tuples) == 0 {
		return nil
	}
	return a.relations.WriteTuples(ctx, toRelationTuples(tuples))
}

// DeleteTuples applies the withdrawal direction. Idempotent at the SET level: its
// postcondition is that none of these tuples is in the store, so a tuple a racing drainer
// already removed counts as applied.
func (a *HierarchyTupleApplier) DeleteTuples(ctx context.Context, tuples []outboxtypes.RelationTuple) error {
	if a == nil || len(tuples) == 0 {
		return nil
	}
	return a.relations.DeleteTuples(ctx, toRelationTuples(tuples))
}

func toRelationTuples(in []outboxtypes.RelationTuple) []RelationTuple {
	out := make([]RelationTuple, 0, len(in))
	for _, t := range in {
		out = append(out, RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return out
}
