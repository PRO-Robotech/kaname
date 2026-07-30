// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// batch.go — the same walk StructuralFacts does, for many objects at once.
//
// The per-object walk (authzcascade.go) reads one object's row and then follows each
// derived pointer to its own row, on one snapshot, to a depth of at most the chain
// leaf → project → account → cluster. This does exactly that for a whole page: one
// snapshot, one statement per LEVEL per type instead of one transaction per object.
//
// It is a second READ path, not a second projection. Both paths call the same
// domain/structural_tuple.go functions, and batch_matches_per_object_integration_test.go
// asserts the two produce IDENTICAL facts for the same ids — so a divergence fails a test
// instead of quietly changing authorization answers on pages only.
package authzcascade

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// StructuralSnapshot — several structural reads on ONE state of the hierarchy. A chain
// read across separate snapshots can see a torn one (a leaf's project from before a move,
// that project's account from after it), and the facts would then describe a shape that
// never existed.
type StructuralSnapshot interface {
	// FactsByIDs — the facts of the named rows, keyed by object id. An id with no row is
	// ABSENT from the map; a row with nothing structural to say is present and empty.
	FactsByIDs(ctx context.Context, objectType string, ids []string) (map[string][]domain.StructuralTuple, error)
	// Close releases the snapshot. Called exactly once.
	Close(ctx context.Context)
}

// StructuralBatchSource opens those snapshots on the PRIMARY. Satisfied by
// *repo/kacho/pg.StructuralFactsRepo.
type StructuralBatchSource interface {
	StructuralSnapshot(ctx context.Context) (StructuralSnapshot, error)
}

// BatchSourceFunc adapts a concrete snapshot opener to StructuralBatchSource. The
// composition root is where the concrete repository is known, so that is where the
// adapting closure belongs — the alternative is the adapter naming this package, which
// would point the dependency the wrong way.
type BatchSourceFunc func(ctx context.Context) (StructuralSnapshot, error)

// StructuralSnapshot — StructuralBatchSource.
func (f BatchSourceFunc) StructuralSnapshot(ctx context.Context) (StructuralSnapshot, error) {
	return f(ctx)
}

// BatchReachable — BatchFactSource. See that port for why the capability has to be
// askable instead of inferred from the presence of the method.
func (r *Resolver) BatchReachable() bool { return r != nil && r.batch != nil }

// WithBatch wires the batch source, making the page prefetch possible. Without it the
// resolver still answers every question — one object at a time, which the cost
// measurement shows is the shape a page must not use.
func (r *Resolver) WithBatch(b StructuralBatchSource) *Resolver {
	r.batch = b
	return r
}

// StructuralFactsBatch returns the facts for each of `ids`, transitively closed exactly
// as StructuralFacts closes them for one object.
//
// Contract, deliberately the same three outcomes as the per-object form:
//   - no batch source wired, an underivable type, or no ids → (nil, nil); the caller's
//     per-object path stands.
//   - an id with no row → ABSENT from the result. The caller learns "iam knows nothing
//     about this id" from the absence, and must not read it as an error.
//   - a read failure → (nil, err). Not "no facts": the facts are part of a decision, and
//     an unread fact is an unknown answer rather than a negative one.
func (r *Resolver) StructuralFactsBatch(
	ctx context.Context, objectType string, ids []string,
) (map[string][]authztypes.TupleKey, error) {
	if r == nil || r.batch == nil || len(ids) == 0 || !r.Derivable(objectType) {
		return nil, nil
	}
	// The whole page shares ONE deadline, for the same reason a single read has one: this
	// sits on the request path of an authorization decision, so an unresponsive database
	// must cost a bounded wait and a fail-closed answer rather than a held goroutine. The
	// budget belongs to the page, not to each row of it.
	if r.readTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.batchTimeout())
		defer cancel()
	}
	snap, err := r.batch.StructuralSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("authzcascade batch snapshot: %w", err)
	}
	defer snap.Close(ctx)

	// factsOf["<type>:<id>"] — every row read, at every level.
	factsOf := map[string][]authztypes.TupleKey{}
	// requested — the ids that HAVE a row, so a miss stays distinguishable from a row
	// with nothing to say.
	requested := map[string]bool{}

	queue := map[string][]string{objectType: dedupe(ids)}
	for depth := 0; depth < maxChainDepth && len(queue) > 0; depth++ {
		next := map[string][]string{}
		for typ, tids := range queue {
			if !r.Derivable(typ) {
				continue
			}
			pending := make([]string, 0, len(tids))
			for _, id := range tids {
				if _, seen := factsOf[typ+":"+id]; !seen {
					pending = append(pending, id)
				}
			}
			if len(pending) == 0 {
				continue
			}
			got, gerr := snap.FactsByIDs(ctx, typ, pending)
			if gerr != nil {
				return nil, fmt.Errorf("authzcascade batch read %s: %w", typ, gerr)
			}
			for id, facts := range got {
				key := typ + ":" + id
				factsOf[key] = toConditional(facts)
				if depth == 0 {
					requested[id] = true
				}
				for _, f := range facts {
					if p, ok := parseObjectRef(f.User); ok {
						if _, seen := factsOf[p.Type+":"+p.ID]; !seen {
							next[p.Type] = append(next[p.Type], p.ID)
						}
					}
				}
			}
		}
		queue = next
	}

	out := make(map[string][]authztypes.TupleKey, len(requested))
	for id := range requested {
		out[id] = closeOver(factsOf, objectType, id)
	}
	return out, nil
}

// batchTimeout scales the page's budget with the number of LEVELS, not with the number of
// rows: the read cost of a level does not grow with the page, so a page of 1000 gets the
// same allowance as a page of 10. It is expressed as a multiple of the single-read budget
// so there is one knob rather than two that can drift apart.
func (r *Resolver) batchTimeout() time.Duration {
	return r.readTimeout * maxChainDepth
}

// closeOver walks the pointers already read and returns the transitive fact set for one
// object, in a deterministic order (the object's own facts first, then its ancestors'
// breadth-first). Determinism matters only for readable failures — the relation store is
// order-insensitive.
func closeOver(factsOf map[string][]authztypes.TupleKey, objectType, objectID string) []authztypes.TupleKey {
	var (
		out     []authztypes.TupleKey
		visited = map[string]bool{}
		queue   = []objectRef{{Type: objectType, ID: objectID}}
	)
	for depth := 0; depth < maxChainDepth && len(queue) > 0; depth++ {
		next := make([]objectRef, 0, len(queue))
		for _, ref := range queue {
			key := ref.Type + ":" + ref.ID
			if visited[key] {
				continue
			}
			visited[key] = true
			facts := factsOf[key]
			out = append(out, facts...)
			for _, f := range facts {
				if p, ok := parseObjectRef(f.User); ok && !visited[p.Type+":"+p.ID] {
					next = append(next, p)
				}
			}
		}
		queue = next
	}
	return out
}

func dedupe(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
