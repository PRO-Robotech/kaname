// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// page_memo.go — the structural facts of ONE page, warmed once and read per object.
//
// # WHY, AND WHY IT IS NOT A CACHE
//
// Measured (page_cost_integration_test.go), a page of 100 denied objects cost 200
// primary transactions and 1000 statements when every per-object question derived its
// own facts: the page filter asks two relations per object, so the same row was read
// twice, and every object re-read the ancestors it shares with the rest of the page. Page
// size is part of the contract up to 1000 and narrowing it to fit a budget is forbidden,
// so the cost had to stop growing with the page.
//
// This is deliberately NOT a cache, and the difference is the safety argument. A cache
// would answer a question in a LATER request from a row read in an earlier one, and one
// of the pointers involved is mutable: a project can move between accounts, and a stale
// pointer would keep the old account's administrator in authority over rows that are no
// longer his — an over-grant, on a window nobody configured. This memo lives in the
// request context, is written once by the prefetch that created it, and dies with the
// request. Nothing invalidates it because nothing outlives the call that filled it.
//
// # WHAT THE MEMO CHANGES ABOUT THE QUESTION ASKED
//
// When the facts for an object are already known, they are attached to the FIRST
// relation question instead of being used to re-ask a denied one. That is not a shortcut:
// a contextual tuple can only ADD a resolution path, so the single question carrying true
// facts has exactly the answer the two-question form had, and the page stops paying a
// second round-trip per object. Without a memo the lazy form stands, which is the right
// shape for a gate about one object — there an ALLOWED caller must not pay a read at all.
package authzcascade

import (
	"context"
	"sync"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// factMemo — derived facts keyed by "<type>:<id>".
//
// PRESENCE is meaningful and absence is not the same as emptiness: a key present with an
// empty slice means "read, and the row has nothing structural to say", which must not be
// re-read; a key absent means "not known", which the lazy path resolves. Conflating them
// would either re-read every rowless id or invent facts for one.
type factMemo struct {
	mu sync.RWMutex
	m  map[string][]authztypes.TupleKey
}

type factMemoKey struct{}

// WithFactMemo returns a context carrying an EMPTY memo, or the same context if it
// already carries one. Idempotent so nested prefetches (a page filter inside a use-case
// that already prefetched) share one memo instead of shadowing it.
func WithFactMemo(ctx context.Context) context.Context {
	if factMemoFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, factMemoKey{}, &factMemo{m: map[string][]authztypes.TupleKey{}})
}

func factMemoFrom(ctx context.Context) *factMemo {
	m, _ := ctx.Value(factMemoKey{}).(*factMemo)
	return m
}

func (m *factMemo) get(key string) ([]authztypes.TupleKey, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.m[key]
	return f, ok
}

func (m *factMemo) put(key string, facts []authztypes.TupleKey) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if facts == nil {
		facts = []authztypes.TupleKey{}
	}
	m.m[key] = facts
}

// BatchFactSource — the OPTIONAL batch capability of a FactSource: the facts of many
// objects of one type, on one snapshot, at a cost that does not grow with the count.
//
// BatchReachable is part of the port, not a convenience. Without it the capability is
// indistinguishable from a batch that ran and found nothing: *Resolver has the method
// whether or not a batch source is wired, and the "nothing claimed" answer of an unwired
// one is the same (nil, nil) a real read of absent rows returns. The measurement caught
// exactly that — a prefetch believed an unwired batch, recorded every id as having no
// facts, and silently turned the whole page back into the pre-fix behaviour while looking
// like the fixed one.
type BatchFactSource interface {
	// BatchReachable reports whether a batch read can actually be performed. A false
	// answer means the caller must not read anything into the result of a call.
	BatchReachable() bool
	StructuralFactsBatch(ctx context.Context, objectType string, ids []string) (map[string][]authztypes.TupleKey, error)
}

// PrefetchStructural warms the facts for a whole page and returns the context the
// per-object questions must be asked with. Callers that hold a page of ids of ONE object
// type (the read filters) call it once; everyone else does not have to know it exists.
//
// It is best-effort BY DESIGN and that is safe: on any failure it returns the context
// unchanged, and every per-object question then resolves its own facts exactly as it
// would have. A failure therefore costs speed and never an answer — in particular a
// database that cannot be read still produces the fail-closed error from the per-object
// path rather than a silent denial here.
//
// The one thing it must not do is record a fact it did not read. Only ids the batch
// actually returned are memoised — an id it did not return is left UNKNOWN, so the
// per-object path resolves it and cannot be handed an emptiness nobody established. This
// is not defensive: the first version of this function recorded absent ids as "no facts",
// and against a batch that was not wired at all it recorded that for the entire page,
// which reinstated the defect while every structural test stayed green.
func (c *Client) PrefetchStructural(ctx context.Context, objectType string, ids []string) context.Context {
	if c == nil || c.facts == nil || len(ids) == 0 || !c.facts.Derivable(objectType) {
		return ctx
	}
	batch, ok := c.facts.(BatchFactSource)
	if !ok || !batch.BatchReachable() {
		return ctx
	}
	got, err := batch.StructuralFactsBatch(ctx, objectType, ids)
	if err != nil || len(got) == 0 {
		return ctx
	}
	ctx = WithFactMemo(ctx)
	m := factMemoFrom(ctx)
	for id, facts := range got {
		m.put(objectType+":"+id, facts)
	}
	return ctx
}

// memoFacts reports the facts already known for this object in this request.
func (c *Client) memoFacts(ctx context.Context, object string) ([]authztypes.TupleKey, bool) {
	return factMemoFrom(ctx).get(object)
}
