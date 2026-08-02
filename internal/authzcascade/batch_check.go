// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// batch_check.go — the batched relation question, decorated with the same
// structural second chance the per-object one carries.
//
// # Why this file has to exist
//
// Client embeds Relations, so every method it does not override is the transport's
// own. That is exactly what it wants for reads it does not decorate — and exactly
// what it must NOT have for a Check. When the batched question was added to
// clients.RelationQueries, the wrapper acquired it by promotion: the page filter
// asserted the capability, found it, and asked the STORE directly, with the
// wrapper's whole reason for existing sitting one frame away, untouched.
//
// The effect was not subtle and was not theoretical. A delegated account
// administrator's page went from all of his bindings to none of them: his
// authority is a grant on the account, the pointers that carry it down to each
// binding are read from committed rows and attached as contextual tuples, and a
// question that skips the wrapper carries no such tuples. The integration
// measurement caught it (TestPageCost), which is the only reason this is a file
// and not an incident.
//
// The general shape is written down in this package already, about a different
// method: a promoted method is a capability the compiler will happily report as
// present while the behaviour that made it correct is gone, and neither a type
// check nor a diff review can see the difference.
package authzcascade

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// BatchCheckWithContext — clients.RelationQueries, decorated.
//
// # The two populations of a page, and why they are asked differently
//
// A page reaching here has been through PrefetchStructural, so most of its objects
// have their structural facts already memoised for this request. For those the
// per-object path does NOT ask twice: it asks once, carrying the facts, because a
// contextual tuple can only ADD a resolution path — one question with true facts
// has the answer the ask-then-re-ask pair has. That is the property the page-cost
// measurement pins, and it is preserved here exactly: known-facts objects go into
// ONE request, each item carrying its own tuples.
//
// An object whose facts are NOT memoised is a memo miss — the prefetch was not
// wired, or the batch read did not return that row. Recording it as "no facts"
// is the one thing that must never happen (see PrefetchStructural's doc, and the
// defect it describes), so those objects take the per-object path unchanged: ask,
// and on a denial read the facts and ask again. They are the minority by
// construction and the fallback is the pre-existing code.
//
// Fail-closed is unchanged: the first error of either population is returned and
// no partial answer is produced.
func (c *Client) BatchCheckWithContext(
	ctx context.Context, subject, relation string, objects []string, condCtx map[string]any,
) ([]bool, error) {
	if c == nil {
		return nil, nil
	}
	out := make([]bool, len(objects))
	if len(objects) == 0 {
		return out, nil
	}

	// Split by what this request already knows. Positions are kept so the answer
	// can be reassembled in the caller's order — a batched answer that is right
	// but shuffled filters a page by someone else's verdict.
	var (
		knownIdx  []int
		knownItem []clients.BatchCheckItem
		missIdx   []int
	)
	for i, object := range objects {
		facts, known := c.memoFacts(ctx, object)
		if !known {
			missIdx = append(missIdx, i)
			continue
		}
		knownIdx = append(knownIdx, i)
		knownItem = append(knownItem, clients.BatchCheckItem{Object: object, Contextual: facts})
	}

	if len(knownItem) > 0 {
		verdicts, err := c.batchItems(ctx, subject, relation, knownItem, condCtx)
		if err != nil {
			return nil, err
		}
		if len(verdicts) != len(knownItem) {
			// Guarded here as well as in the transport: this wrapper is what the
			// page filter holds, so a misaligned answer arriving through a
			// different Relations implementation must not reach the filter either.
			return nil, errMisalignedBatch(len(verdicts), len(knownItem))
		}
		for j, pos := range knownIdx {
			out[pos] = verdicts[j]
		}
	}

	for _, pos := range missIdx {
		allowed, err := c.CheckWithContext(ctx, subject, relation, objects[pos], condCtx)
		if err != nil {
			return nil, err
		}
		out[pos] = allowed
	}
	return out, nil
}

// batchItems asks the transport with per-item contextual tuples when it can carry
// them, and falls back to the per-object decorated path when it cannot.
//
// The capability is asked for rather than assumed because Relations is an
// interface the tests and the composition root both satisfy, and a doubling that
// cannot carry tuples must produce the same ANSWER, not a faster wrong one. The
// fallback here is the decorated per-object Check, never the promoted plain
// batch — falling back to the undecorated door is the defect this file exists to
// close.
func (c *Client) batchItems(
	ctx context.Context, subject, relation string, items []clients.BatchCheckItem, condCtx map[string]any,
) ([]bool, error) {
	if bc, ok := c.Relations.(batchContextualChecker); ok {
		return bc.BatchCheckItems(ctx, subject, relation, items, condCtx)
	}
	out := make([]bool, len(items))
	for i, item := range items {
		allowed, err := c.checkCarryingFacts(ctx, subject, relation, item.Object, condCtx, item.Contextual)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// checkCarryingFacts asks one question the way the per-object path asks it for an
// object whose facts are known: once, with the facts attached.
func (c *Client) checkCarryingFacts(
	ctx context.Context, subject, relation, object string,
	condCtx map[string]any, facts []authztypes.TupleKey,
) (bool, error) {
	if len(facts) > 0 {
		return c.Relations.CheckWithContextualTuples(ctx, subject, relation, object, condCtx, facts)
	}
	return c.Relations.CheckWithContext(ctx, subject, relation, object, condCtx)
}

// batchContextualChecker — the transport capability that makes one request carry a
// whole page's worth of per-item facts.
type batchContextualChecker interface {
	BatchCheckItems(ctx context.Context, subject, relation string,
		items []clients.BatchCheckItem, condCtx map[string]any) ([]bool, error)
}

// errMisalignedBatch — a batched answer that cannot be aligned with the questions
// it answers. Stated as its own constructor so the two guards that raise it read
// identically.
func errMisalignedBatch(got, want int) error {
	return fmt.Errorf("authzcascade: relation store answered %d of %d batched checks", got, want)
}
