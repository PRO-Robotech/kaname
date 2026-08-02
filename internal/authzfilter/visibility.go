// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authzfilter resolves per-object READ-visibility (`viewer` ∪ `v_list`)
// for kacho-iam's own read surfaces by asking a DIRECT per-object question —
// never by enumerating the objects a subject may see.
//
// # Why not ListObjects (this was the bug)
//
// Every iam read that filtered by visibility used to ask OpenFGA "enumerate ALL
// objects of this type the subject may see" (`ListObjects`) and then matched the
// resource against that set — read-by-id via membership, List via an
// `id = ANY(...)` push-down.
//
// OpenFGA bounds `ListObjects` SERVER-side (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`,
// default 1000) and exposes NO continuation token, so the enumeration silently
// returns an arbitrary 1000-id prefix. The bound applies to the TYPE IN THE
// STORE (cluster-wide), not to the tenant: on a long-lived store (the live stand
// already holds 3693 `iam_access_binding` tuples) a tenant's own resource falls
// outside the prefix and becomes PERMANENTLY invisible — Get → 403/404, List →
// absent — while the DB row exists, the grant exists, and mutations (which ask a
// DIRECT per-object question) keep working. Asking for a larger `max_results`
// does not help: that argument is only a CLIENT-side trim of an already-cut
// response, so requesting more can never widen the answer.
//
// The cure is not a bigger cap (it is external, and finite either way) but a
// different SHAPE of question: instead of "enumerate the universe and look for
// me in it", ask "may this subject see THIS object", for the objects on the page
// (List) or for the single object being read (Get). Cost then scales with the
// PAGE, not with the type's population.
//
// # The visibility predicate is unchanged
//
// `ListObjects` returns, by definition, the objects `Check` would allow, and iam
// unioned two relations — `viewer ∪ v_list` (AuthorizeService.ListObjects, and
// every use-case-level copy). This package evaluates EXACTLY that predicate,
// only per-object: `viewer` first, then `v_list` for the ids `viewer` denied. No
// weakening and no widening — the same question, asked in a bounded shape.
//
// # Fail-closed
//
// Any Check error aborts the whole resolution with that error; callers map it to
// UNAVAILABLE. A partially-resolved set is never returned: a page filtered by an
// incomplete answer would silently under-report (and, on the deny side, could
// under-report a deny).
package authzfilter

import (
	"context"
	"fmt"
	"sync"
)

// Relations — the union that constitutes read-visibility, in cost order:
//   - `viewer` — the read tier (direct usersets ∪ editor ∪ admin); covers the
//     overwhelming majority of visible objects;
//   - `v_list` — the object-only selector grant ("see in the selector without
//     content"), which on the decoupled Design-B model does NOT resolve `viewer`.
//
// Order matters only for cost: `viewer` is queried first and `v_list` only for
// the objects `viewer` denied.
var Relations = [...]string{"viewer", "v_list"}

// DefaultParallelism bounds how many per-object Checks VisibleSet keeps in flight
// ON THE FALLBACK PATH — the one taken by a checker that cannot answer in
// batches. Production wiring can (clients.RelationQueries requires the
// capability), so this bound governs in-process fakes and any future checker that
// does not offer the batched door.
//
// # What a page costs on this path, and what this bound does not do
//
// It bounds DEPTH, not COUNT. Every question is an HTTP round-trip to the relation
// store, which runs in its own pod: iam holds the OpenFGA client in-process, but
// the store is across the network, so "in-process client" says nothing about the
// price of asking. A page pays len(Relations) questions for every object the first
// relation does not resolve, so a contract-sized page (validate.MaxPageSize = 1000)
// costs up to 2000 round-trips, and this bound turns them into 125 sequential
// waves rather than removing any of them. At a 10ms answer that is over a second
// of wall time on ONE List; at 50ms, over six.
//
// The 200ms budget on a Check belongs to the CALL, not to the page — nothing caps
// the page as a whole — so those waves accumulate without any per-call deadline
// firing. Measured, with the arithmetic spelled out, in
// TestVisibleSet_WorstCasePageCost; the bound itself is locked by
// TestVisibleSet_MaxPageBoundedFanOut.
//
// # Why the bound is nonetheless right
//
// Unbounded is worse, not better: a goroutine per row puts the whole page on the
// client at once. The bound is what keeps a large page from arriving all at once;
// it is not an argument that the page is cheap.
//
// # The count IS smaller now, on the path production takes
//
// This paragraph used to end "Making the COUNT smaller is a different change —
// asking the store about many objects in one request — and it is not done here".
// It is done here now: see MaxBatchChecksPerRequest and visibleSetBatched, which
// resolve the same 2000 tuples in 40 requests. The sentence is kept, corrected,
// rather than deleted, because it was true when written and the next reader of
// DefaultParallelism has to know which path the number above describes.
const DefaultParallelism = 16

// MaxBatchChecksPerRequest — how many objects one request to the relation store
// may ask about.
//
// This is the STORE's ceiling, not ours, and the two are easy to confuse. iam
// publishes its own `AuthorizeService.BatchCheck` bounded at 100, and that number
// governs how large a page a SIBLING service may hand to iam. The relation store
// behind iam enforces its own, lower bound and refuses an over-cap request
// outright — a `validation_error`, never a trim — so splitting a page against the
// published 100 would make every partition a refusal rather than a faster page.
//
// Read off the deployed build (openfga/openfga:v1.14.0) rather than assumed: a
// request of 51 is answered `batchCheck received 51 checks, the maximum allowed
// is 50`, a request of 50 is answered 200. The bound is a server flag, so a
// deployment MAY raise it; splitting against the default is correct at any
// setting at or above it, and a deployment that LOWERS it gets a loud refusal
// that fails the page closed, not a quietly short answer.
const MaxBatchChecksPerRequest = 50

// BatchParallelism bounds how many partitions of one page are in flight.
//
// It replaces DefaultParallelism on the batched path and is smaller on purpose:
// each partition already carries MaxBatchChecksPerRequest questions, which the
// store resolves with its own internal concurrency, so in-flight partitions
// multiply against that. Eight partitions is 400 questions the store may be
// resolving at once — comparable to the pressure the per-object path applied at
// sixteen in-flight single questions only because that path spread the same work
// across 125 waves instead of three.
//
// A contract-sized page is 20 partitions per relation, so this bound makes a
// relation round three waves and the whole page at most six — against 125. The
// arithmetic is asserted, with both counts, in
// TestVisibleSet_BatchedWorstCasePageCost.
const BatchParallelism = 8

// BatchObjectChecker — OPTIONAL capability of an ObjectChecker: answer ONE
// relation question about MANY objects in a single request.
//
// Declared here as a narrow port and satisfied by the OpenFGA adapter, so this
// package keeps knowing nothing about the store — the same leaf discipline as
// ObjectChecker and pagePreparer.
//
// Unlike pagePreparer this capability is NOT best-effort: it decides. An
// implementation must return one verdict per object, in the order the objects
// were given, or an error. It must never return a short slice — a caller cannot
// tell a short answer from a page of denials, and a page of silent denials is
// exactly the permanent-invisibility defect this package exists to prevent.
type BatchObjectChecker interface {
	BatchCheckWithContext(ctx context.Context, subject, relation string, objects []string,
		condCtx map[string]any) (allowed []bool, err error)
}

// ObjectChecker — narrow port: ONE direct per-object relation question.
// Satisfied by clients.RelationQueries (and by *clients.OpenFGAHTTPClient).
//
// The port is declared here rather than imported so this package stays a leaf
// (it must not depend on the OpenFGA adapter) — the same discipline as
// authzguard.RelationChecker.
type ObjectChecker interface {
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (allowed bool, err error)
}

// pagePreparer — OPTIONAL capability of an ObjectChecker: prepare, once, whatever the
// per-object questions of a whole page would otherwise prepare row by row.
//
// It is declared here as a narrow port and satisfied elsewhere, so this package keeps
// knowing nothing about what is being prepared. The contract is deliberately weak, and
// that is what makes it safe to call blind:
//
//   - it returns a context, never an error. A preparation that fails must return the
//     context it was given, so the per-object path runs exactly as it would have — the
//     capability can cost speed, never an answer;
//   - it must not decide anything. Nothing here reads its result; the per-object question
//     is still the only thing that decides.
//
// Absence is invisible to correctness and visible to cost, so cost is where it is
// asserted (the implementor's page-cost measurement), not here.
type pagePreparer interface {
	PrefetchStructural(ctx context.Context, objectType string, ids []string) context.Context
}

// Visible reports whether `subject` may read `<objectType>:<id>` — the
// `viewer ∪ v_list` union, evaluated per-object.
//
// Fail-closed: a nil checker, an empty subject or an empty id yields
// (false, nil); a Check transport error yields (false, err) and the caller MUST
// propagate it (never treat it as a deny — that would turn an FGA outage into a
// silent, permanent 404).
func Visible(ctx context.Context, chk ObjectChecker, subject, objectType, id string) (bool, error) {
	if chk == nil || subject == "" || objectType == "" || id == "" {
		return false, nil
	}
	object := objectType + ":" + id
	for _, relation := range Relations {
		allowed, err := chk.CheckWithContext(ctx, subject, relation, object, nil)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// VisibleSet returns the subset of `ids` visible to `subject`, as a set. It is
// the page-scoped form: callers read a page from their OWN database by cursor
// FIRST (so page_size/page_token validation keeps running before any authz
// short-circuit) and then filter that page with this call.
//
// Duplicate ids are resolved once. The result is always non-nil so callers can
// index it directly. Fail-closed: the FIRST Check error aborts the whole
// resolution and is returned — a partially-resolved set is never handed back.
func VisibleSet(ctx context.Context, chk ObjectChecker, subject, objectType string, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if chk == nil || subject == "" || objectType == "" || len(ids) == 0 {
		return out, nil
	}

	// Deduplicate: one page must not pay twice for a repeated id.
	pending := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		pending = append(pending, id)
	}
	if len(pending) == 0 {
		return out, nil
	}

	// One preparation for the whole page, if the checker has one to offer. The
	// per-object question may need a fact about the object's place in the hierarchy;
	// resolving that per row makes the page cost grow with the page, and page size is
	// part of the contract up to 1000 while narrowing it to fit a budget is forbidden.
	// Asking here — the one place that knows the whole page — keeps that cost flat.
	//
	// OPTIONAL and best-effort by contract (see the port's doc): a checker without the
	// capability, or a preparation that fails, returns a context the per-object path
	// works with unchanged. So this can cost speed and never an answer, and this package
	// stays a leaf that knows nothing about where those facts come from.
	if p, ok := chk.(pagePreparer); ok {
		ctx = p.PrefetchStructural(ctx, objectType, pending)
	}

	// One request per partition when the checker can answer that way. This is the
	// whole reduction: the same tuples, asked in ceil(len/cap) messages per
	// relation instead of one message per (object, relation).
	if bc, ok := chk.(BatchObjectChecker); ok {
		return visibleSetBatched(ctx, bc, subject, objectType, pending, out)
	}

	// Bounded fan-out over a fixed worker pool (workers, not goroutine-per-id, so
	// a large page does not spawn a goroutine per row). The first error cancels
	// the remaining work and is the one returned.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := DefaultParallelism
	if len(pending) < workers {
		workers = len(pending)
	}
	queue := make(chan string)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for id := range queue {
				allowed, err := Visible(cctx, chk, subject, objectType, id)
				mu.Lock()
				if err != nil {
					if firstEr == nil {
						firstEr = err
						cancel() // stop the rest — the answer is already fail-closed
					}
					mu.Unlock()
					return
				}
				if allowed {
					out[id] = true
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, id := range pending {
		select {
		case queue <- id:
		case <-cctx.Done():
			break feed // a worker already failed closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}
	// cancel() is called only after firstEr is set, so a done cctx with no
	// recorded error means the PARENT ctx expired mid-page. Report it instead of
	// handing back the half-resolved set as if it were the answer.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// visibleSetBatched resolves a page by asking the store about many objects per
// request. It evaluates EXACTLY the predicate the per-object path evaluates —
// `viewer` for the whole page, then `v_list` only for what `viewer` denied — and
// differs from it in one respect only: how many messages carry the question.
//
// # Two rounds, not two hundred waves
//
// The relations stay sequential because the second one's input is the first
// one's denials; that data dependency is the same one the per-object path has,
// and it is what keeps the tuple count at "one relation per object until one
// allows" rather than "every relation for every object". What changes is the
// inside of a round: its partitions are issued CONCURRENTLY, so a round is one
// round-trip plus scheduling rather than a queue.
//
// That distinction is the point of the whole change. A budget belongs to the
// REQUEST, and a request may legitimately ask for 1000 rows; twenty partitions
// issued one after another would put the page back on the wrong side of that
// budget while looking, in a request count, as if it had been fixed.
//
// # Fail-closed, and no falling back
//
// The first error aborts the page and is returned; a partially-resolved set is
// never handed back. In particular a refusing batch door is NOT papered over by
// re-asking per object: the two doors reach the same store, so a refusal that is
// real would simply be re-collected 2000 times, and a refusal that is about the
// REQUEST (an over-cap partition, a store that does not serve this endpoint) is a
// configuration fault that must stay loud rather than degrade into a slow path
// nobody notices.
func visibleSetBatched(
	ctx context.Context, bc BatchObjectChecker,
	subject, objectType string, pending []string, out map[string]bool,
) (map[string]bool, error) {
	remaining := pending
	for _, relation := range Relations {
		if len(remaining) == 0 {
			break
		}
		denied, err := batchRelationRound(ctx, bc, subject, objectType, relation, remaining, out)
		if err != nil {
			return nil, err
		}
		remaining = denied
	}
	// Mirrors the per-object path: a done parent context with no recorded error
	// means the REQUEST expired mid-page. Reporting it is the difference between
	// "these rows are not visible" and "we stopped asking".
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// batchRelationRound asks ONE relation about every id in `ids`, in partitions of
// at most MaxBatchChecksPerRequest issued concurrently, records the allowed ids
// in `out`, and returns the denied ids for the next relation.
func batchRelationRound(
	ctx context.Context, bc BatchObjectChecker,
	subject, objectType, relation string, ids []string, out map[string]bool,
) ([]string, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type partition struct {
		offset int
		ids    []string
	}
	parts := make([]partition, 0, (len(ids)+MaxBatchChecksPerRequest-1)/MaxBatchChecksPerRequest)
	for off := 0; off < len(ids); off += MaxBatchChecksPerRequest {
		end := off + MaxBatchChecksPerRequest
		if end > len(ids) {
			end = len(ids)
		}
		parts = append(parts, partition{offset: off, ids: ids[off:end]})
	}

	// allowed is indexed by position in `ids`, so partitions write disjoint slots
	// and need no lock; the denied list is rebuilt afterwards in input order,
	// which keeps the second relation's partitioning deterministic.
	allowed := make([]bool, len(ids))

	workers := BatchParallelism
	if len(parts) < workers {
		workers = len(parts)
	}
	queue := make(chan partition)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for p := range queue {
				objects := make([]string, len(p.ids))
				for i, id := range p.ids {
					objects[i] = objectType + ":" + id
				}
				verdicts, err := bc.BatchCheckWithContext(cctx, subject, relation, objects, nil)
				if err == nil && len(verdicts) != len(objects) {
					// A short or long answer cannot be aligned with the objects it
					// was asked about, and a page filtered by a misaligned answer is
					// wrong in a way no caller can detect. Refuse it as an error.
					err = fmt.Errorf(
						"authzfilter: relation store answered %d of %d checks for relation %q",
						len(verdicts), len(objects), relation)
				}
				mu.Lock()
				if err != nil {
					if firstEr == nil {
						firstEr = err
						cancel() // stop the rest — the answer is already fail-closed
					}
					mu.Unlock()
					return
				}
				mu.Unlock()
				for i, ok := range verdicts {
					allowed[p.offset+i] = ok
				}
			}
		}()
	}
feed:
	for _, p := range parts {
		select {
		case queue <- p:
		case <-cctx.Done():
			break feed // a worker already failed closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}

	denied := make([]string, 0, len(ids))
	for i, id := range ids {
		if allowed[i] {
			out[id] = true
			continue
		}
		denied = append(denied, id)
	}
	return denied, nil
}
