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

// DefaultParallelism bounds how many per-object Checks VisibleSet keeps in flight.
//
// # What a page costs, and what this bound does not do
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
// Making the COUNT smaller is a different change — asking the store about many
// objects in one request — and it is not done here: see
// services/iam/docs/architecture/known-divergences.md §11.
const DefaultParallelism = 16

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
