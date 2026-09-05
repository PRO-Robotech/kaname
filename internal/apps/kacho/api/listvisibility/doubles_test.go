// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// doubles_test.go — the three wrappers the probes put between a use-case and the
// LIVE decision door.
//
// None of them is a stand-in for the door: each EMBEDS the production client and
// delegates every question it does not have a reason to touch. That is not
// tidiness, it decides what is being measured. `authzfilter.VisibleSet` chooses
// its path by asserting capabilities on the checker it was handed — a wrapper
// that implemented only the single-object door would silently move the whole
// page onto the one-question-per-row path, and a probe counting questions would
// then be reporting the wrapper's shape rather than the product's cost.
//
// Здесь у двух обёрток стояли ещё `WriteTuples`/`DeleteTuples`. Их предмет снят
// вместе с внешним движком отношений: писать кортежи больше некуда — состояние,
// из которого складывается ответ, есть свёртка СОБСТВЕННОГО журнала, и пишет в
// него тот же коммит, что меняет выдачу. Обёртка, сохранившая эти методы, была бы
// ШИРЕ настоящего порта, а дублёр шире предмета первым же делом перестаёт ловить
// то, ради чего его подставляют.

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

// ── counting ─────────────────────────────────────────────────────────────────

// countingQueries counts what one request asks of the relation store.
//
// Two counters, because the acceptance defines two different quantities (§2.1):
// `requests` is messages sent to the store — the unit that costs a round-trip;
// `objects` is verdicts obtained — the unit that says how much of the page was
// judged. A batched question moves the second without moving the first, which is
// precisely the distinction a probe about cost has to be able to make.
type countingQueries struct {
	clients.RelationQueries

	mu       sync.Mutex
	requests int
	objects  int
	// subject counts the questions that name no resource at all — "is this caller
	// a cluster administrator". §3.6 requires exactly one of these per request,
	// independent of population and of page size; counting them apart from the
	// per-object ones is the only way to notice the day that stops being true.
	subject int
}

func newCountingQueries(inner clients.RelationQueries) *countingQueries {
	return &countingQueries{RelationQueries: inner}
}

func (c *countingQueries) CheckWithContext(ctx context.Context, subject, relation, object string,
	condCtx map[string]any) (bool, error) {
	c.mu.Lock()
	c.requests++
	if isSubjectQuestion(relation, object) {
		c.subject++
	} else {
		c.objects++
	}
	c.mu.Unlock()
	return c.RelationQueries.CheckWithContext(ctx, subject, relation, object, condCtx)
}

func (c *countingQueries) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	c.mu.Lock()
	c.requests++
	c.objects += len(objects)
	c.mu.Unlock()
	return c.RelationQueries.BatchCheckWithContext(ctx, subject, relation, objects, condCtx)
}

func (c *countingQueries) counts() (requests, objects int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.objects
}

func (c *countingQueries) subjectQuestions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.subject
}

// ── subject-question outage ──────────────────────────────────────────────────

// errSubjectQuestion is the injected failure. It is deliberately unmistakable in
// a failure message: a probe that ends up reporting this string has proved the
// error reached the caller, which is the point.
var errSubjectQuestion = errors.New("injected: the relation store could not answer the SUBJECT question")

// subjectQuestionDown fails exactly one shape of question — "is this caller a
// cluster administrator" — and answers everything else from the live store.
//
// Why that shape and only that shape. A whole-store outage proves nothing here:
// every path fails and the answer is UNAVAILABLE for reasons that have nothing
// to do with the subject question. The interesting state is the one the
// acceptance names in §3.6 — structural tiers are resolved by asking about the
// CALLER, once per request — and the failure mode it forbids: that question
// failing, and the answer being a narrowed `200` instead of a refusal.
type subjectQuestionDown struct {
	clients.RelationQueries
	store clients.RelationStore

	mu    sync.Mutex
	asked int
}

func newSubjectQuestionDown(q clients.RelationQueries, s clients.RelationStore) *subjectQuestionDown {
	return &subjectQuestionDown{RelationQueries: q, store: s}
}

// isSubjectQuestion reports whether this is the "who is the caller" question:
// a cluster-scoped relation asked about the singleton cluster object, carrying
// no resource id at all.
func isSubjectQuestion(relation, object string) bool {
	return strings.HasPrefix(object, "cluster:") &&
		(relation == "system_admin" || relation == "any_admin" || relation == "system_viewer")
}

func (s *subjectQuestionDown) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if isSubjectQuestion(relation, object) {
		s.mu.Lock()
		s.asked++
		s.mu.Unlock()
		return false, errSubjectQuestion
	}
	return s.store.Check(ctx, subject, relation, object)
}

func (s *subjectQuestionDown) CheckWithContext(ctx context.Context, subject, relation, object string,
	condCtx map[string]any) (bool, error) {
	if isSubjectQuestion(relation, object) {
		s.mu.Lock()
		s.asked++
		s.mu.Unlock()
		return false, errSubjectQuestion
	}
	return s.RelationQueries.CheckWithContext(ctx, subject, relation, object, condCtx)
}

func (s *subjectQuestionDown) timesAsked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

// ── whole-store outage ───────────────────────────────────────────────────────

var errStoreDown = errors.New("injected: the relation store is unreachable")

// storeDown refuses every question. It is the C6 fixture: whatever a list does
// when it cannot resolve rights, it may not be "an empty page" — that answer is
// byte-identical to "you have nothing".
type storeDown struct {
	clients.RelationQueries
	store clients.RelationStore
}

func newStoreDown(q clients.RelationQueries, s clients.RelationStore) *storeDown {
	return &storeDown{RelationQueries: q, store: s}
}

func (s *storeDown) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return false, errStoreDown
}

func (s *storeDown) BatchCheckWithContext(context.Context, string, string, []string, map[string]any) ([]bool, error) {
	return nil, errStoreDown
}

func (s *storeDown) Check(context.Context, string, string, string) (bool, error) {
	return false, errStoreDown
}

// ── mid-request hook ─────────────────────────────────────────────────────────

// hookedQueries runs `onNth` just before the n-th question of a request reaches
// the store, and then answers it normally.
//
// It exists to place a database write INSIDE one request, between two reads of
// the refill loop. Sleeping in another goroutine and hoping to land in the gap
// would be an assertion about scheduling; hooking the one call the loop is
// guaranteed to make between its reads is an assertion about the product.
type hookedQueries struct {
	clients.RelationQueries

	mu     sync.Mutex
	seen   int
	nth    int
	onNth  func()
	fired  bool
	firing bool
}

func newHookedQueries(inner clients.RelationQueries, nth int, onNth func()) *hookedQueries {
	return &hookedQueries{RelationQueries: inner, nth: nth, onNth: onNth}
}

func (h *hookedQueries) maybeFire() {
	h.mu.Lock()
	h.seen++
	should := h.seen == h.nth && !h.fired && !h.firing
	if should {
		h.firing = true
	}
	h.mu.Unlock()
	if !should {
		return
	}
	h.onNth()
	h.mu.Lock()
	h.fired = true
	h.firing = false
	h.mu.Unlock()
}

func (h *hookedQueries) didFire() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fired
}

func (h *hookedQueries) CheckWithContext(ctx context.Context, subject, relation, object string,
	condCtx map[string]any) (bool, error) {
	h.maybeFire()
	return h.RelationQueries.CheckWithContext(ctx, subject, relation, object, condCtx)
}

func (h *hookedQueries) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	h.maybeFire()
	return h.RelationQueries.BatchCheckWithContext(ctx, subject, relation, objects, condCtx)
}
