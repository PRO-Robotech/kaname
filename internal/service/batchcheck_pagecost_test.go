// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"sync"
	"testing"
	"time"
)

// latencyRelations — an Authorizer that records how many store round-trips a pass
// makes AND how many of them were ever in flight at the same time.
//
// The second number is the one that matters here and the one a call counter cannot
// see: a batch resolved one item after another and a batch resolved in parallel
// issue the SAME number of questions, and differ only in how long the caller waits.
// A test that counts calls is green on both.
type latencyRelations struct {
	perCheck time.Duration

	mu       sync.Mutex
	calls    int
	inFlight int
	maxInFly int
}

func (m *latencyRelations) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	m.mu.Lock()
	m.calls++
	m.inFlight++
	if m.inFlight > m.maxInFly {
		m.maxInFly = m.inFlight
	}
	m.mu.Unlock()

	if m.perCheck > 0 {
		select {
		case <-time.After(m.perCheck):
		case <-ctx.Done():
		}
	}

	m.mu.Lock()
	m.inFlight--
	m.mu.Unlock()
	return false, nil // every per-object resolve denies: the worst case, and the shape a page filter hits
}

func (m *latencyRelations) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	return nil, "", nil
}

func (m *latencyRelations) Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error) {
	return nil, nil
}

// DirectRelations — диагностика хвоста текста отказа. Она НЕ учитывается
// счётчиками выше, и это осознанно: предмет файла — сколько вопросов о ВЕРДИКТЕ
// пачка задаёт одновременно, а не сколько всего обращений к хранилищу делает
// ответ. Считать её здесь значило бы смешать две величины и получить число,
// которого никто не измерял.
func (m *latencyRelations) DirectRelations(ctx context.Context, subject, objectType, objectID string, limit int) ([]string, error) {
	return nil, nil
}

func (m *latencyRelations) snapshot() (calls, maxInFly int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls, m.maxInFly
}

// batchOfSameSubject builds the shape a sibling's page filter actually sends: one
// subject, one relation, many distinct objects — a slice of ONE page.
func batchOfSameSubject(n int) []CheckRequest {
	reqs := make([]CheckRequest, n)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:          "user:usr_tenant",
			Resource:         ResourceRef{Type: "vpc_network", ID: "net_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))},
			Action:           "vpc.networks.get",
			RequiredRelation: "v_get",
		}
	}
	return reqs
}

// TestBatchCheck_ResolvesItsItemsConcurrently — AuthorizeService.BatchCheck is the
// door every sibling service's List filter walks through: vpc/compute/nlb/storage
// each cut their page into slices of at most 100 ids and hand each slice here.
//
// The number of store questions is not what this asserts — it is the same either
// way, one per item, and that is inherent to a per-object predicate. What it
// asserts is that those questions are not made to WAIT ON EACH OTHER inside one
// request, because the caller's deadline is per REQUEST: a sibling gives this call
// one second (authzfilter.DefaultConfig().Timeout) for the whole slice of 100. If
// the slice is resolved one item after another, its wall time is 100 × the store's
// answer time, so a store answering in 10ms consumes the entire budget and anything
// slower fails the caller's whole POSITIVE List closed with UNAVAILABLE — the
// failure mode the sibling's own bounded fan-out was written to remove, sitting one
// hop further in than that fan-out can see.
//
// The property is therefore "a slice is not a queue", expressed as observed
// concurrency, and the wall-time arithmetic is printed so the number is auditable
// rather than asserted as a timing (which would be flaky).
func TestBatchCheck_ResolvesItsItemsConcurrently(t *testing.T) {
	const (
		slice        = 100                     // the published cap siblings partition against
		perCheck     = 5 * time.Millisecond    // a deliberately OPTIMISTIC store latency
		callerBudget = 1000 * time.Millisecond // authzfilter.DefaultConfig().Timeout in vpc/compute/nlb/storage
	)

	// The premise. The arithmetic above is derived from ONE number that is not
	// this package's to choose: the published batch cap the siblings partition
	// against. It cannot be imported (a service must not import a sibling), so it
	// is re-established here against the enforcement below — if iam ever changes
	// the cap, this fails and the wall-time reasoning in BatchCheck's doc, and in
	// each sibling's partitioning, has to be re-derived rather than silently
	// inherited.
	if _, err := (&AuthorizeService{}).BatchCheck(context.Background(), make([]CheckRequest, slice+1)); err == nil {
		t.Fatalf("premise broken: a %d-item batch is no longer refused, so %d is not the cap "+
			"siblings partition against and this probe's arithmetic no longer describes a real slice",
			slice+1, slice)
	}
	if batchCheckParallelism <= 1 {
		t.Fatalf("premise broken: batchCheckParallelism=%d cannot express concurrency",
			batchCheckParallelism)
	}

	// What this double is, and what its number therefore means.
	//
	// It answers ONE store question per item and nothing else: no structural
	// facts, no contextual re-ask, no deny-reason enrichment. Production pays
	// MORE than that per item on the deny path. The wall time printed below is
	// therefore a LOWER bound on what the sequential version cost, not an
	// estimate of it — the double understates the problem, which is the safe
	// direction for a number that argues a fix was needed.
	//
	// It is deliberately minimal for that same reason: the property asserted here
	// is "the items do not wait on each other", and every extra store interaction
	// would add cost that is not this property, making the observed concurrency
	// harder to attribute. The MAGNITUDE of the win belongs to a measurement
	// against a real store; the PROPERTY belongs here.
	store := &latencyRelations{perCheck: perCheck}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	start := time.Now()
	results, err := svc.BatchCheck(context.Background(), batchOfSameSubject(slice))
	wall := time.Since(start)
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if len(results) != slice {
		t.Fatalf("results: got %d want %d", len(results), slice)
	}

	calls, maxInFly := store.snapshot()
	t.Logf("slice=%d items | store round-trips=%d | max in flight=%d | per-check=%v | wall=%v | caller budget=%v",
		slice, calls, maxInFly, perCheck, wall.Round(time.Millisecond), callerBudget)
	t.Logf("sequential wall would be %v; a contract page (1000 ids = 10 slices) at this latency costs %v of store time",
		time.Duration(slice)*perCheck, time.Duration(slice*10)*perCheck)

	// Volume examined. A pass that never reached the store observes no concurrency
	// either, so every assertion below would hold vacuously — "nothing ran" must be
	// a failure, not a silent pass.
	if calls != slice {
		t.Fatalf("the probe asked the store %d times for a %d-item slice: it is not measuring the "+
			"fan-out it claims to measure (every item must reach the store on the all-denied path)",
			calls, slice)
	}

	if maxInFly <= 1 {
		t.Fatalf("BatchCheck resolves its %d items SEQUENTIALLY (max in flight=%d): "+
			"wall time is items × store latency (%v here), and the caller's deadline for the whole "+
			"slice is %v, so a store slower than %v fails the caller's entire positive List closed. "+
			"A slice must not be a queue.",
			slice, maxInFly, wall.Round(time.Millisecond), callerBudget, callerBudget/slice)
	}
}

// TestBatchCheck_ConcurrencyIsBounded — the paired POSITIVE control for the
// assertion above, and the reason that assertion cannot be satisfied by the wrong
// fix. "Not a queue" must not become "a goroutine per item": an unbounded fan-out
// would put a whole slice on the store at once, and several concurrent Lists would
// multiply against each other.
//
// Without this pair the sibling test above is a one-way ratchet that reads as
// "more concurrency is always better", which is how a bounded fan-out gets removed
// by the next person trying to make a page faster.
func TestBatchCheck_ConcurrencyIsBounded(t *testing.T) {
	const slice = 100

	store := &latencyRelations{perCheck: 2 * time.Millisecond}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	if _, err := svc.BatchCheck(context.Background(), batchOfSameSubject(slice)); err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}

	_, maxInFly := store.snapshot()
	t.Logf("slice=%d | max in flight=%d | declared bound=%d", slice, maxInFly, batchCheckParallelism)

	if maxInFly > batchCheckParallelism {
		t.Fatalf("BatchCheck put %d questions on the store at once; the declared bound is %d. "+
			"A slice resolved with a goroutine per item hands the whole page to the store in one "+
			"burst, and concurrent Lists multiply against that.",
			maxInFly, batchCheckParallelism)
	}
	if maxInFly <= 1 {
		t.Fatalf("max in flight=%d — the bound cannot be observed because nothing ran concurrently; "+
			"this control is vacuous unless the sibling property holds", maxInFly)
	}
}

// TestBatchCheck_ClusterAdminMemoStaysDedupedUnderConcurrency — the memo that makes
// a cluster-admin batch cost ONE super-gate question instead of one per item is
// shared mutable state across the pass. Resolving the pass concurrently is exactly
// what turns that sharing into a data race, so the property it encodes is re-asserted
// here under the concurrent path (and this file is run with -race).
//
// This is the "did the fix keep the earlier fix" check: the dedup was itself a
// measured improvement (TestAuthorize_BatchCheck_ClusterAdmin_SingleShortCircuit),
// and a concurrency change that silently restored one super-gate question per item
// would leave that test green while undoing its point.
func TestBatchCheck_ClusterAdminMemoStaysDedupedUnderConcurrency(t *testing.T) {
	const slice = 100

	store := &latencyRelations{perCheck: time.Millisecond}
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_tenant": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           store,
		ClusterAdminChecker: cl,
	})

	results, err := svc.BatchCheck(context.Background(), batchOfSameSubject(slice))
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	for i, r := range results {
		if !r.Allowed {
			t.Fatalf("item %d: cluster-admin must resolve via the super-gate; deny=%v", i, r.DenyReasons)
		}
	}
	storeCalls, _ := store.snapshot()
	t.Logf("slice=%d | store round-trips=%d | super-gate questions=%d (memoized; one per subject, not per item)",
		slice, storeCalls, cl.calls)
	// Volume examined: the super-gate is only reached on the DENY path, so a pass
	// that never asked the store never reached it either and "≤1" would hold for
	// the wrong reason.
	if storeCalls != slice {
		t.Fatalf("the probe asked the store %d times for a %d-item slice; the super-gate is only "+
			"reached after a per-object deny, so this measurement would be vacuous", storeCalls, slice)
	}
	if cl.calls < 1 {
		t.Fatalf("super-gate was never asked (%d): the memo cannot be shown to dedupe a question "+
			"that was not asked", cl.calls)
	}
	if cl.calls > 1 {
		t.Fatalf("super-gate asked %d times for ONE subject; the per-pass memo must dedupe it to 1 "+
			"even when the pass is resolved concurrently", cl.calls)
	}
}

// latencyClusterChecker — a cluster-admin checker that TAKES TIME and records
// how many of its questions were ever in flight at once.
//
// The existing double counts calls only, which cannot see the property below: a
// memo that serialises every subject and a memo that resolves subjects in
// parallel issue the SAME number of super-gate questions and differ only in how
// long the pass takes.
type latencyClusterChecker struct {
	perCheck time.Duration
	admins   map[string]bool

	mu       sync.Mutex
	calls    int
	bySubj   map[string]int
	inFlight int
	maxInFly int
}

func (c *latencyClusterChecker) Check(_ context.Context, subject, _, _ string) (bool, error) {
	c.mu.Lock()
	c.calls++
	if c.bySubj == nil {
		c.bySubj = map[string]int{}
	}
	c.bySubj[subject]++
	c.inFlight++
	if c.inFlight > c.maxInFly {
		c.maxInFly = c.inFlight
	}
	c.mu.Unlock()

	if c.perCheck > 0 {
		time.Sleep(c.perCheck)
	}

	c.mu.Lock()
	c.inFlight--
	allowed := c.admins[subject]
	c.mu.Unlock()
	return allowed, nil
}

func (c *latencyClusterChecker) snapshot() (calls, maxInFly, maxPerSubject int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.bySubj {
		if n > maxPerSubject {
			maxPerSubject = n
		}
	}
	return c.calls, c.maxInFly, maxPerSubject
}

// batchOfDistinctSubjects — a slice whose items name DIFFERENT subjects. The
// method supports this shape explicitly (its own comment says a mixed-subject
// batch stays correct), so it is not a hypothetical.
func batchOfDistinctSubjects(n int) []CheckRequest {
	reqs := make([]CheckRequest, n)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:          "user:usr_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)),
			Resource:         ResourceRef{Type: "vpc_network", ID: "net_shared"},
			Action:           "vpc.networks.get",
			RequiredRelation: "v_get",
		}
	}
	return reqs
}

// TestBatchCheck_SuperGateDoesNotSerialiseDistinctSubjects — the pool survives a
// slice whose items name different subjects.
//
// The memo exists to ask the cluster-admin super-gate at most once per SUBJECT,
// and to do that it must hold its guard across the question — otherwise every
// worker that arrives before the first answer misses and asks again. Held as ONE
// guard for the whole pass, that correct requirement had a consequence its
// comment denied: on a mixed-subject slice the single lock was taken across a
// network call for every item in turn, so the bounded pool this method was given
// was defeated completely and the pass ran at parallelism one — the very failure
// the pool was added to remove, reintroduced one layer in.
//
// Two things are asserted together, because either alone is satisfiable by a
// broken implementation: the super-gate is still asked AT MOST ONCE PER SUBJECT
// (drop the memo and this fails), and questions for DIFFERENT subjects overlap
// (serialise the memo and this fails).
func TestBatchCheck_SuperGateDoesNotSerialiseDistinctSubjects(t *testing.T) {
	const slice = 100

	store := &latencyRelations{}
	cl := &latencyClusterChecker{perCheck: 5 * time.Millisecond, admins: map[string]bool{}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           store,
		ClusterAdminChecker: cl,
	})

	start := time.Now()
	if _, err := svc.BatchCheck(context.Background(), batchOfDistinctSubjects(slice)); err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	wall := time.Since(start)

	calls, maxInFly, maxPerSubject := cl.snapshot()
	storeCalls, _ := store.snapshot()
	t.Logf("slice=%d distinct subjects | store round-trips=%d | super-gate questions=%d "+
		"| max in flight=%d | max per subject=%d | wall=%s",
		slice, storeCalls, calls, maxInFly, maxPerSubject, wall.Round(time.Millisecond))

	// Volume examined: the super-gate is reached only after a per-object deny, so
	// a pass that asked nothing would satisfy every bound below for the wrong
	// reason.
	if storeCalls != slice {
		t.Fatalf("probe asked the store %d times for a %d-item slice — the measurement below "+
			"would be vacuous", storeCalls, slice)
	}
	if calls == 0 {
		t.Fatalf("super-gate was never asked: nothing about its concurrency can be shown")
	}
	if maxPerSubject > 1 {
		t.Errorf("super-gate asked %d times for ONE subject — the per-subject memo is gone, and "+
			"a same-subject slice would pay one super-gate question per item", maxPerSubject)
	}
	if maxInFly < 2 {
		t.Errorf("super-gate questions for %d DIFFERENT subjects never overlapped (max in flight=%d).\n"+
			"  The memo is serialising the whole pass across a network call, so the bounded pool "+
			"given to this method is defeated and the slice resolves at parallelism one — exactly "+
			"the wall-time failure the pool was added to remove.\n"+
			"  Guard per SUBJECT, not per pass: the dedup is a property of one subject's question.",
			slice, maxInFly)
	}
}
