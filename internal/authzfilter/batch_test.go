// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// batch_test.go — what a page costs when the relation store is asked about many
// objects in ONE request, and the gate that keeps a batch-capable checker from
// silently falling back to asking about them one at a time.
//
// The sibling pagecost_gate_test.go states the per-object ceiling (2000
// round-trips for a contract-sized page). This file states the batched ceiling
// and, more importantly, the STRUCTURAL condition under which the batched number
// is the one a deployment actually pays: a checker that can answer in batches
// must never be asked row by row. Without that condition the number here
// describes a code path nothing is obliged to take.
package authzfilter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/validate"
)

// fakeBatchChecker — a checker that answers BOTH shapes over one oracle, and
// counts each shape separately.
//
// Counting them separately is the whole point: "the page was resolved correctly"
// is true of both shapes, so a test that only checks the verdict cannot tell a
// batched page from a per-object one. What distinguishes them is how many times
// the store was addressed, and by which door.
type fakeBatchChecker struct {
	granted map[string]bool
	err     error
	// batchErr — returned by the batch door only, so a test can prove the batch
	// path fails closed without also disabling the per-object door.
	batchErr error
	// sleep — artificial per-REQUEST latency (one batch = one request), so a test
	// can observe how many sequential waves a page takes.
	sleep time.Duration
	// maxBatch — the largest partition this stub will accept, mirroring the
	// relation store's own server-side cap. A larger partition is rejected the
	// way the store rejects it: an error, not a silent trim.
	maxBatch int

	nSingle atomic.Int64 // per-object questions (the old shape)
	nBatch  atomic.Int64 // batch requests (the new shape)
	nTuples atomic.Int64 // tuples asked about across all batch requests

	mu             sync.Mutex
	batchSizes     []int
	inFlightBatch  int
	maxInFlightBat int
}

func newFakeBatchChecker(granted ...string) *fakeBatchChecker {
	g := make(map[string]bool, len(granted))
	for _, k := range granted {
		g[k] = true
	}
	return &fakeBatchChecker{granted: g, maxBatch: MaxBatchChecksPerRequest}
}

func (f *fakeBatchChecker) CheckWithContext(_ context.Context, _, relation, object string,
	_ map[string]any) (bool, error) {
	f.nSingle.Add(1)
	if f.err != nil {
		return false, f.err
	}
	return f.granted[relation+"|"+object], nil
}

func (f *fakeBatchChecker) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, _ map[string]any) ([]bool, error) {
	f.nBatch.Add(1)
	f.nTuples.Add(int64(len(objects)))

	f.mu.Lock()
	f.batchSizes = append(f.batchSizes, len(objects))
	f.inFlightBatch++
	if f.inFlightBatch > f.maxInFlightBat {
		f.maxInFlightBat = f.inFlightBatch
	}
	sleep, maxBatch := f.sleep, f.maxBatch
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlightBatch--
		f.mu.Unlock()
	}()

	if len(objects) > maxBatch {
		// Exactly how the store answers an over-cap partition: a validation
		// refusal. Never a trim — a trimmed answer would under-report a page.
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
			len(objects), maxBatch)
	}
	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	if f.err != nil {
		return nil, f.err
	}
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = f.granted[relation+"|"+subject[:0]+o]
	}
	return out, nil
}

func (f *fakeBatchChecker) observedBatchSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.batchSizes...)
}

func (f *fakeBatchChecker) observedMaxInFlightBatches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInFlightBat
}

// worstCasePage — a contract-sized page on which the FIRST relation resolves
// nothing, which is what makes every object pay every relation. Returns the ids
// and the grant set that makes them visible through the LAST relation only.
func worstCasePage() (ids []string, granted []string) {
	n := int(validate.MaxPageSize)
	ids = make([]string, 0, n)
	granted = make([]string, 0, n)
	// Предикат членства принадлежит ТИПУ: тестовый тип "t" записи не имеет и берёт
	// умолчание, поэтому число раундов читается отсюда, а не из исчезнувшей
	// пакетной константы. Это не тавтология: утверждение ниже — про РАЗБИЕНИЕ
	// страницы, а число отношений ему вход.
	rels := RelationsFor("t")
	last := rels[len(rels)-1]
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("obj%04d", i)
		ids = append(ids, id)
		granted = append(granted, last+"|t:"+id)
	}
	return ids, granted
}

// TestVisibleSet_BatchedWorstCasePageCost — the ceiling a batch-capable checker
// pays, asserted as a COUNT of REQUESTS.
//
// The unit is the request, not the tuple: a tuple is work the store does either
// way, while a request is a network round-trip the caller waits on, and it is
// round-trips that turned a contract-sized page into 125 sequential waves. The
// tuple count is asserted too, and it must be UNCHANGED — batching is not
// allowed to ask about more or fewer objects than the per-object shape asked
// about, only to ask in fewer messages.
func TestVisibleSet_BatchedWorstCasePageCost(t *testing.T) {
	rels := RelationsFor("t")
	require.NotEmpty(t, rels,
		"premise: the ceiling below is one round of partitions per relation of the type")
	// Парный положительный контроль: предикат ДЕЙСТВИТЕЛЬНО зависит от типа, а не
	// отдаёт одно и то же всем. Без него «умолчание» неотличимо от «константа».
	require.NotEqual(t, rels, RelationsFor("iam_role"),
		"premise: page membership is per-type — the default and the one type that "+
			"keeps a union must not be the same answer")
	require.Equal(t, 50, MaxBatchChecksPerRequest,
		"premise: the partition count below divides the page by this cap — it is the "+
			"relation store's own server-side ceiling, measured off the deployed build")

	ids, granted := worstCasePage()
	f := newFakeBatchChecker(granted...)

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.NoError(t, err)
	require.Len(t, got, int(validate.MaxPageSize),
		"the verdict itself must be unaffected by how the question is carried")

	perRelation := (int(validate.MaxPageSize) + MaxBatchChecksPerRequest - 1) / MaxBatchChecksPerRequest
	wantRequests := int64(len(rels) * perRelation)
	wantTuples := int64(len(rels)) * validate.MaxPageSize

	require.Equal(t, int64(0), f.nSingle.Load(),
		"a checker that can answer in batches must never be asked object by object")
	require.Equal(t, wantRequests, f.nBatch.Load(),
		"a contract-sized page costs this many requests to the relation store")
	require.Equal(t, wantTuples, f.nTuples.Load(),
		"the same tuples are asked about as the per-object shape asked about — "+
			"fewer messages, not a different question")

	for _, sz := range f.observedBatchSizes() {
		require.LessOrEqual(t, sz, MaxBatchChecksPerRequest,
			"no partition may exceed the store's cap; the store refuses an over-cap "+
				"partition outright, so an over-cap partition is a failed page, not a slow one")
	}

	t.Logf("page=%d ids | relations=%d | partition cap=%d | requests=%d (was %d per-object) | "+
		"tuples=%d (unchanged) | in-flight batch bound=%d",
		len(ids), len(rels), MaxBatchChecksPerRequest, f.nBatch.Load(),
		int64(len(rels))*validate.MaxPageSize, f.nTuples.Load(), BatchParallelism)
}

// TestVisibleSet_BatchesRunConcurrently — the partitions of one page must not be
// issued one after another.
//
// This is the condition that makes the count above a time budget the REQUEST can
// meet. Twenty partitions run in sequence at 20ms each is 400ms per relation
// round for a page the contract explicitly permits; the same twenty overlapped is
// one round-trip plus scheduling. The assertion is on observed overlap, not on
// elapsed time, so it states the property rather than the speed of this machine.
func TestVisibleSet_BatchesRunConcurrently(t *testing.T) {
	ids, granted := worstCasePage()
	f := newFakeBatchChecker(granted...)
	f.sleep = 5 * time.Millisecond // long enough that sequential issue is observable

	_, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.NoError(t, err)

	require.Greater(t, f.observedMaxInFlightBatches(), 1,
		"partitions of one page ran one after another; the time budget belongs to the "+
			"request, and a page the contract allows must not be paid for serially")
	require.LessOrEqual(t, f.observedMaxInFlightBatches(), BatchParallelism,
		"in-flight partitions must stay inside the declared bound")
}

// TestVisibleSet_BatchCapableCheckerIsNeverAskedPerObject — the gate.
//
// The number in TestVisibleSet_BatchedWorstCasePageCost is a property of the code
// path a batch-capable checker takes. Nothing about correctness would change if
// that path were removed: the per-object fallback returns the same verdict, and
// every other test in this package would stay green while a deployment quietly
// went back to 2000 round-trips per page. So the property is asserted directly,
// and in both directions:
//
//   - a checker that CAN answer in batches is asked ONLY in batches (this test);
//   - a checker that CANNOT is still answered, per object, without error
//     (TestVisibleSet_NonBatchCheckerStillResolvesPerObject) — the fallback is
//     legitimate and must not be gated away.
//
// Injecting the defect (deleting the batch branch in VisibleSet) reddens the
// first and leaves the second green, which is what distinguishes this gate from
// one that merely asserts a page resolves.
func TestVisibleSet_BatchCapableCheckerIsNeverAskedPerObject(t *testing.T) {
	f := newFakeBatchChecker(RelationsFor("t")[0] + "|t:a")

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", []string{"a", "b", "c"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"a": true}, got)

	require.Zero(t, f.nSingle.Load(),
		"VisibleSet asked a batch-capable checker %d per-object questions; the batch door "+
			"exists precisely so a page is not paid for row by row", f.nSingle.Load())
	require.Positive(t, f.nBatch.Load(), "the batch door was not used at all")
}

// TestVisibleSet_NonBatchCheckerStillResolvesPerObject — the legitimate twin.
//
// A checker without the capability is not a defect: the port is optional by
// design (the package must stay a leaf, and the in-process fakes of eight
// use-case test suites implement only the narrow shape). The gate above must not
// be satisfiable by refusing such a checker.
func TestVisibleSet_NonBatchCheckerStillResolvesPerObject(t *testing.T) {
	f := newFakeChecker(RelationsFor("t")[0]+"|t:a", RelationsFor("t")[len(RelationsFor("t"))-1]+"|t:c")

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", []string{"a", "b", "c"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"a": true, "c": true}, got,
		"the per-object fallback must resolve the same predicate")
	require.Positive(t, f.nCalls.Load(), "the fallback must actually ask")
}

// TestVisibleSet_BatchErrorFailsTheWholePage — fail-closed survives the new shape.
//
// A partially-resolved page is the failure mode that matters here: nineteen
// partitions answered and one refused would, if the refusal were dropped, produce
// a page that is silently short. Under-reporting a page is indistinguishable from
// "those rows do not exist", so it must be an error.
func TestVisibleSet_BatchErrorFailsTheWholePage(t *testing.T) {
	sentinel := errors.New("relation store refused")
	ids, granted := worstCasePage()
	f := newFakeBatchChecker(granted...)
	f.batchErr = sentinel

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, got, "a partially-resolved page must never be handed back as the answer")
	require.Zero(t, f.nSingle.Load(),
		"a refusing batch door must not be papered over by falling back to per-object "+
			"questions: that would turn one loud refusal into 2000 quiet ones")
}

// TestVisibleSet_OverCapPartitionIsNeverIssued — the partition size is the
// STORE's cap, not ours.
//
// iam publishes its own BatchCheck at 100 per request, and that number is about a
// sibling service's page arriving at iam. The relation store behind iam refuses
// anything over its own cap, so splitting a page against the published 100 would
// make every partition a refusal. The stub refuses over-cap partitions for the
// same reason the store does, so this asserts the split is against the right
// number.
func TestVisibleSet_OverCapPartitionIsNeverIssued(t *testing.T) {
	ids, granted := worstCasePage()
	f := newFakeBatchChecker(granted...)
	f.maxBatch = MaxBatchChecksPerRequest // the store's cap, restated as the stub's

	_, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.NoError(t, err, "a partition exceeded the store's cap and was refused")

	require.NotEmpty(t, f.observedBatchSizes())
	for _, sz := range f.observedBatchSizes() {
		require.LessOrEqual(t, sz, MaxBatchChecksPerRequest)
	}
}

// TestVisibleSet_PageSizeIsNotNarrowedToFitTheBudget — page_size is contract.
//
// The forbidden shortcut for a page that costs too much is to make the page
// smaller. This asserts every id of a contract-sized page gets an answer, so a
// future "cap the page at what one partition holds" cannot land quietly.
func TestVisibleSet_PageSizeIsNotNarrowedToFitTheBudget(t *testing.T) {
	ids, granted := worstCasePage()
	f := newFakeBatchChecker(granted...)

	got, err := VisibleSet(context.Background(), f, "user:u1", "t", ids)
	require.NoError(t, err)
	require.Len(t, got, len(ids),
		"every id of a contract-sized page must be answered; narrowing the page to fit a "+
			"budget is the one cure that is forbidden")
	require.EqualValues(t, int64(len(RelationsFor("t")))*validate.MaxPageSize, f.nTuples.Load())
}
