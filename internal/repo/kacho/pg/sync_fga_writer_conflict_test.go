// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// sync_fga_writer_conflict_test.go — RED→GREEN proof that the per-object sync
// FGA writer materializes the grant under the PRODUCTION concurrency shape
// instead of dumping it on the async drainer.
//
// PRODUCTION SHAPE (why this concurrency is guaranteed, not exotic): every
// reconcile pass co-commits its tuples to kacho_iam.fga_outbox AND writes them
// synchronously post-commit (reconcile.applyAfterCommit → syncFGAWriter). The
// fga_outbox drainer is NOTIFY-driven, so the very same commit wakes it — and it
// re-applies the SAME tuples ROW-BY-ROW (one tuple per request, per-object FIFO).
// Two writers, one object, overlapping tuple sets, on EVERY create.
//
// OpenFGA (v1.14.0 + Postgres, the deployed version) answers such overlap with
// either
//
//	HTTP 400 "cannot write a tuple which already exists"  — the racer already landed it, or
//	HTTP 409 {"code":"Aborted","message":"transactional write failed due to conflict:
//	          one or more tuples to write were inserted by another transaction"}
//
// (both reproduced against a live server). A 409 applies NOTHING and is safe to
// retry verbatim.
//
// FAILURES LOCKED HERE (both observed in CI run 30135586348 on
// vpc_address:adr… — and downstream as the nlb address-bind 404 and the registry
// repo-create that retried 81× in 52s without converging):
//
//  1. "sync FGA per-object write failed — full tuple-set deferred to the async
//     drainer" + "openfga write: status 409": a conflict was not recognised, so
//     the object's FULL tuple-set was deferred WITHOUT A SINGLE RETRY.
//  2. "sync FGA delta did not converge for … after 4 rounds": the read-delta
//     loop's round budget was a flat 4 while the racing drainer lands ONE tuple
//     per round on a SIX-tuple grant — so the loop provably cannot outrun it.
//     The budget must be derived from the desired-set size (each already-exists
//     round proves ≥1 more desired tuple is present ⇒ `missing` strictly shrinks
//     ⇒ len(desired)+1 rounds always suffice), not from a magic constant.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

const (
	conflictCreator = "user:usr_creator0000000000"
	conflictObject  = "vpc_address:adrtdrpxy5b70zm6qk7w"
)

// errWriteConflict builds the error the PRODUCTION client surfaces for OpenFGA's
// HTTP 409 abort (clients.ErrWriteConflict wrapping the server's vocabulary).
func errWriteConflict() error {
	return fmt.Errorf("%w: %s", clients.ErrWriteConflict,
		`{"code":"Aborted","message":"transactional write failed due to conflict: one or more tuples to write were inserted by another transaction"}`)
}

// warnLogger returns a WARN-level logger writing into buf (defer / non-convergence
// warnings are the observable this file asserts on).
func warnLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. A transactional conflict must be RETRIED, never deferred outright.
// ─────────────────────────────────────────────────────────────────────────────

// conflictThenApplyStore models a racing writer that holds the store for the
// first `conflicts` write attempts (OpenFGA aborts them, applying nothing) and
// then lets go.
type conflictThenApplyStore struct {
	mu        sync.Mutex
	conflicts int
	writes    int
	existing  map[clients.RelationTuple]struct{}
}

func (s *conflictThenApplyStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *conflictThenApplyStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.conflicts > 0 {
		s.conflicts--
		return errWriteConflict() // aborted: applies NOTHING
	}
	if s.existing == nil {
		s.existing = make(map[clients.RelationTuple]struct{})
	}
	for _, t := range tuples {
		if _, dup := s.existing[t]; dup {
			return errors.New("openfga write: bad request: cannot write a tuple which already exists: " + t.Relation)
		}
	}
	for _, t := range tuples {
		s.existing[t] = struct{}{}
	}
	return nil
}

func (s *conflictThenApplyStore) DeleteTuples(context.Context, []clients.RelationTuple) error {
	return nil
}

func (s *conflictThenApplyStore) ReadTuplesStrong(_ context.Context, subj, rel, obj string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []clients.ConditionalTuple
	for t := range s.existing {
		if (subj == "" || t.User == subj) && (rel == "" || t.Relation == rel) && (obj == "" || t.Object == obj) {
			out = append(out, clients.ConditionalTuple{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	return out, "", nil
}

func (s *conflictThenApplyStore) has(t clients.RelationTuple) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.existing[t]
	return ok
}

// TestSyncFGAWriter_TransactionalConflict_RetriesInsteadOfDeferring — the core
// RED. A conflict means the racer won this round and NOTHING was written; the
// object must be retried, not shipped to the async drainer (whose per-object
// partition then backs off 1s→30s while the creator's grant stays invisible).
func TestSyncFGAWriter_TransactionalConflict_RetriesInsteadOfDeferring(t *testing.T) {
	grant := ownerGrant(conflictCreator, conflictObject)
	store := &conflictThenApplyStore{conflicts: 2}

	var buf bytes.Buffer
	w := kachopg.NewSyncFGAWriter(store, warnLogger(&buf))

	if err := w.WriteTuples(context.Background(), grant); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}
	for _, g := range grant {
		if !store.has(rt(g)) {
			t.Fatalf("conflict deferred the grant instead of retrying it: %s#%s never landed "+
				"(log=%s)", g.Object, g.Relation, buf.String())
		}
	}
	if strings.Contains(buf.String(), "deferred to the async drainer") {
		t.Fatalf("a transactional conflict is retryable — the object must NOT be deferred; log=%s", buf.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The read-delta loop must outrun the row-by-row drainer.
// ─────────────────────────────────────────────────────────────────────────────

// drainerRaceStore models the EXACT production self-competition: our batched
// write of the whole object races the fga_outbox drainer applying the SAME
// tuples ONE PER REQUEST. Every time we read, the drainer has landed exactly one
// more tuple — so our follow-up missing-write is rejected wholesale with
// already-exists, and the loop needs one round per drained tuple.
type drainerRaceStore struct {
	mu       sync.Mutex
	desired  []clients.RelationTuple // the order the drainer applies them in
	next     int                     // how many the drainer has already landed
	existing map[clients.RelationTuple]struct{}
	writes   int
	reads    int
}

// newDrainerRaceStore starts with the drainer ALREADY one tuple ahead (it drained
// the object's first outbox row before our post-commit batch reached OpenFGA), so
// our atomic whole-object write is rejected with already-exists and the read-delta
// loop takes over — with the drainer still landing one more tuple per round.
func newDrainerRaceStore(desired []clients.RelationTuple) *drainerRaceStore {
	s := &drainerRaceStore{desired: desired, existing: make(map[clients.RelationTuple]struct{})}
	if len(desired) > 0 {
		s.existing[desired[0]] = struct{}{}
		s.next = 1
	}
	return s
}

func (s *drainerRaceStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

// WriteTuples is transactional: any pre-existing tuple rejects the WHOLE batch.
func (s *drainerRaceStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	for _, t := range tuples {
		if _, ok := s.existing[t]; ok {
			return errors.New("openfga write: bad request: cannot write a tuple which already exists: " +
				t.User + ", relation:'" + t.Relation + "', object:'" + t.Object + "'")
		}
	}
	for _, t := range tuples {
		s.existing[t] = struct{}{}
	}
	return nil
}

func (s *drainerRaceStore) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

// ReadTuples returns the current snapshot and THEN lets the drainer land its next
// tuple — modelling a racer that keeps making progress between our read and our
// write, one outbox row at a time.
func (s *drainerRaceStore) ReadTuplesStrong(_ context.Context, subj, rel, obj string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	var out []clients.ConditionalTuple
	for t := range s.existing {
		if (subj == "" || t.User == subj) && (rel == "" || t.Relation == rel) && (obj == "" || t.Object == obj) {
			out = append(out, clients.ConditionalTuple{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	if s.next < len(s.desired) {
		s.existing[s.desired[s.next]] = struct{}{}
		s.next++
	}
	return out, "", nil
}

func (s *drainerRaceStore) missing(desired []clients.RelationTuple) []clients.RelationTuple {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []clients.RelationTuple
	for _, t := range desired {
		if _, ok := s.existing[t]; !ok {
			out = append(out, t)
		}
	}
	return out
}

// TestSyncFGAWriter_DrainerRacesEveryRound_StillConverges — RED for the flat
// `maxDeltaRounds = 4` budget: the racing drainer lands one of the SIX grant
// tuples per round, so four rounds provably cannot cover the set and the object
// is abandoned with "sync FGA delta did not converge … after 4 rounds". The
// budget must follow the desired-set size.
func TestSyncFGAWriter_DrainerRacesEveryRound_StillConverges(t *testing.T) {
	grant := ownerGrant(conflictCreator, conflictObject)
	desired := grantTuples(conflictCreator, conflictObject)
	store := newDrainerRaceStore(desired)

	var buf bytes.Buffer
	w := kachopg.NewSyncFGAWriter(store, warnLogger(&buf))

	if err := w.WriteTuples(context.Background(), grant); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}
	if miss := store.missing(desired); len(miss) != 0 {
		t.Fatalf("read-delta abandoned the object under the row-by-row drainer race: %d tuple(s) still missing (%v); log=%s",
			len(miss), miss, buf.String())
	}
	if strings.Contains(buf.String(), "did not converge") {
		t.Fatalf("the delta budget must be derived from the desired-set size, not a flat constant; log=%s", buf.String())
	}
	if strings.Contains(buf.String(), "deferred to the async drainer") {
		t.Fatalf("a converging race must not defer the object; log=%s", buf.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Behaviour under real concurrency (-race): many writers, same + distinct objects.
// ─────────────────────────────────────────────────────────────────────────────

// contendedFGAStore is a faithful OpenFGA model: a write is serialised, and a
// batch that overlaps a CONCURRENTLY-INFLIGHT batch is ABORTED (409, applies
// nothing); a batch overlapping an already-COMMITTED tuple is rejected 400
// already-exists.
type contendedFGAStore struct {
	mu       sync.Mutex
	inflight map[clients.RelationTuple]struct{}
	existing map[clients.RelationTuple]struct{}
}

func newContendedFGAStore() *contendedFGAStore {
	return &contendedFGAStore{
		inflight: make(map[clients.RelationTuple]struct{}),
		existing: make(map[clients.RelationTuple]struct{}),
	}
}

func (s *contendedFGAStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *contendedFGAStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	// Phase 1 — claim: abort if any tuple is already claimed by a concurrent tx.
	for _, t := range tuples {
		if _, busy := s.inflight[t]; busy {
			s.mu.Unlock()
			return errWriteConflict()
		}
	}
	for _, t := range tuples {
		if _, ok := s.existing[t]; ok {
			s.mu.Unlock()
			return errors.New("openfga write: bad request: cannot write a tuple which already exists: " + t.Relation)
		}
	}
	for _, t := range tuples {
		s.inflight[t] = struct{}{}
	}
	s.mu.Unlock()

	// Phase 2 — commit.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		delete(s.inflight, t)
		s.existing[t] = struct{}{}
	}
	return nil
}

func (s *contendedFGAStore) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

func (s *contendedFGAStore) ReadTuplesStrong(_ context.Context, subj, rel, obj string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []clients.ConditionalTuple
	for t := range s.existing {
		if (subj == "" || t.User == subj) && (rel == "" || t.Relation == rel) && (obj == "" || t.Object == obj) {
			out = append(out, clients.ConditionalTuple{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	return out, "", nil
}

func (s *contendedFGAStore) has(t clients.RelationTuple) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.existing[t]
	return ok
}

// TestSyncFGAWriter_ConcurrentMaterialization_NoDeferral — the observable-level
// proof, modelling the FULL production shape of one object's materialization:
//
//   - `writersPerObject` concurrent SYNC passes of the same object — the
//     post-register additive forward, the async worker's FULL ReconcileObject
//     backstop, the periodic sweep, and repeat RegisterResource on label updates.
//     They all derive the SAME desired set. These go through the writer, so the
//     per-object gate serialises them.
//   - `drainersPerObject` concurrent ROW-BY-ROW writers hitting the store DIRECTLY,
//     modelling the NOTIFY-woken fga_outbox drainer replaying the same tuples one
//     per request. These BYPASS the writer (as the real drainer does), so they are
//     the contention the gate cannot cover and the delta loop's backed-off conflict
//     rounds must absorb.
//
// Every object's grant must be fully present when the writers return, with no
// "deferred to the async drainer" and no "did not converge" in the log.
func TestSyncFGAWriter_ConcurrentMaterialization_NoDeferral(t *testing.T) {
	const (
		writersPerObject = 8
		objects          = 6
	)
	// One drainer per grant tuple — the outbox row-per-tuple shape. Derived from the
	// grant, not a constant: a literal 6 indexed grant[i] out of range the moment the
	// verb-set shrank by one (`v_create` withdrawn from the ordinary resource types).
	// The coupling was real and unstated, so it broke as a panic in a goroutine rather
	// than as an assertion.
	drainersPerObject := len(ownerGrant(conflictCreator, "vpc_address:adr0000000000000000"))
	if drainersPerObject == 0 {
		t.Fatal("empty grant — the contention this test creates would be nil")
	}
	store := newContendedFGAStore()

	var mu sync.Mutex
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&lockedWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	w := kachopg.NewSyncFGAWriter(store, logger)

	var wg sync.WaitGroup
	for o := range objects {
		object := fmt.Sprintf("vpc_address:adr%016d", o)
		grant := ownerGrant(conflictCreator, object)
		for range writersPerObject {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := w.WriteTuples(context.Background(), grant); err != nil {
					t.Errorf("WriteTuples must stay non-fatal, got %v", err)
				}
			}()
		}
		// The fga_outbox drainer: same tuples, ONE per request, straight at the store.
		// Its own failures are irrelevant (at-least-once, it retries) — it is here to
		// contend with the sync writer, exactly as in production.
		for i := range drainersPerObject {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_ = store.WriteTuples(context.Background(), []clients.RelationTuple{rt(grant[i])})
			}(i)
		}
	}
	wg.Wait()

	for o := range objects {
		object := fmt.Sprintf("vpc_address:adr%016d", o)
		for _, g := range ownerGrant(conflictCreator, object) {
			if !store.has(rt(g)) {
				t.Fatalf("concurrent materialization left %s#%s unmaterialized; log=%s",
					g.Object, g.Relation, buf.String())
			}
		}
	}
	mu.Lock()
	log := buf.String()
	mu.Unlock()
	if strings.Contains(log, "deferred to the async drainer") {
		t.Fatalf("per-object grants must materialize synchronously under contention, "+
			"not fall onto the async drainer; log=%s", log)
	}
	if strings.Contains(log, "did not converge") {
		t.Fatalf("the delta loop must converge under contention; log=%s", log)
	}
}

// lockedWriter serialises concurrent slog writes into the assertion buffer.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// compile-time guard: the fakes satisfy the production port the writer needs.
var (
	_ clients.RelationStore = (*conflictThenApplyStore)(nil)
	_ clients.RelationStore = (*drainerRaceStore)(nil)
	_ clients.RelationStore = (*contendedFGAStore)(nil)
	_                       = reconcile.SyncFGATuple{}
)

// TestSyncFGAWriter_UnrelentingConflict_TerminatesAndDefers — the budget must be a
// budget: a racer that never lets go (OpenFGA wedged in conflict) must NOT spin the
// delta loop; the object terminates on the conflict allowance and falls back to the
// durable async drainer, with the typed conflict surfaced for diagnosis.
func TestSyncFGAWriter_UnrelentingConflict_TerminatesAndDefers(t *testing.T) {
	grant := ownerGrant(conflictCreator, conflictObject)
	store := &conflictThenApplyStore{conflicts: 1 << 30} // never lets go

	var buf bytes.Buffer
	w := kachopg.NewSyncFGAWriter(store, warnLogger(&buf))

	done := make(chan error, 1)
	go func() { done <- w.WriteTuples(context.Background(), grant) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the delta loop must be BOUNDED — it spun on an unrelenting conflict")
	}
	if !strings.Contains(buf.String(), "deferred to the async drainer") {
		t.Fatalf("an unresolvable conflict must fall back to the durable drainer; log=%s", buf.String())
	}
	if !strings.Contains(buf.String(), "transactional conflict") {
		t.Fatalf("the deferral must name the typed conflict for diagnosis; log=%s", buf.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. A conflict round must WAIT — contention the per-object gate cannot cover.
// ─────────────────────────────────────────────────────────────────────────────

// timedConflictStore models the contention that BYPASSES the in-process gate (the
// fga_outbox drainer's row-by-row writes, another iam replica): a competing
// transaction holds the object for a fixed wall-clock window and every write
// during it is ABORTED. After the window the competitor has committed the FULL
// desired set — so a writer that actually WAITS finds `missing == ∅` and returns
// success, while a writer that retries instantly burns its whole conflict budget
// inside a few microseconds and abandons the object to the async drainer.
type timedConflictStore struct {
	mu        sync.Mutex
	releaseAt time.Time
	desired   []clients.RelationTuple
	existing  map[clients.RelationTuple]struct{}
}

func newTimedConflictStore(hold time.Duration, desired []clients.RelationTuple) *timedConflictStore {
	return &timedConflictStore{
		releaseAt: time.Now().Add(hold),
		desired:   desired,
		existing:  make(map[clients.RelationTuple]struct{}),
	}
}

func (s *timedConflictStore) held() bool { return time.Now().Before(s.releaseAt) }

func (s *timedConflictStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *timedConflictStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held() {
		return errWriteConflict()
	}
	for _, t := range tuples {
		if _, ok := s.existing[t]; ok {
			return errors.New("openfga write: bad request: cannot write a tuple which already exists: " + t.Relation)
		}
	}
	for _, t := range tuples {
		s.existing[t] = struct{}{}
	}
	return nil
}

func (s *timedConflictStore) DeleteTuples(context.Context, []clients.RelationTuple) error { return nil }

func (s *timedConflictStore) ReadTuplesStrong(_ context.Context, subj, rel, obj string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once the competitor's window closes, its commit is visible: the FULL desired
	// set is present (it materialized exactly what we wanted).
	if !s.held() {
		for _, t := range s.desired {
			s.existing[t] = struct{}{}
		}
	}
	var out []clients.ConditionalTuple
	for t := range s.existing {
		if (subj == "" || t.User == subj) && (rel == "" || t.Relation == rel) && (obj == "" || t.Object == obj) {
			out = append(out, clients.ConditionalTuple{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	return out, "", nil
}

// TestSyncFGAWriter_ConflictRoundsWait_OutlastCompetitor — RED without the wait.
// The competitor holds the object for `hold`, which is comfortably under the
// GUARANTEED minimum the backed-off conflict rounds span (half-jitter floors:
// 2.5 + 5 + 10 = 17.5ms) but astronomically above the microseconds four
// zero-wait rounds take. So the object is abandoned iff the rounds do not wait.
func TestSyncFGAWriter_ConflictRoundsWait_OutlastCompetitor(t *testing.T) {
	const hold = 12 * time.Millisecond
	desired := grantTuples(conflictCreator, conflictObject)
	store := newTimedConflictStore(hold, desired)

	var buf bytes.Buffer
	w := kachopg.NewSyncFGAWriter(store, warnLogger(&buf))

	if err := w.WriteTuples(context.Background(), ownerGrant(conflictCreator, conflictObject)); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}
	if strings.Contains(buf.String(), "deferred to the async drainer") {
		t.Fatalf("a conflict round must WAIT for the competing transaction instead of "+
			"burning the budget instantly; log=%s", buf.String())
	}
	// The competitor materialized the full desired set; the writer observed it
	// rather than duplicating (or abandoning) the work.
	have, _, err := store.ReadTuplesStrong(context.Background(), conflictCreator, "", conflictObject, 0, "")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(have) != len(desired) {
		t.Fatalf("expected the full grant (%d tuples) present after the competitor released, got %d",
			len(desired), len(have))
	}
}
