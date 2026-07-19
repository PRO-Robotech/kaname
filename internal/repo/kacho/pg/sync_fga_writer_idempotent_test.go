// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// sync_fga_writer_idempotent_test.go — unit test (no DB) for the IDEMPOTENCY of
// the syncFGAWriter create-path closer.
//
// ROOT CAUSE UNDER TEST (owner-403, GATE-RUN #2, 692× deferral): OpenFGA's Write
// is TRANSACTIONAL and NON-idempotent — it rejects the WHOLE batch (applying
// NONE of its tuples) with "cannot write a tuple which already exists" if ANY
// tuple in the batch pre-exists. Under at-least-once register / re-register
// (redelivery, account/cluster-scope re-materialization) owner tuples frequently
// pre-exist, so the previous per-object atomic Write failed wholesale and the
// FULL owner-set was deferred to the async drainer. op-done then did NOT imply a
// full grant → the creator got a 403 on delete/update/get of its own resource in
// the confirm-gate polling window.
//
// THE FIX (read-then-write-delta): on an already-exists conflict the writer reads
// the object's existing tuples for the subject, computes missing = desired −
// existing, and writes ONLY the missing tuples (which do not exist → no conflict,
// atomic apply). missing == ∅ ⇒ the full grant is already present (idempotent
// no-op success), so the object is NOT deferred. INVARIANT: after WriteTuples the
// FULL desired set is present in FGA (existing ∪ written), so op-done ⟹ full grant.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// idempotentFGAStore models OpenFGA's TRANSACTIONAL, NON-idempotent Write: a
// WriteTuples batch is rejected WHOLESALE (applying NONE of its tuples) if ANY
// tuple in it already exists — the exact production behavior from GATE-RUN #2:
//
//	openfga write: bad request: cannot write a tuple which already exists: …
//
// It also exposes ReadTuples (filtered by subject+object) so the read-delta path
// can compute missing = desired − existing. This is the ONLY fake that models the
// already-exists rejection; the sibling atomicRelationStore (sync_fga_writer_test.go)
// models transient write-contention instead, which is a distinct failure mode.
type idempotentFGAStore struct {
	mu       sync.Mutex
	existing map[clients.RelationTuple]struct{}
	writes   int
	reads    int

	// raceInject models a CONCURRENT writer (e.g. the async drainer applying the
	// SAME fga_outbox rows row-by-row) that lands these tuples into `existing`
	// exactly once, right AFTER the first ReadTuples returns — so the follow-up
	// missing-write hits already-exists on the raced-in tuples and the bounded
	// read-delta retry must re-read and converge on the residual.
	raceInject []clients.RelationTuple
	raceArmed  bool
}

func newIdempotentFGAStore(pre ...clients.RelationTuple) *idempotentFGAStore {
	m := make(map[clients.RelationTuple]struct{}, len(pre))
	for _, t := range pre {
		m[t] = struct{}{}
	}
	return &idempotentFGAStore{existing: m}
}

func (s *idempotentFGAStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *idempotentFGAStore) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	// Transactional: if ANY tuple already exists, reject the WHOLE batch and
	// apply NONE of it (OpenFGA all-or-nothing on conflict).
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

func (s *idempotentFGAStore) DeleteTuples(context.Context, []clients.RelationTuple) error {
	return nil
}

func (s *idempotentFGAStore) ReadTuples(_ context.Context, subjectFilter, relationFilter, objectFilter string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	var out []clients.ConditionalTuple
	for t := range s.existing {
		if subjectFilter != "" && t.User != subjectFilter {
			continue
		}
		if relationFilter != "" && t.Relation != relationFilter {
			continue
		}
		if objectFilter != "" && t.Object != objectFilter {
			continue
		}
		out = append(out, clients.ConditionalTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	// Deterministic benign-race injection: land raceInject exactly once, after the
	// FIRST read returns its (now-stale) snapshot.
	if s.raceArmed && len(s.raceInject) > 0 {
		s.raceArmed = false
		for _, t := range s.raceInject {
			s.existing[t] = struct{}{}
		}
	}
	return out, "", nil
}

func (s *idempotentFGAStore) has(t clients.RelationTuple) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.existing[t]
	return ok
}

func (s *idempotentFGAStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// grantTuples is ownerGrant projected to clients.RelationTuple (the persisted shape).
func grantTuples(subject, object string) []clients.RelationTuple {
	g := ownerGrant(subject, object) // defined in sync_fga_writer_test.go
	out := make([]clients.RelationTuple, 0, len(g))
	for _, t := range g {
		out = append(out, rt(t))
	}
	return out
}

const (
	idmpCreator = "user:usr_creator0000000000"
	idmpObject  = "iam_access_binding:acb_owner00000000000"
)

// TestSyncFGAWriter_PartPreExists_CompletesFullGrant is the core RED→GREEN proof.
// HALF the owner grant already exists (prior register / partial drainer progress).
// The previous behavior wrote the FULL set atomically → OpenFGA rejects the whole
// batch on the first pre-existing tuple → the whole owner-set is deferred to the
// drainer → the object is left with ONLY its pre-existing subset (partial). The
// read-delta fix writes the MISSING subset so the FULL grant is present.
func TestSyncFGAWriter_PartPreExists_CompletesFullGrant(t *testing.T) {
	grant := grantTuples(idmpCreator, idmpObject)
	// Pre-exist the first three verbs (v_get, v_list, v_create).
	store := newIdempotentFGAStore(grant[0], grant[1], grant[2])
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), ownerGrant(idmpCreator, idmpObject)); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}

	// INVARIANT: the FULL desired set is present (existing ∪ written) — NOT partial.
	for _, tup := range grant {
		if !store.has(tup) {
			t.Fatalf("owner-403 root cause: tuple %s#%s NOT present after write — "+
				"pre-existing conflict deferred the whole owner-set (op-done would NOT imply full grant)",
				tup.Object, tup.Relation)
		}
	}
}

// TestSyncFGAWriter_AllPreExist_NoOpSuccess — the whole owner grant already exists
// (re-register redelivery, the 692-deferral generator). The write must recognize
// completeness and NOT defer the object to the drainer (no per-object failure
// warning), staying a clean idempotent no-op success.
func TestSyncFGAWriter_AllPreExist_NoOpSuccess(t *testing.T) {
	grant := grantTuples(idmpCreator, idmpObject)
	store := newIdempotentFGAStore(grant...) // ALL pre-exist

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	w := kachopg.NewSyncFGAWriter(store, logger)

	if err := w.WriteTuples(context.Background(), ownerGrant(idmpCreator, idmpObject)); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal, got %v", err)
	}

	// Full grant present.
	for _, tup := range grant {
		if !store.has(tup) {
			t.Fatalf("pre-existing tuple %s#%s vanished", tup.Object, tup.Relation)
		}
	}
	// RED discriminator: the old code defers the whole owner-set (already-exists on
	// the atomic batch) and logs a per-object-failure WARN. The idempotent no-op
	// must log NOTHING — the grant is already complete.
	if n := strings.Count(buf.String(), "deferred"); n != 0 {
		t.Fatalf("all-pre-exist grant must be an idempotent no-op (no deferral), "+
			"got %d defer-warnings; log=%s", n, buf.String())
	}
}

// TestSyncFGAWriter_NonePreExist_NoRead — a genuinely-fresh object (no pre-existing
// tuple) lands via the packed fast path with NO read round-trip: read-delta must
// pay its read cost ONLY on an actual conflict, never on the clean create hot path.
func TestSyncFGAWriter_NonePreExist_NoRead(t *testing.T) {
	grant := grantTuples(idmpCreator, idmpObject)
	store := newIdempotentFGAStore() // empty — nothing pre-exists
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), ownerGrant(idmpCreator, idmpObject)); err != nil {
		t.Fatalf("clean WriteTuples must succeed, got %v", err)
	}
	for _, tup := range grant {
		if !store.has(tup) {
			t.Fatalf("clean batch must land every tuple; missing %s#%s", tup.Object, tup.Relation)
		}
	}
	if r := store.readCount(); r != 0 {
		t.Fatalf("clean create must NOT read (fast path); got %d reads", r)
	}
}

// TestSyncFGAWriter_BenignRace_ReReadConverges — a concurrent writer (async
// drainer) lands the missing subset between the read-delta's Read and its
// missing-Write, so the missing-Write hits already-exists on the raced-in tuples.
// The bounded retry must re-read and converge on the residual, leaving the FULL
// grant present. Proves the read-modify-write is race-idempotent (not a
// second-writer-wins TOCTOU).
func TestSyncFGAWriter_BenignRace_ReReadConverges(t *testing.T) {
	grant := grantTuples(idmpCreator, idmpObject)
	// Pre-exist the first three; the racer will land the LAST three right after our
	// first read, so our missing-write of them hits already-exists.
	store := newIdempotentFGAStore(grant[0], grant[1], grant[2])
	store.raceArmed = true
	store.raceInject = []clients.RelationTuple{grant[3], grant[4], grant[5]}
	w := kachopg.NewSyncFGAWriter(store, nil)

	if err := w.WriteTuples(context.Background(), ownerGrant(idmpCreator, idmpObject)); err != nil {
		t.Fatalf("WriteTuples must stay non-fatal under a benign race, got %v", err)
	}

	for _, tup := range grant {
		if !store.has(tup) {
			t.Fatalf("benign race left a partial grant: missing %s#%s", tup.Object, tup.Relation)
		}
	}
	// The bounded retry must have RE-READ after the raced already-exists (≥2 reads).
	if r := store.readCount(); r < 2 {
		t.Fatalf("benign race must trigger a re-read (bounded retry); got %d reads", r)
	}
}
