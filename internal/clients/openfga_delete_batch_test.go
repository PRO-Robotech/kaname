// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_delete_batch_test.go — a revoke batch must not be impossible to apply.
//
// THE DEFECT (mirror image of the already-fixed write conflict, see the commit that
// introduced openfga_conflict.go). OpenFGA's /write is TRANSACTIONAL: a request whose
// deletes name even ONE tuple that is already absent is rejected wholesale and applies
// NOTHING. The access_binding revoke sends its whole emitted-set as one batch, and a
// partial drain — the async fga_outbox drainer applies the SAME rows one at a time —
// makes "one of them is already gone" the ORDINARY case, not an exotic one. Such a
// batch can then NEVER succeed: every replay hits the same absent tuple. The revoke
// burned its six bounded retries (~3s of worker time) and fell through to the async
// drainer EVERY time, and the still-live tuples of that batch were left in place
// meanwhile.
//
// THE RULE. "Already exists" / "already absent" proves the caller's post-condition
// only for a request carrying exactly ONE tuple; for a batch it proves the OTHERS did
// not land. So the fix is not to widen the shortcut — it is to REDUCE the batch to
// single-tuple deletes, exactly the shape the fga_outbox drainer applies, where the
// idempotent reading is sound tuple by tuple.
//
// These tests drive a STATE-carrying fake OpenFGA (rejects a delete naming an absent
// tuple, applies one naming only live tuples) and assert on the OBSERVABLE — which
// tuples are actually gone from the store afterwards — never on the code path.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// fgaStoreServer — a fake OpenFGA /write endpoint with REAL transactional delete
// semantics: the batch applies in full or not at all, and a delete naming a tuple that
// is not present is rejected with the deployed server's verbatim v1.14.0 body.
type fgaStoreServer struct {
	mu sync.Mutex
	// live tuples, keyed "user|relation|object".
	live map[string]struct{}
	// requests counts /write calls (how much the client had to decompose).
	requests int
	// reads counts /read calls — the grant-completion path's half of the work.
	reads int
	// rejectAll, when set, makes every request fail with a NON-idempotent 400 (a
	// genuine validation error) — the "must still surface an error" control.
	rejectAll bool
}

type fgaWireKeys struct {
	TupleKeys []struct {
		User     string `json:"user"`
		Relation string `json:"relation"`
		Object   string `json:"object"`
	} `json:"tuple_keys"`
}

type fgaWriteBody struct {
	Deletes *fgaWireKeys `json:"deletes"`
	Writes  *fgaWireKeys `json:"writes"`
}

func tupleKey(user, relation, object string) string { return user + "|" + relation + "|" + object }

func (s *fgaStoreServer) has(t clients.RelationTuple) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.live[tupleKey(t.User, t.Relation, t.Object)]
	return ok
}

func (s *fgaStoreServer) reqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// serveRead answers /read for the (subject, object) filter the grant-completion path
// uses. Without it the fake would report an EMPTY store to a caller about to decide what
// is missing — and a fake that lies about the state is exactly the "fixture more lenient
// than production" trap: the completion would rewrite tuples that are already there and
// the case would pass for the wrong reason.
func (s *fgaStoreServer) serveRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TupleKey *struct {
			User     string `json:"user"`
			Relation string `json:"relation"`
			Object   string `json:"object"`
		} `json:"tuple_key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++

	type wireKey struct {
		User     string `json:"user"`
		Relation string `json:"relation"`
		Object   string `json:"object"`
	}
	out := struct {
		Tuples []struct {
			Key wireKey `json:"key"`
		} `json:"tuples"`
		ContinuationToken string `json:"continuation_token"`
	}{}
	for k := range s.live {
		parts := strings.SplitN(k, "|", 3)
		if len(parts) != 3 {
			continue
		}
		if req.TupleKey != nil {
			if req.TupleKey.User != "" && req.TupleKey.User != parts[0] {
				continue
			}
			if req.TupleKey.Object != "" && req.TupleKey.Object != parts[2] {
				continue
			}
		}
		out.Tuples = append(out.Tuples, struct {
			Key wireKey `json:"key"`
		}{Key: wireKey{User: parts[0], Relation: parts[1], Object: parts[2]}})
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

func (s *fgaStoreServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/read") {
		s.serveRead(w, r)
		return
	}
	var body fgaWriteBody
	_ = json.NewDecoder(r.Body).Decode(&body)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++

	if s.rejectAll {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"validation_error","message":"invalid tuple: relation 'bogus' not found on type 'doc'"}`))
		return
	}
	// WRITE direction, same transactional semantics in mirror image: a batch naming
	// even ONE tuple that is already present is rejected wholesale, with the deployed
	// server's verbatim duplicate body. Modelling this is what makes the write test
	// assert an OUTCOME (which tuples ended up in the store) instead of a code path —
	// a fake that accepted duplicates could not tell a decomposing client from one
	// that silently dropped the batch.
	if body.Writes != nil && len(body.Writes.TupleKeys) > 0 {
		for _, k := range body.Writes.TupleKeys {
			if _, ok := s.live[tupleKey(k.User, k.Relation, k.Object)]; ok {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf(
					`{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists: user: '%s', relation: '%s', object: '%s': tuple to be written already existed or the tuple to be deleted did not exist"}`,
					k.User, k.Relation, k.Object)))
				return
			}
		}
		for _, k := range body.Writes.TupleKeys {
			s.live[tupleKey(k.User, k.Relation, k.Object)] = struct{}{}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	if body.Deletes == nil || len(body.Deletes.TupleKeys) == 0 {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	// TRANSACTIONAL: verify the WHOLE batch first; one absent tuple rejects everything.
	for _, k := range body.Deletes.TupleKeys {
		if _, ok := s.live[tupleKey(k.User, k.Relation, k.Object)]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist: user: '%s', relation: '%s', object: '%s': tuple to be written already existed or the tuple to be deleted did not exist"}`,
				k.User, k.Relation, k.Object)))
			return
		}
	}
	for _, k := range body.Deletes.TupleKeys {
		delete(s.live, tupleKey(k.User, k.Relation, k.Object))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func newFGAStoreServer(t *testing.T, s *fgaStoreServer) *clients.OpenFGAHTTPClient {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &clients.OpenFGAHTTPClient{
		Endpoint:           strings.TrimPrefix(srv.URL, "http://"),
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
		WriteTimeout:       500 * time.Millisecond,
	}
}

var (
	liveTupleA    = clients.RelationTuple{User: "user:u1", Relation: "v_get", Object: "doc:d1"}
	liveTupleB    = clients.RelationTuple{User: "user:u1", Relation: "v_update", Object: "doc:d1"}
	absentTupleC  = clients.RelationTuple{User: "user:u1", Relation: "v_delete", Object: "doc:d1"}
	absentTupleD  = clients.RelationTuple{User: "user:u1", Relation: "v_list", Object: "doc:d1"}
	revokeBatchAC = []clients.RelationTuple{liveTupleA, absentTupleC, liveTupleB, absentTupleD}
)

// TestDeleteTuples_BatchWithAnAlreadyAbsentTuple_StillRemovesTheLiveOnes — the core
// regression. A revoke batch mixing live and already-drained tuples must reach its
// post-condition (none of them live) instead of failing forever.
//
// RED before the fix: the transactional batch was replayed verbatim, rejected every
// time by the absent tuple, and liveTupleA/B stayed in the store — the revoke could
// only ever be completed by the async drainer.
func TestDeleteTuples_BatchWithAnAlreadyAbsentTuple_StillRemovesTheLiveOnes(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{
		tupleKey(liveTupleA.User, liveTupleA.Relation, liveTupleA.Object): {},
		tupleKey(liveTupleB.User, liveTupleB.Relation, liveTupleB.Object): {},
	}}
	c := newFGAStoreServer(t, store)

	if err := c.DeleteTuples(context.Background(), revokeBatchAC); err != nil {
		t.Fatalf("a revoke batch containing an already-absent tuple must still converge, got %v", err)
	}
	if store.has(liveTupleA) {
		t.Fatalf("the live tuple %v survived the revoke — a batch that can never apply left the grant standing", liveTupleA)
	}
	if store.has(liveTupleB) {
		t.Fatalf("the live tuple %v survived the revoke", liveTupleB)
	}
}

// TestDeleteTuples_FullyAbsentBatch_IsIdempotentSuccess — a batch whose tuples are ALL
// already gone (the async drainer got there first) is the caller's post-condition:
// success, no error, nothing left behind.
func TestDeleteTuples_FullyAbsentBatch_IsIdempotentSuccess(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{}}
	c := newFGAStoreServer(t, store)

	if err := c.DeleteTuples(context.Background(), []clients.RelationTuple{absentTupleC, absentTupleD}); err != nil {
		t.Fatalf("deleting tuples that are already gone is the desired post-condition, got %v", err)
	}
}

// TestDeleteTuples_AllLiveBatch_AppliedInOneRequest — the happy path stays a SINGLE
// transactional request: the decomposition is a fallback for the rejected batch, not
// the new normal (a per-tuple revoke on every call would multiply the request count of
// every teardown).
func TestDeleteTuples_AllLiveBatch_AppliedInOneRequest(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{
		tupleKey(liveTupleA.User, liveTupleA.Relation, liveTupleA.Object): {},
		tupleKey(liveTupleB.User, liveTupleB.Relation, liveTupleB.Object): {},
	}}
	c := newFGAStoreServer(t, store)

	if err := c.DeleteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB}); err != nil {
		t.Fatalf("an all-live batch must apply cleanly, got %v", err)
	}
	if n := store.reqCount(); n != 1 {
		t.Fatalf("an all-live batch must stay ONE transactional request, took %d", n)
	}
	if store.has(liveTupleA) || store.has(liveTupleB) {
		t.Fatalf("both tuples must be gone after a clean batch delete")
	}
}

// TestDeleteTuples_GenuineRejection_SurfacesError — direction discipline: a 400 that is
// NOT "already absent" (a real validation error) must still surface as an error. A
// revoke reported as applied while its tuples are live is an over-grant.
func TestDeleteTuples_GenuineRejection_SurfacesError(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{
		tupleKey(liveTupleA.User, liveTupleA.Relation, liveTupleA.Object): {},
	}, rejectAll: true}
	c := newFGAStoreServer(t, store)

	err := c.DeleteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB})
	if err == nil {
		t.Fatalf("a genuinely rejected delete must NOT be reported as a successful revoke")
	}
	if !store.has(liveTupleA) {
		t.Fatalf("nothing may have been removed by a rejected request (transactional)")
	}
}

// TestWriteTuples_BatchWithAnExistingTuple_LandsTheMissingOnes — the WRITE direction now
// gets the same treatment as the revoke, and for a reason the revoke did not have.
//
// The invariant is unchanged and is the one this file is about: a call that returns nil
// must mean the caller's post-condition holds. What changed is that a write batch is now
// a UNIT — one subject's whole relation set on one object — because a set split across
// requests is a grant a caller can observe half present. A batch rejected for naming one
// tuple that is already there is the ORDINARY outcome of the synchronous writer and the
// queue materialising the same grant; the batch can never succeed on replay, so reporting
// the rejection (the old behaviour) left the missing relations unwritten, and swallowing
// it would report a partial grant as whole. Decomposition does neither.
//
// Asserted on the OBSERVABLE: after the call, every tuple of the batch is in the store.
func TestWriteTuples_BatchWithAnExistingTuple_LandsTheMissingOnes(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{
		tupleKey(liveTupleA.User, liveTupleA.Relation, liveTupleA.Object): {},
	}}
	c := newFGAStoreServer(t, store)

	if err := c.WriteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB}); err != nil {
		t.Fatalf("a batch whose only fault is a pre-existing member must converge, got %v", err)
	}
	if !store.has(liveTupleA) || !store.has(liveTupleB) {
		t.Fatalf("both tuples must be present afterwards (A=%v B=%v)", store.has(liveTupleA), store.has(liveTupleB))
	}
	// The missing member lands in ONE further request, not one per tuple: the grant is
	// the unit, and a caller must never be able to observe half of it. Two writes total
	// (the rejected batch, then the missing subset) plus the read that decided what was
	// missing.
	if n := store.reqCount(); n != 2 {
		t.Fatalf("the completion must be ONE write of the missing subset: expected 2 writes, got %d", n)
	}
}

// TestWriteTuples_AllMissingBatch_AppliedInOneRequest — the positive control, and the
// half that keeps the decomposition a FALLBACK. Without it the test above would stay
// green on a client that abandoned batching entirely and wrote every grant tuple by
// tuple — which is the very shape (one relation per request) whose partial observations
// this change exists to remove.
func TestWriteTuples_AllMissingBatch_AppliedInOneRequest(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{}}
	c := newFGAStoreServer(t, store)

	if err := c.WriteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB}); err != nil {
		t.Fatalf("an all-missing batch must apply cleanly, got %v", err)
	}
	if n := store.reqCount(); n != 1 {
		t.Fatalf("an all-missing batch must stay ONE transactional request, took %d", n)
	}
	if !store.has(liveTupleA) || !store.has(liveTupleB) {
		t.Fatalf("both tuples must be present after a clean batch write")
	}
}

// TestWriteTuples_GenuineRejection_SurfacesError — direction discipline, mirror of the
// delete control: a 400 that is NOT "already exists" (a real validation error) must
// still surface. A grant reported as applied while nothing landed is an authz gap that
// the durable queue would never be told to retry.
func TestWriteTuples_GenuineRejection_SurfacesError(t *testing.T) {
	store := &fgaStoreServer{live: map[string]struct{}{}, rejectAll: true}
	c := newFGAStoreServer(t, store)

	err := c.WriteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB})
	if err == nil {
		t.Fatalf("a genuinely rejected write must NOT be reported as a successful grant")
	}
	if store.has(liveTupleA) || store.has(liveTupleB) {
		t.Fatalf("nothing may have been written by a rejected request (transactional)")
	}
}
