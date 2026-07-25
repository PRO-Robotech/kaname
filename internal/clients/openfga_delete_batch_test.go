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
	// rejectAll, when set, makes every request fail with a NON-idempotent 400 (a
	// genuine validation error) — the "must still surface an error" control.
	rejectAll bool
}

type fgaWriteBody struct {
	Deletes *struct {
		TupleKeys []struct {
			User     string `json:"user"`
			Relation string `json:"relation"`
			Object   string `json:"object"`
		} `json:"tuple_keys"`
	} `json:"deletes"`
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

func (s *fgaStoreServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// TestWriteTuples_BatchWithAnExistingTuple_IsNotSilentlySwallowed — the WRITE direction
// is deliberately NOT given the same treatment here: the reconciler's sync writer owns
// that case with a read-then-write-delta (it must know WHICH tuples are missing to keep
// a grant all-or-nothing per object), so the client must keep surfacing the rejection
// rather than reporting a partial grant as applied.
func TestWriteTuples_BatchWithAnExistingTuple_IsNotSilentlySwallowed(t *testing.T) {
	c := replyClient(badRequestServer(t, liveDuplicateWriteBody))
	err := c.WriteTuples(context.Background(), []clients.RelationTuple{liveTupleA, liveTupleB})
	if err == nil {
		t.Fatalf("a rejected multi-tuple WRITE applied nothing — it must not be reported as written")
	}
}
