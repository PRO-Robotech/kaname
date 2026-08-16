// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_idempotent_reply_test.go — RED→GREEN proof that the write paths
// recognise the IDEMPOTENT-REPLAY reply of the DEPLOYED OpenFGA.
//
// GROUND TRUTH (captured verbatim from openfga/openfga:v1.14.0, the umbrella
// chart's appVersion):
//
//	write duplicate → 400 {"code":"write_failed_due_to_invalid_input",
//	  "message":"cannot write a tuple which already exists: user: 'user:u1',
//	   relation: 'v_get', object: 'doc:d1': tuple to be written already existed
//	   or the tuple to be deleted did not exist"}
//	delete missing  → 400 {"code":"write_failed_due_to_invalid_input",
//	  "message":"cannot delete a tuple which does not exist: …<same trailer>"}
//
// FAILURE (RED): the client's idempotency check looked for the token
// "already_exists" (UNDERSCORE) — which this body does NOT contain anywhere. So
// every idempotent replay surfaced as a hard error to every direct caller
// (relationhook hierarchy-tuple write, RelationProjector, the InternalAuthorize
// admin WriteTuples RPC) and forced the reconciler's sync writer off its packed
// fast path onto the read-delta round-trip on EVERY re-register.
//
// Note the trailer is direction-AMBIGUOUS (it names both directions), so the
// discriminator must be the leading "cannot write a tuple" / "cannot delete a
// tuple" clause, not the trailer.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

const (
	// Verbatim v1.14.0 bodies.
	liveDuplicateWriteBody = `{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists: user: 'user:u1', relation: 'v_get', object: 'doc:d1': tuple to be written already existed or the tuple to be deleted did not exist"}`
	liveMissingDeleteBody  = `{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist: user: 'user:u1', relation: 'v_get', object: 'doc:d1': tuple to be written already existed or the tuple to be deleted did not exist"}`
)

func badRequestServer(t *testing.T, body string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// countingBadRequestServer is badRequestServer plus a request counter — the only way
// to tell "the client stopped at the rejected batch" from "the client decomposed and
// asked about each tuple", which is the whole difference this file's batch cases turn on.
func countingBadRequestServer(t *testing.T, body string) (string, func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func replyClient(endpoint string) *clients.OpenFGAHTTPClient {
	return &clients.OpenFGAHTTPClient{
		Endpoint: endpoint, StoreID: "store_test", AuthorizationModel: "model_test",
		WriteTimeout: 500 * time.Millisecond,
	}
}

var replyTuple = []clients.RelationTuple{
	{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
}

// TestWriteTuples_LiveDuplicateBody_IsIdempotentSuccess — writing a tuple that
// already exists means the desired post-condition holds: success, not an error.
func TestWriteTuples_LiveDuplicateBody_IsIdempotentSuccess(t *testing.T) {
	err := replyClient(badRequestServer(t, liveDuplicateWriteBody)).
		WriteTuples(context.Background(), replyTuple)
	if err != nil {
		t.Fatalf("the DEPLOYED OpenFGA duplicate-write reply must be idempotent success, got %v", err)
	}
}

// TestDeleteTuples_LiveMissingBody_IsIdempotentSuccess — deleting a tuple that is
// already gone is likewise the desired post-condition.
func TestDeleteTuples_LiveMissingBody_IsIdempotentSuccess(t *testing.T) {
	err := replyClient(badRequestServer(t, liveMissingDeleteBody)).
		DeleteTuples(context.Background(), replyTuple)
	if err != nil {
		t.Fatalf("the DEPLOYED OpenFGA missing-delete reply must be idempotent success, got %v", err)
	}
}

// TestWriteTuples_LiveMissingDeleteBody_IsNotWriteSuccess — direction discipline:
// a WRITE must never accept the DELETE-direction reply as success (the shared
// trailer names both directions, so a trailer-based match would wrongly pass).
func TestWriteTuples_LiveMissingDeleteBody_IsNotWriteSuccess(t *testing.T) {
	err := replyClient(badRequestServer(t, liveMissingDeleteBody)).
		WriteTuples(context.Background(), replyTuple)
	if err == nil {
		t.Fatalf("a delete-direction reply must NOT be swallowed as a successful write")
	}
}

// TestDeleteTuples_LiveDuplicateWriteBody_IsNotDeleteSuccess — the mirror image.
func TestDeleteTuples_LiveDuplicateWriteBody_IsNotDeleteSuccess(t *testing.T) {
	err := replyClient(badRequestServer(t, liveDuplicateWriteBody)).
		DeleteTuples(context.Background(), replyTuple)
	if err == nil {
		t.Fatalf("a write-direction reply must NOT be swallowed as a successful delete")
	}
}

// TestWriteConditionalTuples_SingleDirection_IsIdempotentSuccess — the raw path
// keeps idempotent replay when the request carries ONE direction.
func TestWriteConditionalTuples_SingleDirection_IsIdempotentSuccess(t *testing.T) {
	c := replyClient(badRequestServer(t, liveDuplicateWriteBody))
	if err := c.WriteConditionalTuples(context.Background(),
		[]clients.ConditionalTuple{{User: "user:u1", Relation: "v_get", Object: "doc:d1"}}, nil); err != nil {
		t.Fatalf("writes-only duplicate must be idempotent success, got %v", err)
	}
	c2 := replyClient(badRequestServer(t, liveMissingDeleteBody))
	if err := c2.WriteConditionalTuples(context.Background(), nil,
		[]clients.ConditionalTuple{{User: "user:u1", Relation: "v_get", Object: "doc:d1"}}); err != nil {
		t.Fatalf("deletes-only missing must be idempotent success, got %v", err)
	}
}

// TestWriteConditionalTuples_MixedBatch_RejectedIsNotSuccess — OpenFGA's write is
// TRANSACTIONAL: a rejected request applies NOTHING. For a MIXED batch
// (writes AND deletes — e.g. the InternalAuthorize admin WriteTuples RPC, or a
// binding's re-write as delete-old + add-new) a duplicate WRITE therefore also
// means the DELETES were not applied. Reporting success there would drop a
// revoke and leave an over-grant, and the RPC would report `deleted` for tuples
// that are still live.
func TestWriteConditionalTuples_MixedBatch_RejectedIsNotSuccess(t *testing.T) {
	c := replyClient(badRequestServer(t, liveDuplicateWriteBody))
	err := c.WriteConditionalTuples(context.Background(),
		[]clients.ConditionalTuple{{User: "user:u1", Relation: "v_get", Object: "doc:d1"}},
		[]clients.ConditionalTuple{{User: "user:u2", Relation: "v_get", Object: "doc:d1"}})
	if err == nil {
		t.Fatalf("a rejected MIXED batch applied nothing — the un-applied deletes must not be reported as success")
	}
}

// TestWriteTuples_MultiTupleBatch_AlreadyExists_IsNotSwallowedWholesale — BATCH
// semantics. "This tuple already exists" is an idempotent SUCCESS only for a request
// that carried exactly ONE tuple: then the rejection literally means the desired
// post-condition holds. OpenFGA's write is TRANSACTIONAL, so for a MULTI-tuple batch
// the very same reply means the batch applied NOTHING — the other tuples did not land,
// and treating the reply as success would silently lose them.
//
// Here EVERY request is rejected, the read included, so the client cannot establish what
// is actually present. The required outcome is then an ERROR: a grant reported as applied
// on the strength of a reply that proves nothing about the rest of the set is exactly the
// silent loss this case exists to forbid. The durable queue retries; a retired row does not.
//
// The converging counterpart, against a fake with real transactional state, is
// TestWriteTuples_BatchWithAnExistingTuple_LandsTheMissingOnes.
func TestWriteTuples_MultiTupleBatch_AlreadyExists_IsNotSwallowedWholesale(t *testing.T) {
	endpoint, count := countingBadRequestServer(t, liveDuplicateWriteBody)
	c := replyClient(endpoint)
	err := c.WriteTuples(context.Background(), []clients.RelationTuple{
		{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
		{User: "user:u1", Relation: "v_list", Object: "doc:d1"},
	})
	if err == nil {
		t.Fatalf("nothing was established about the set — reporting the grant as applied would lose it")
	}
	// The client did not stop at the rejected batch: it went on to ask what is present.
	// Without that step the count is 1, and the two tuples were never enquired about.
	if n := count(); n < 2 {
		t.Fatalf("the rejected batch must be followed by a read of the grant: got %d requests", n)
	}
}

// TestDeleteTuples_MultiTupleBatch_CannotDelete_ReducedToSingleTupleDeletes — the
// revoke mirror of the batch rule, and the point where the two directions part.
//
// The invariant is unchanged: a tuple that is still live must never be reported as
// revoked. What changed is HOW the client honours it. A rejected multi-tuple delete
// removed NOTHING and, unlike a 409, replaying it verbatim can never succeed (the
// absent tuple stays absent), so simply surfacing the error left the batch's live
// tuples standing and burned the revoke's whole retry budget. The client now reduces
// such a batch to SINGLE-tuple deletes, where "already absent" is a sound per-tuple
// success — so every tuple in the batch is genuinely dealt with.
//
// Here the stub answers "already absent" to EVERY request, so after decomposition
// every tuple's post-condition provably holds and success is correct. That the live
// ones are actually removed — the assertion this test cannot make against a stateless
// stub — is locked on the observable in
// openfga_delete_batch_test.go:TestDeleteTuples_BatchWithAnAlreadyAbsentTuple_StillRemovesTheLiveOnes,
// together with the control that a genuine (non-absent) rejection still errors.
func TestDeleteTuples_MultiTupleBatch_CannotDelete_ReducedToSingleTupleDeletes(t *testing.T) {
	c := replyClient(badRequestServer(t, liveMissingDeleteBody))
	err := c.DeleteTuples(context.Background(), []clients.RelationTuple{
		{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
		{User: "user:u1", Relation: "v_list", Object: "doc:d1"},
	})
	if err != nil {
		t.Fatalf("a delete batch every tuple of which is already absent must converge, not fail forever: %v", err)
	}
}

// TestWriteConditionalTuples_MultiTupleBatch_AlreadyExists_IsNotSuccess — same
// rule on the raw/admin path.
func TestWriteConditionalTuples_MultiTupleBatch_AlreadyExists_IsNotSuccess(t *testing.T) {
	c := replyClient(badRequestServer(t, liveDuplicateWriteBody))
	err := c.WriteConditionalTuples(context.Background(), []clients.ConditionalTuple{
		{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
		{User: "user:u1", Relation: "v_list", Object: "doc:d1"},
	}, nil)
	if err == nil {
		t.Fatalf("a rejected MULTI-tuple raw batch applied nothing — it must not be reported as success")
	}
}
