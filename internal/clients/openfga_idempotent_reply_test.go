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

// TestWriteTuples_MultiTupleBatch_AlreadyExists_IsNotSuccess — BATCH semantics.
// "This tuple already exists" is an idempotent SUCCESS only for a request that
// carried exactly ONE tuple: then the rejection literally means the desired
// post-condition holds. OpenFGA's write is TRANSACTIONAL, so for a MULTI-tuple
// batch the very same reply means the batch applied NOTHING — the other tuples
// did not land. Reporting success there would silently lose them (the sync
// writer would skip its read-delta reconciliation and the object's grant would
// stay partial / absent).
func TestWriteTuples_MultiTupleBatch_AlreadyExists_IsNotSuccess(t *testing.T) {
	c := replyClient(badRequestServer(t, liveDuplicateWriteBody))
	err := c.WriteTuples(context.Background(), []clients.RelationTuple{
		{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
		{User: "user:u1", Relation: "v_list", Object: "doc:d1"},
	})
	if err == nil {
		t.Fatalf("a rejected MULTI-tuple batch applied nothing — the un-applied tuples must not be reported as written")
	}
}

// TestDeleteTuples_MultiTupleBatch_CannotDelete_IsNotSuccess — the revoke mirror:
// a rejected multi-tuple delete removed NOTHING, so the still-live tuples must
// not be reported as revoked (that would be a silent over-grant).
func TestDeleteTuples_MultiTupleBatch_CannotDelete_IsNotSuccess(t *testing.T) {
	c := replyClient(badRequestServer(t, liveMissingDeleteBody))
	err := c.DeleteTuples(context.Background(), []clients.RelationTuple{
		{User: "user:u1", Relation: "v_get", Object: "doc:d1"},
		{User: "user:u1", Relation: "v_list", Object: "doc:d1"},
	})
	if err == nil {
		t.Fatalf("a rejected MULTI-tuple delete removed nothing — the surviving tuples must not be reported as revoked")
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
