// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_conflict_test.go — RED→GREEN proof for OpenFGA's TRANSACTIONAL WRITE
// CONFLICT (HTTP 409).
//
// GROUND TRUTH (reproduced against openfga/openfga:v1.14.0 + Postgres datastore,
// the deployed umbrella version): two transactions writing OVERLAPPING tuple sets
// concurrently make OpenFGA abort one of them with
//
//	HTTP 409 {"code":"Aborted","message":"transactional write failed due to
//	          conflict: one or more tuples to write were inserted by another
//	          transaction"}
//
// NOTHING is applied by an aborted write, and the request is safe to retry
// verbatim. This is EXACTLY the production shape: for every created resource the
// post-commit sync writer (reconcile.applyAfterCommit → syncFGAWriter, whole
// object in one batch) races the NOTIFY-woken fga_outbox drainer re-applying the
// SAME tuples row-by-row.
//
// FAILURE (RED): the client read the response body ONLY for 400; every other
// status collapsed to a vocabulary-free `openfga write: status 409`. Nobody could
// classify it: the sync writer deferred the object's FULL tuple-set to the async
// drainer WITHOUT A SINGLE RETRY, and the drainer's applier fell through to
// "unclassified ⇒ transient" and backed off 1s→30s behind the per-object
// partition head — turning a millisecond conflict into tens of seconds of
// unmaterialized grant (observed: 52s, registry repo-create).
//
// FIX: 409 is read, retried a bounded number of times (a conflict is by
// definition transient and applies nothing), and — if it still stands — surfaced
// as a TYPED clients.ErrWriteConflict carrying OpenFGA's vocabulary.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// openfgaConflictBody is the VERBATIM 409 body of openfga/openfga:v1.14.0 on a
// transactional write conflict (captured from a live server).
const openfgaConflictBody = `{"code":"Aborted","message":"transactional write failed due to conflict: one or more tuples to write were inserted by another transaction"}`

// conflictServer replies 409 (transactional conflict) to the first `conflicts`
// write requests and 200 afterwards. `calls` counts every request received.
func conflictServer(t *testing.T, conflicts int32) (endpoint string, calls *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= conflicts {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(openfgaConflictBody))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &n
}

func conflictClient(endpoint string) *clients.OpenFGAHTTPClient {
	return &clients.OpenFGAHTTPClient{
		Endpoint:           endpoint,
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
		WriteTimeout:       500 * time.Millisecond,
	}
}

var conflictTuple = []clients.RelationTuple{
	{User: "user:usr_creator0000000000", Relation: "v_get", Object: "vpc_address:adr0000000000000000"},
}

// TestWriteTuples_Conflict_RetriedAndSucceeds — a transient conflict (the racing
// writer commits and goes away) must be absorbed INSIDE the write call. The
// caller sees success, so the object never falls off the synchronous
// materialization path onto the async drainer.
func TestWriteTuples_Conflict_RetriedAndSucceeds(t *testing.T) {
	ep, calls := conflictServer(t, 2) // two conflicts, then the write lands
	err := conflictClient(ep).WriteTuples(context.Background(), conflictTuple)
	if err != nil {
		t.Fatalf("a transactional conflict is retryable — WriteTuples must succeed, got %v", err)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("WriteTuples must RETRY the aborted write (nothing was applied); got %d attempt(s)", got)
	}
}

// TestDeleteTuples_Conflict_RetriedAndSucceeds — the revoke direction hits the
// same OpenFGA abort (a concurrent write/delete on the same tuples) and must be
// retried identically, or a revoke silently degrades to the async drain.
func TestDeleteTuples_Conflict_RetriedAndSucceeds(t *testing.T) {
	ep, calls := conflictServer(t, 2)
	err := conflictClient(ep).DeleteTuples(context.Background(), conflictTuple)
	if err != nil {
		t.Fatalf("a transactional conflict is retryable — DeleteTuples must succeed, got %v", err)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("DeleteTuples must RETRY the aborted delete; got %d attempt(s)", got)
	}
}

// TestWriteConditionalTuples_Conflict_RetriedAndSucceeds — the admin/raw write
// path shares the transport and must share the conflict semantics.
func TestWriteConditionalTuples_Conflict_RetriedAndSucceeds(t *testing.T) {
	ep, calls := conflictServer(t, 2)
	err := conflictClient(ep).WriteConditionalTuples(context.Background(),
		[]clients.ConditionalTuple{{User: "user:u1", Relation: "v_get", Object: "vpc_address:adr1"}}, nil)
	if err != nil {
		t.Fatalf("a transactional conflict is retryable — WriteConditionalTuples must succeed, got %v", err)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("WriteConditionalTuples must RETRY the aborted write; got %d attempt(s)", got)
	}
}

// TestWriteTuples_Conflict_Exhausted_TypedError — a conflict that outlives the
// bounded retry must surface as a TYPED, classifiable error carrying OpenFGA's
// vocabulary. A bare "openfga write: status 409" is unclassifiable: the sync
// writer cannot tell it from a genuine reject, and the drainer's applier cannot
// tell it from an unknown failure.
func TestWriteTuples_Conflict_Exhausted_TypedError(t *testing.T) {
	ep, _ := conflictServer(t, 1<<30) // never lets up
	err := conflictClient(ep).WriteTuples(context.Background(), conflictTuple)
	if err == nil {
		t.Fatalf("a permanent conflict must surface an error, got nil")
	}
	if !errors.Is(err, clients.ErrWriteConflict) {
		t.Fatalf("409 must be typed as clients.ErrWriteConflict (errors.Is), got %q", err)
	}
	if !strings.Contains(err.Error(), "transactional write failed due to conflict") {
		t.Fatalf("the 409 body vocabulary must be preserved in the error, got %q", err)
	}
}

// TestWriteTuples_Conflict_ErrorBodyCapped — the 409 body read must be bounded
// exactly like the 400 path (a misbehaving OpenFGA must not bloat the error/log
// line or spike memory).
func TestWriteTuples_Conflict_ErrorBodyCapped(t *testing.T) {
	big := strings.Repeat("A", 200*1024)
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(big))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	err := conflictClient(strings.TrimPrefix(srv.URL, "http://")).
		WriteTuples(context.Background(), conflictTuple)
	if err == nil {
		t.Fatalf("expected an error for an unrelenting 409, got nil")
	}
	if len(err.Error()) > bodyCapBytes+256 {
		t.Fatalf("the 409-body read must be capped at %d bytes, got error length %d",
			bodyCapBytes, len(err.Error()))
	}
}

// TestWriteTuples_Conflict_HonoursContextCancel — the bounded retry must never
// outlive the caller's context (the sync writer runs on a request-scoped ctx).
func TestWriteTuples_Conflict_HonoursContextCancel(t *testing.T) {
	ep, _ := conflictServer(t, 1<<30)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := conflictClient(ep).WriteTuples(ctx, conflictTuple)
	if err == nil {
		t.Fatalf("a cancelled context must abort the conflict retry, got nil error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// fga_outbox applier classification of the conflict
// ─────────────────────────────────────────────────────────────────────────────

// conflictStore — RelationStore whose write/delete always report OpenFGA's
// transactional conflict, exactly as the production client surfaces it.
type conflictStore struct{}

func (conflictStore) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (conflictStore) WriteTuples(context.Context, []clients.RelationTuple) error {
	return fmt.Errorf("%w: %s", clients.ErrWriteConflict, openfgaConflictBody)
}
func (conflictStore) DeleteTuples(context.Context, []clients.RelationTuple) error {
	return fmt.Errorf("%w: %s", clients.ErrWriteConflict, openfgaConflictBody)
}

// TestFGAApplier_Conflict_IsTransientNotAlreadyApplied — the drainer classification
// of an aborted write. A conflict applied NOTHING, so classifying it as
// ClassAlreadyApplied (what drainer/classify.go's comment used to claim for
// "FGA-409 on write") would mark the row sent_at and SILENTLY DROP the tuple —
// a permanent authz gap. It is equally not ClassPermanent: the retry is exactly
// what resolves it.
func TestFGAApplier_Conflict_IsTransientNotAlreadyApplied(t *testing.T) {
	apply := clients.NewFGAApplier(conflictStore{})
	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "v_get", Object: "vpc_address:adr1"}

	for _, evType := range []string{clients.FGAEventTypeWrite, clients.FGAEventTypeDelete} {
		err := apply(context.Background(), evType, ev)
		if err == nil {
			t.Fatalf("%s: an unresolved conflict must NOT be reported as applied", evType)
		}
		if got := drainer.Classify(err); got != drainer.ClassTransient {
			t.Fatalf("%s: an aborted write applied NOTHING — it must classify as %v (retry), got %v (err=%v)",
				evType, drainer.ClassTransient, got, err)
		}
	}
}
