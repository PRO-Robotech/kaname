// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_batchcheck_test.go — the wire contract of the batched relation
// question, pinned against a stub that answers the way the deployed store
// answers.
//
// The shapes asserted here were read off openfga/openfga:v1.14.0 on the running
// stand rather than taken from documentation: a request of 51 tuples is answered
// `{"code":"validation_error","message":"batchCheck received 51 checks, the
// maximum allowed is 50"}` with HTTP 400, a request of 50 is answered HTTP 200,
// and the response body is `{"result":{"<correlation_id>":{"allowed":bool}}}` —
// a MAP, not an array, which is why alignment with the request has to be done by
// correlation id and why getting that wrong would silently misattribute verdicts
// to the wrong objects.
package clients

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
)

// batchStub — an OpenFGA-shaped HTTP stub for the batch-check endpoint only.
type batchStub struct {
	srv *httptest.Server
	// granted — "<relation>|<object>" the stub allows.
	granted map[string]bool
	// maxChecks — the stub's cap, mirroring the store's server-side one.
	maxChecks int
	// status — forced HTTP status; 0 means answer normally.
	status int
	// dropOne — answer one fewer verdict than asked, to prove a misaligned answer
	// is refused rather than silently zero-filled.
	dropOne bool

	nBatch  atomic.Int64
	nSingle atomic.Int64
}

func newBatchStub(t *testing.T, granted ...string) *batchStub {
	t.Helper()
	s := &batchStub{granted: map[string]bool{}, maxChecks: 50}
	for _, g := range granted {
		s.granted[g] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/st1/batch-check", func(w http.ResponseWriter, r *http.Request) {
		s.nBatch.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Checks []struct {
				TupleKey struct {
					User, Relation, Object string
				} `json:"tuple_key"`
				CorrelationID string `json:"correlation_id"`
			} `json:"checks"`
		}
		_ = json.Unmarshal(body, &req)
		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(`{"code":"internal_error","message":"forced"}`))
			return
		}
		if len(req.Checks) > s.maxChecks {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w,
				`{"code":"validation_error","message":"batchCheck received %d checks, the maximum allowed is %d"}`,
				len(req.Checks), s.maxChecks)
			return
		}
		out := map[string]map[string]bool{}
		for i, c := range req.Checks {
			if s.dropOne && i == 0 {
				continue
			}
			out[c.CorrelationID] = map[string]bool{
				"allowed": s.granted[c.TupleKey.Relation+"|"+c.TupleKey.Object],
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": out})
	})
	mux.HandleFunc("/stores/st1/check", func(w http.ResponseWriter, r *http.Request) {
		s.nSingle.Add(1)
		_, _ = w.Write([]byte(`{"allowed":false}`))
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *batchStub) client() *OpenFGAHTTPClient {
	return &OpenFGAHTTPClient{
		Endpoint: strings.TrimPrefix(s.srv.URL, "http://"),
		StoreID:  "st1",
	}
}

// TestOpenFGAHTTPClient_BatchCheckWithContext_VerdictsAlignWithObjects — the
// verdict for object i must be the verdict the store gave for object i.
//
// The response is keyed by correlation id, so this is not automatic: a naive
// implementation that iterates the response map and appends would return the
// right MULTISET of verdicts in an arbitrary order, which is worse than an error
// because the page would be filtered — plausibly — by someone else's answer. The
// grants below are deliberately asymmetric so any reordering shows.
func TestOpenFGAHTTPClient_BatchCheckWithContext_VerdictsAlignWithObjects(t *testing.T) {
	s := newBatchStub(t, "viewer|project:b", "viewer|project:d")
	c := s.client()

	objects := []string{"project:a", "project:b", "project:c", "project:d", "project:e"}
	got, err := c.BatchCheckWithContext(t.Context(), "user:u1", "viewer", objects, nil)
	require.NoError(t, err)
	require.Equal(t, []bool{false, true, false, true, false}, got,
		"verdicts must be positional against the objects asked about")
	require.EqualValues(t, 1, s.nBatch.Load(), "one request for the whole set")
	require.EqualValues(t, 0, s.nSingle.Load(), "the per-object endpoint must not be touched")
}

// TestOpenFGAHTTPClient_BatchCheckWithContext_OverCapIsRefused — the client must
// not hand the store more than it accepts.
//
// The store refuses an over-cap request with a 400; the client must surface that
// as an error. It must NOT be mapped to the "a 400 means a clean deny" rule the
// single Check uses — that rule is about a tuple that can never resolve, whereas
// this 400 is about the REQUEST, and treating it as a deny would turn a
// configuration fault into a page of silent denials.
func TestOpenFGAHTTPClient_BatchCheckWithContext_OverCapIsRefused(t *testing.T) {
	s := newBatchStub(t)
	c := s.client()

	objects := make([]string, authzfilter.MaxBatchChecksPerRequest+1)
	for i := range objects {
		objects[i] = fmt.Sprintf("project:p%d", i)
	}
	got, err := c.BatchCheckWithContext(t.Context(), "user:u1", "viewer", objects, nil)
	require.Error(t, err, "an over-cap request must be an error, never a page of denials")
	require.Nil(t, got)
	require.Contains(t, err.Error(), "maximum allowed",
		"the store's own words identify this as a request fault, not an outage")
}

// TestOpenFGAHTTPClient_BatchCheckWithContext_MisalignedAnswerIsRefused — a
// response missing a verdict is an error, not a deny.
func TestOpenFGAHTTPClient_BatchCheckWithContext_MisalignedAnswerIsRefused(t *testing.T) {
	s := newBatchStub(t, "viewer|project:b")
	s.dropOne = true
	c := s.client()

	got, err := c.BatchCheckWithContext(t.Context(), "user:u1", "viewer",
		[]string{"project:a", "project:b"}, nil)
	require.Error(t, err)
	require.Nil(t, got)
}

// TestOpenFGAHTTPClient_BatchCheckWithContext_TransportFailureIsAnError — a 5xx
// fails the call rather than resolving to denials.
func TestOpenFGAHTTPClient_BatchCheckWithContext_TransportFailureIsAnError(t *testing.T) {
	s := newBatchStub(t)
	s.status = http.StatusInternalServerError
	c := s.client()

	got, err := c.BatchCheckWithContext(t.Context(), "user:u1", "viewer",
		[]string{"project:a"}, nil)
	require.Error(t, err)
	require.Nil(t, got)
}

// TestOpenFGAHTTPClient_BatchCheckWithContext_NotConfigured — same fail-closed
// posture as every sibling call.
func TestOpenFGAHTTPClient_BatchCheckWithContext_NotConfigured(t *testing.T) {
	c := &OpenFGAHTTPClient{}
	_, err := c.BatchCheckWithContext(t.Context(), "user:u1", "viewer", []string{"project:a"}, nil)
	require.ErrorIs(t, err, ErrNotConfigured)
}

// TestProductionCheckerSatisfiesTheVisibilityBatchPort — the wiring gate.
//
// authzfilter's batch path is taken only by a checker that implements the port,
// and the check is a type assertion at run time: if the production client ever
// stopped satisfying it, every List would keep returning correct pages while
// quietly costing 2000 round-trips again, and no test in authzfilter could
// notice — its fakes implement the port themselves.
//
// So the property is asserted where the two sides meet, on the concrete type the
// composition root builds, and additionally on the interface every use-case field
// is declared as: a ninth read surface cannot be wired with a non-batch checker
// without failing to compile.
func TestProductionCheckerSatisfiesTheVisibilityBatchPort(t *testing.T) {
	var _ authzfilter.ObjectChecker = (*OpenFGAHTTPClient)(nil)
	var _ authzfilter.BatchObjectChecker = (*OpenFGAHTTPClient)(nil)

	var rq RelationQueries = (*OpenFGAHTTPClient)(nil)
	_, ok := rq.(authzfilter.BatchObjectChecker)
	require.True(t, ok,
		"clients.RelationQueries is the declared type of every relationQueries field in "+
			"the read use-cases; if it does not carry the batch capability, a page reverts "+
			"to one round-trip per row with nothing to notice")
}

// TestBatchCapAgreesWithTheFilterPartitionSize — the two numbers that must match.
//
// The store's ceiling lives on the adapter (fgaMaxChecksPerBatchCheck) and the
// partition size lives on the filter (authzfilter.MaxBatchChecksPerRequest),
// deliberately: the adapter must not import the filter. Nothing else makes them
// agree, and a drift is silent in exactly one direction — a partition LARGER
// than the ceiling is refused by the store on every page, turning every List
// into an outage. Asserted here because this is the one place both are visible.
func TestBatchCapAgreesWithTheFilterPartitionSize(t *testing.T) {
	require.Equal(t, fgaMaxChecksPerBatchCheck, authzfilter.MaxBatchChecksPerRequest,
		"the partition size the filter splits a page against must not exceed the ceiling "+
			"the store enforces on one request")
}
