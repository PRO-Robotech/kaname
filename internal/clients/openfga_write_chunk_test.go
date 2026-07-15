// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_write_chunk_test.go — RED→GREEN proof of the Contract-A flat
// read-after-write tail fix (#232, iam-access-binding last red class).
//
// ROOT CAUSE: the reconciler's create-path synchronous OpenFGA write
// (reconcile.applyAfterCommit → RelationStore.WriteTuples) sends the ENTIRE
// collected tuple-set of one ReconcileObject pass in a SINGLE OpenFGA /write
// request. When ReconcileObject("iam.accessBinding", id) fans out over MULTIPLE
// bounded `*.*` ARM_ANCHOR bindings (the account OWNER binding + the freshly-granted
// grantee's `*.*` view binding) on a populated account, the combined batch exceeds
// OpenFGA's default maxTuplesPerWrite (100). OpenFGA rejects the WHOLE request with a
// 400 validation_error, so NONE of the tuples land — including the owner's viewer/
// admin tuple on the new iam_access_binding. applyAfterCommit logs-and-swallows the
// error (best-effort), so the immediate GET races the async drainer (which applies
// row-by-row, never hitting the limit) and gets 403. The other resource suites
// (account/group/role) pass because their ReconcileObject fan-out stays under 100.
//
// FIX: OpenFGAHTTPClient.WriteTuples/DeleteTuples chunk into ≤maxTuplesPerWriteRequest
// batches so a large fan-out is applied across several requests. This test emulates
// OpenFGA's per-request limit with an httptest server: an un-chunked single >100-tuple
// write is rejected (RED on the base client), the chunked client succeeds and applies
// every tuple (GREEN).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// openfgaLimitServer emulates the OpenFGA /write endpoint enforcing
// maxTuplesPerWrite: a single request carrying more than `limit` tuple_keys is
// rejected with HTTP 400 validation_error (the exact failure the un-chunked client
// hits in production); within-limit requests succeed and the tuples are recorded so
// the test can assert every tuple was applied across the chunked requests.
type openfgaLimitServer struct {
	limit    int
	srv      *httptest.Server
	applied  map[string]struct{}
	requests int
}

func newOpenFGALimitServer(t *testing.T, limit int) *openfgaLimitServer {
	t.Helper()
	s := &openfgaLimitServer{limit: limit, applied: make(map[string]struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, r *http.Request) {
		// Only the /write path is exercised here.
		if !strings.HasSuffix(r.URL.Path, "/write") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var body struct {
			Writes *struct {
				TupleKeys []struct {
					User     string `json:"user"`
					Relation string `json:"relation"`
					Object   string `json:"object"`
				} `json:"tuple_keys"`
			} `json:"writes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.requests++
		keys := []struct {
			User     string `json:"user"`
			Relation string `json:"relation"`
			Object   string `json:"object"`
		}{}
		if body.Writes != nil {
			keys = body.Writes.TupleKeys
		}
		if len(keys) > s.limit {
			// Mirror OpenFGA's wire reply for an over-limit write.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"validation_error","message":"the number of tuples in the write exceeds the maximum allowed"}`))
			return
		}
		for _, k := range keys {
			s.applied[k.User+"|"+k.Relation+"|"+k.Object] = struct{}{}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// endpoint returns host:port (no scheme — OpenFGAHTTPClient prefixes http:// itself).
func (s *openfgaLimitServer) endpoint() string {
	return strings.TrimPrefix(s.srv.URL, "http://")
}

// TestOpenFGAHTTPClient_WriteTuples_ChunksOverLimit asserts a single WriteTuples call
// carrying MORE tuples than OpenFGA's per-request limit is applied across multiple
// chunked requests (every tuple lands), instead of being rejected wholesale. RED on
// the un-chunked base client (one >100-tuple request → 400 → error, 0 tuples applied);
// GREEN once WriteTuples chunks.
func TestOpenFGAHTTPClient_WriteTuples_ChunksOverLimit(t *testing.T) {
	const limit = 100
	srv := newOpenFGALimitServer(t, limit)
	c := &clients.OpenFGAHTTPClient{
		Endpoint:           srv.endpoint(),
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
	}

	// 250 distinct tuples — well over the 100-per-request limit. With chunking this
	// is 3 requests (100+100+50); un-chunked it is one rejected 400.
	const n = 250
	tuples := make([]clients.RelationTuple, 0, n)
	for i := 0; i < n; i++ {
		tuples = append(tuples, clients.RelationTuple{
			User:     "user:usr_chunk_" + itoa(i),
			Relation: "viewer",
			Object:   "iam_access_binding:acb_chunk_" + itoa(i),
		})
	}

	if err := c.WriteTuples(context.Background(), tuples); err != nil {
		t.Fatalf("WriteTuples(%d) must succeed by chunking under the %d-per-request "+
			"OpenFGA limit, got error: %v", n, limit, err)
	}
	if got := len(srv.applied); got != n {
		t.Fatalf("expected all %d tuples applied across chunked requests, got %d "+
			"(requests=%d) — an un-chunked single write is rejected wholesale", n, got, srv.requests)
	}
}

// itoa is a tiny strconv.Itoa avoiding the import churn in this focused test file.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
