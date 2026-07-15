// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_context_drain_test.go — RED→GREEN proof that the CEL-context-aware
// query paths that go through OpenFGAHTTPClient.do() (retryClient-wrapped)
// drain (capped) the response body on their non-OK branches before the deferred
// Close, so the keep-alive TCP connection returns to the http.Transport idle
// pool and is reused — mirroring the sibling drain in openfga_client.go Check()
// / writeOrDelete and openfga_list.go listUsersOfType.
//
// FAILURE (RED): each method returns on its non-OK branch WITHOUT reading the
// body; the deferred resp.Body.Close() on an undrained body makes net/http mark
// the persistent connection unreusable → every call opens a FRESH TCP
// connection. On the hot authz path (CheckWithContext backs both the public
// AuthorizeService.check and the internal CheckRelation gate the api-gateway
// fires for every tenant RPC), a degraded OpenFGA emitting a burst of 400/4xx
// then churns connections (fd + handshake pressure) exactly when FGA is already
// struggling. The test observes connection reuse (distinct RemoteAddr count) —
// a behavioural lock, not just an error-code check.
//
// Statuses are chosen to isolate the fixed branch from the retryClient retry
// layer: 400 (clean-deny branch) and 404 (< 500 ⇒ retryClient returns it
// immediately, no retry-churn confound). A 5xx would be retried and its
// intermediate bodies closed undrained by retryClient, which is a separate
// path outside these findings.

import (
	"context"
	"net/http"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

func newDrainTestClient(endpoint string) *clients.OpenFGAHTTPClient {
	return &clients.OpenFGAHTTPClient{Endpoint: endpoint, StoreID: "st_test", AuthorizationModel: "01MODEL"}
}

func TestCheckWithContext_DrainsBodyForConnReuse_400(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusBadRequest)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		// 400 → clean DENY (nil error); still must drain for reuse.
		allowed, err := c.CheckWithContext(context.Background(), "user:usr01", "viewer", "project:prj01", nil)
		if err != nil {
			t.Fatalf("400 must be a clean deny (nil error), got %v", err)
		}
		if allowed {
			t.Fatalf("400 must deny")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("CheckWithContext must drain the 400 body so the keep-alive connection is reused: "+
			"expected 1 distinct connection across %d calls, got %d (undrained body → churned connections)", n, got)
	}
}

func TestCheckWithContext_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusNotFound)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		if _, err := c.CheckWithContext(context.Background(), "user:usr01", "viewer", "project:prj01", nil); err == nil {
			t.Fatalf("non-200 must return an error")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("CheckWithContext must drain the non-200 body so the keep-alive connection is reused: "+
			"expected 1 distinct connection across %d calls, got %d (undrained body → churned connections)", n, got)
	}
}
