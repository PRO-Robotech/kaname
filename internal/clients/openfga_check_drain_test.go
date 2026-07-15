// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_check_drain_test.go — RED→GREEN proof that OpenFGAHTTPClient.Check
// drains (capped) the response body on its non-2xx branches (400 clean-deny and
// non-200 error) before the deferred Close, so the keep-alive TCP connection is
// returned to the http.Transport idle pool and reused — mirroring the sibling
// drain patterns in openfga_client.go writeOrDelete (io.LimitReader+ReadFrom)
// and openfga_list.go listUsersOfType (io.Copy(io.Discard, io.LimitReader)).
//
// FAILURE (RED): Check returns on the 400 / non-200 branch WITHOUT reading the
// body. deferred resp.Body.Close() on an undrained body makes net/http mark the
// persistent connection unreusable → each Check opens a FRESH TCP connection.
// When OpenFGA is degraded and repeatedly emits 5xx/400 on the hot authz path,
// this churns connections (fd + TLS/handshake pressure) precisely when FGA is
// already struggling. The test observes connection reuse (distinct client
// RemoteAddr count) — a behavioural lock, not just an error-code check.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// countingStatusServer returns the given status with a non-trivial body and
// records the distinct client connection addresses (host:port) it observes. A
// reused keep-alive connection reports the SAME RemoteAddr across requests; a
// fresh dial reports a new ephemeral port.
func countingStatusServer(t *testing.T, status int) (endpoint string, distinctConns func() int) {
	t.Helper()
	// A realistic OpenFGA error body (well under the maxErrBodyBytes=4096 cap), so
	// the capped drain reaches EOF and the connection is eligible for reuse. A
	// pathologically huge body would exceed the cap and forfeit reuse by design —
	// that is the bounded-read tradeoff the sibling paths accept, not what we test.
	body := strings.Repeat("B", 256)
	var mu sync.Mutex
	seen := map[string]struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.RemoteAddr] = struct{}{}
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(seen)
	}
}

func TestCheck_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusInternalServerError)
	c := &clients.OpenFGAHTTPClient{Endpoint: endpoint, StoreID: "st_test", AuthorizationModel: "01MODEL"}

	const n = 5
	for i := 0; i < n; i++ {
		// 500 → error branch; allowed irrelevant. We only care about conn reuse.
		_, _ = c.Check(context.Background(), "user:usr01", "viewer", "project:prj01")
	}
	if got := distinct(); got != 1 {
		t.Fatalf("Check must drain the non-200 body so the keep-alive connection is reused: "+
			"expected 1 distinct connection across %d Checks, got %d (undrained body → churned connections)", n, got)
	}
}

func TestCheck_DrainsBodyForConnReuse_400(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusBadRequest)
	c := &clients.OpenFGAHTTPClient{Endpoint: endpoint, StoreID: "st_test", AuthorizationModel: "01MODEL"}

	const n = 5
	for i := 0; i < n; i++ {
		// 400 → clean DENY (nil error); still must drain for reuse.
		allowed, err := c.Check(context.Background(), "user:usr01", "viewer", "project:prj01")
		if err != nil {
			t.Fatalf("400 must be a clean deny (nil error), got %v", err)
		}
		if allowed {
			t.Fatalf("400 must deny")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("Check must drain the 400 body so the keep-alive connection is reused: "+
			"expected 1 distinct connection across %d Checks, got %d (undrained body → churned connections)", n, got)
	}
}
