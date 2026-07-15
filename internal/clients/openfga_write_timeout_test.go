// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_write_timeout_test.go — RED→GREEN regression lock for the audit r5
// finding: writeOrDelete (WriteTuples/DeleteTuples) issued its HTTP request
// via http.DefaultClient.Do on the raw caller ctx, never applying the
// configured WriteTimeout — unlike the sibling Check and
// WriteConditionalTuples, which already wrap ctx in
// context.WithTimeout(ctx, c.writeTimeout()). http.DefaultClient has no
// Timeout, so a TCP-accepted-but-unresponsive OpenFGA (GC pause / overload /
// half-open TCP) hangs the calling goroutine forever instead of failing
// within the configured FGA write budget — especially bad for the detached,
// deadline-less access_binding revoke retry loop (delete.go syncRemoveTuples),
// which has no caller-side deadline of its own to fall back on.
//
// This test drives WriteTuples against an httptest server whose handler
// blocks forever (never writes a response). Pre-fix, the call has no
// per-request deadline and does not return within the 2s test budget — the
// fix bounds it to ~WriteTimeout.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

func TestOpenFGAHTTPClient_WriteTuples_BoundedByWriteTimeout(t *testing.T) {
	// unblock — closing it releases the handler goroutine so the httptest
	// server can shut down cleanly at the end of the test (whichever path —
	// RED-hang or GREEN-timeout — the test takes).
	unblock := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-unblock:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(unblock)

	const writeTimeout = 50 * time.Millisecond
	c := &clients.OpenFGAHTTPClient{
		Endpoint:           strings.TrimPrefix(srv.URL, "http://"),
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
		WriteTimeout:       writeTimeout,
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- c.WriteTuples(context.Background(), []clients.RelationTuple{
			{User: "user:usr_timeout_test", Relation: "viewer", Object: "project:prj_timeout_test"},
		})
	}()

	const testBudget = 2 * time.Second
	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected WriteTuples to fail against a server that never responds, got nil error")
		}
		// Generous upper bound (CI jitter) but far under testBudget: proves the
		// call is bounded by ~WriteTimeout, not by the unresponsive server.
		if elapsed > 20*writeTimeout {
			t.Fatalf("WriteTuples took %v to fail, want roughly the configured WriteTimeout (%v) — "+
				"per-call deadline not applied tightly enough", elapsed, writeTimeout)
		}
	case <-time.After(testBudget):
		t.Fatalf("WriteTuples did not return within %v against an unresponsive OpenFGA — "+
			"http.DefaultClient.Do has no per-call deadline; writeOrDelete must wrap ctx in "+
			"context.WithTimeout(ctx, c.writeTimeout()) like the sibling Check/WriteConditionalTuples", testBudget)
	}
}
