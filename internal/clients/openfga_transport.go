// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"net/http"
	"time"
)

// fgaMaxIdleConnsPerHost sizes the idle-connection pool the OpenFGA client keeps
// to the single OpenFGA host.
//
// It must exceed the number of OpenFGA calls this process can have in flight at
// once, which is the SUM of three independent sources:
//
//   - the fga_outbox drainer's apply fan-out (Config.ApplyConcurrency — one
//     concurrent write per row of a claim batch, sustained for the length of a
//     burst);
//   - the per-RPC authz Check on the hot request path, one per concurrently served
//     gRPC request;
//   - the reconciler's tuple reads/writes.
//
// Undersize it and the excess connections cannot be PARKED: each response tears its
// connection down and the next wave re-handshakes. That is what
// http.DefaultTransport does here — its MaxIdleConnsPerHost is 2, so at a fan-out
// of 16 fourteen connections are rebuilt per wave, and the cost is paid per apply,
// exactly when the queue is deepest. It also silently defeats the response-body
// draining the call sites do specifically so a connection CAN be reused.
//
// Oversizing is cheap and bounded: an idle connection is one file descriptor,
// nothing is pre-dialled, the pool only ever grows to real concurrency, and
// IdleConnTimeout reclaims what a quiet period leaves behind. Locked by
// TestOpenFGAHTTPClient_ReusesConnectionsUnderFanOut.
const fgaMaxIdleConnsPerHost = 256

// fgaHTTPClient is the shared HTTP client for every OpenFGA call in this package.
//
// It deliberately carries NO client-level Timeout: each call site applies its own
// per-operation deadline (CheckTimeout / ListTimeout / WriteTimeout) via
// context.WithTimeout, and those budgets differ by an order of magnitude (a 200ms
// hot-path Check versus a 1s write). A client Timeout would silently override the
// tighter ones and mask the per-operation contract those budgets encode.
var fgaHTTPClient = newFGAHTTPClient()

func newFGAHTTPClient() *http.Client {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Defensive: only reachable if something replaced http.DefaultTransport.
		// Fall back to a fresh transport rather than to the unpooled default.
		tr = &http.Transport{}
	}
	t := tr.Clone()
	t.MaxIdleConnsPerHost = fgaMaxIdleConnsPerHost
	if t.MaxIdleConns < fgaMaxIdleConnsPerHost {
		// MaxIdleConns is a process-wide cap across hosts; leaving it at the
		// default 100 would clamp the per-host pool back below the fan-out.
		t.MaxIdleConns = 2 * fgaMaxIdleConnsPerHost
	}
	t.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: t}
}
