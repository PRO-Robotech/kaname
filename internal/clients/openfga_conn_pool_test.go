// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestOpenFGAHTTPClient_ReusesConnectionsUnderFanOut locks the OpenFGA transport to
// a connection pool sized for the way this client is actually called.
//
// # Why this is a throughput defect, not a style preference
//
// The fga_outbox drainer applies rows with ApplyConcurrency>1 — it fires that many
// OpenFGA writes CONCURRENTLY from one process, continuously, for the length of a
// burst. http.DefaultClient uses http.DefaultTransport, whose
// MaxIdleConnsPerHost is 2. So of N concurrent applies only 2 connections can be
// PARKED for reuse; every other response tears its connection down, and the next
// wave re-handshakes. The client's own code comments state the opposite intent —
// "must not also churn fresh TCP connections (fd + TLS/handshake pressure)", and
// they carefully drain response bodies so connections CAN be reused — but with the
// default transport there is nowhere for them to go. Draining a body into a pool
// that holds 2 of N is a no-op for the other N-2.
//
// # What is asserted (behaviour)
//
// Two successive waves of fanOut concurrent requests. The FIRST wave may open up to
// fanOut connections — that is the fan-out itself. The SECOND wave must open ZERO
// new ones: every connection from wave 1 must still be parked and reusable. With
// MaxIdleConnsPerHost=2 the second wave re-opens ~fanOut-2 connections and this
// fails. The test counts real accepted connections via httptest's ConnState hook,
// so it measures the transport's actual behaviour rather than reading a config
// field back.
func TestOpenFGAHTTPClient_ReusesConnectionsUnderFanOut(t *testing.T) {
	const fanOut = 16

	var opened atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold every request until the whole wave has arrived, so the wave is
		// genuinely concurrent and really does need fanOut connections.
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := &OpenFGAHTTPClient{
		Endpoint:     srv.Listener.Addr().String(),
		StoreID:      "store-pool-test",
		CheckTimeout: 5 * time.Second,
	}

	wave := func() {
		var wg sync.WaitGroup
		for i := 0; i < fanOut; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := c.Check(context.Background(),
					fmt.Sprintf("user:u%02d", i), "v_get", "vpc_network:net01")
				require.NoError(t, err)
			}(i)
		}
		wg.Wait()
	}

	wave()
	afterFirst := opened.Load()
	require.LessOrEqualf(t, afterFirst, int64(fanOut),
		"first wave opened %d connections for a fan-out of %d", afterFirst, fanOut)

	wave()
	afterSecond := opened.Load()

	require.Equalf(t, afterFirst, afterSecond,
		"the second wave of %d concurrent OpenFGA calls opened %d NEW connections: the "+
			"transport parks only a couple of idle connections, so a fan-out of %d tears down "+
			"and re-handshakes most of them on every wave. The drainer applies rows at exactly "+
			"this fan-out for the length of a burst — the churn is paid per apply, and it is "+
			"paid precisely when the queue is deepest.",
		fanOut, afterSecond-afterFirst, fanOut)
}
