// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openfga_consistency_test.go — RED→GREEN proof of the owner-tuple confirm-gate
// tail-latency fix (Koren-1 / plan D3 HIGHER_CONSISTENCY).
//
// CONFIRMED ROOT CAUSE: the owner-tuple is written SYNCHRONOUSLY to OpenFGA on the
// create path (reconcile.WithSyncFGA), but the confirm-probe reads it back through
// InternalIAMService.Check → OpenFGA `Check` with the DEFAULT consistency
// (MINIMIZE_LATENCY). Under the deployed multi-replica OpenFGA (replicaCount=2,
// shared Postgres, behind a ClusterIP) the confirm read can land on a DIFFERENT
// replica than the sync write and be served a STALE negative from that replica's
// cache for seconds — the confirm-op tail (p95=3.1s, max~10s). Passing
// consistency=HIGHER_CONSISTENCY makes OpenFGA bypass the cache / replica lag and
// resolve the just-written tuple on the FIRST attempt.
//
// This simulates the lag at the wire boundary: a fake OpenFGA that returns a stale
// negative for a default read and the fresh tuple for a HIGHER_CONSISTENCY read.

// newStaleReplicaFGA returns a client pointed at a fake OpenFGA modelling
// read-after-write lag: a default (MINIMIZE_LATENCY / unset) /check reads the STALE
// replica → allowed=false; a HIGHER_CONSISTENCY /check reads fresh → allowed=true.
// The captured slice records the `consistency` field of every /check request.
func newStaleReplicaFGA(t *testing.T) (*OpenFGAHTTPClient, *[]string) {
	t.Helper()
	seen := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/check") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			Consistency string `json:"consistency"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		*seen = append(*seen, body.Consistency)
		// HIGHER_CONSISTENCY bypasses the stale replica cache → fresh ALLOW; any
		// weaker/default read is served the stale negative.
		allowed := body.Consistency == "HIGHER_CONSISTENCY"
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"allowed":%v}`, allowed)
	}))
	t.Cleanup(srv.Close)
	return &OpenFGAHTTPClient{
		Endpoint: strings.TrimPrefix(srv.URL, "http://"),
		StoreID:  "store-test",
	}, seen
}

// Default Check hits the stale replica → negative, and sends NO consistency field
// (the hot enforcement gate stays cache-eligible / low-latency, unchanged).
func TestOpenFGA_Check_Default_ReadsStaleReplica(t *testing.T) {
	c, seen := newStaleReplicaFGA(t)
	allowed, err := c.Check(context.Background(), "user:u1", "v_update", "vpc_network:n1")
	require.NoError(t, err)
	assert.False(t, allowed, "default read is served the stale-replica negative")
	assert.Equal(t, []string{""}, *seen, "default Check must NOT set consistency")
}

// CheckConsistent forces HIGHER_CONSISTENCY → reads fresh → ALLOW on first attempt.
// This is the confirm-gate read: it collapses the retry-until-visible tail.
func TestOpenFGA_CheckConsistent_HigherConsistency_ReadsFresh(t *testing.T) {
	c, seen := newStaleReplicaFGA(t)
	allowed, err := c.CheckConsistent(context.Background(), "user:u1", "v_update", "vpc_network:n1")
	require.NoError(t, err)
	assert.True(t, allowed, "HIGHER_CONSISTENCY bypasses replica lag → allow on the FIRST attempt")
	assert.Equal(t, []string{"HIGHER_CONSISTENCY"}, *seen)
}

// The CEL-context variant (CheckWithContext) — the path AuthorizeService.CheckRelation
// uses — mirrors the same default-vs-consistent split.
func TestOpenFGA_CheckWithContext_DefaultVsConsistent(t *testing.T) {
	c, seen := newStaleReplicaFGA(t)

	allowed, err := c.CheckWithContext(context.Background(), "user:u1", "v_update", "vpc_network:n1", nil)
	require.NoError(t, err)
	assert.False(t, allowed, "default CheckWithContext reads the stale replica")

	allowedC, err := c.CheckWithContextConsistent(context.Background(), "user:u1", "v_update", "vpc_network:n1", nil)
	require.NoError(t, err)
	assert.True(t, allowedC, "HIGHER_CONSISTENCY CheckWithContext reads fresh")

	assert.Equal(t, []string{"", "HIGHER_CONSISTENCY"}, *seen)
}
