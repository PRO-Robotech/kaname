// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_read_drain_test.go — RED→GREEN proof that the read/list/expand query
// paths (ListObjects, ListSubjects, ReadTuples, Expand) drain (capped) the
// response body on their non-OK branch before the deferred Close, so the
// keep-alive TCP connection returns to the http.Transport idle pool and is
// reused — mirroring the sibling drain in openfga_list.go listUsersOfType.
//
// FAILURE (RED): each method returns on the `status != 200` branch WITHOUT
// reading the body; the deferred resp.Body.Close() on an undrained body makes
// net/http mark the persistent connection unreusable → every call opens a FRESH
// TCP connection. A degraded OpenFGA emitting a burst of 4xx on these paths
// (they feed AuthorizeService.ListObjects / ExpandAccess / formatDenyReason
// diagnostics) then churns connections instead of reusing them. The test
// observes connection reuse (distinct RemoteAddr count) — a behavioural lock.
//
// 404 (< 500) is used so retryClient returns the response immediately (no
// retry-churn confound); the fixed branch is the method's own non-OK return.

import (
	"context"
	"net/http"
	"testing"
)

func TestListObjects_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusNotFound)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		if _, err := c.ListObjects(context.Background(), "user:usr01", "viewer", "project", nil, 0); err == nil {
			t.Fatalf("non-200 must return an error")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("ListObjects must drain the non-200 body for conn reuse: "+
			"expected 1 distinct connection across %d calls, got %d (undrained → churned)", n, got)
	}
}

func TestListSubjects_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusNotFound)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		if _, _, err := c.ListSubjects(context.Background(), "project", "prj01", "viewer", 100, ""); err == nil {
			t.Fatalf("non-200 must return an error")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("ListSubjects must drain the non-200 body for conn reuse: "+
			"expected 1 distinct connection across %d calls, got %d (undrained → churned)", n, got)
	}
}

func TestReadTuples_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusNotFound)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		if _, _, err := c.ReadTuples(context.Background(), "", "viewer", "project:prj01", 100, ""); err == nil {
			t.Fatalf("non-200 must return an error")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("ReadTuples must drain the non-200 body for conn reuse: "+
			"expected 1 distinct connection across %d calls, got %d (undrained → churned)", n, got)
	}
}

func TestExpand_DrainsBodyForConnReuse_Non200(t *testing.T) {
	endpoint, distinct := countingStatusServer(t, http.StatusNotFound)
	c := newDrainTestClient(endpoint)

	const n = 5
	for i := 0; i < n; i++ {
		if _, err := c.Expand(context.Background(), "project", "prj01", "viewer"); err == nil {
			t.Fatalf("non-200 must return an error")
		}
	}
	if got := distinct(); got != 1 {
		t.Fatalf("Expand must drain the non-200 body for conn reuse: "+
			"expected 1 distinct connection across %d calls, got %d (undrained → churned)", n, got)
	}
}
