// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_write_bodycap_test.go — RED→GREEN proof that the OpenFGA write paths
// cap the 400 response-body read, mirroring the sibling read path
// (openfga_list.go listUsersOfType, which io.LimitReader(resp.Body, 4096)).
//
// FAILURE (RED): a misbehaving / compromised OpenFGA returns a 400 with a large
// body that does NOT contain the idempotent markers (already_exists /
// cannot_delete). The write paths embed the WHOLE body into the returned error
// (fmt.Errorf("openfga write: bad request: %s", s)) via an unbounded
// buf.ReadFrom(resp.Body) — an oversized error/log line plus a transient memory
// spike. FIX: wrap resp.Body in io.LimitReader(resp.Body, maxErrBodyBytes) so the
// interpolated body is bounded, exactly like the read path.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// bigBadRequestServer returns HTTP 400 with a body of `bodyLen` bytes that does
// NOT carry any idempotent marker (so the client surfaces it as an error).
func bigBadRequestServer(t *testing.T, bodyLen int) string {
	t.Helper()
	big := strings.Repeat("A", bodyLen)
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(big))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// The cap the sibling read path uses (openfga_list.go). The interpolated error
// must not exceed this by more than a small fixed prefix ("openfga write: bad
// request: ").
const bodyCapBytes = 4096

// TestWriteConditionalTuples_CapsErrorBody asserts the 400-body embedded in the
// error is bounded (≤ cap + short prefix), not the full multi-KB body.
func TestWriteConditionalTuples_CapsErrorBody(t *testing.T) {
	const bodyLen = 200 * 1024 // 200 KiB — far over the 4096 cap
	c := &clients.OpenFGAHTTPClient{
		Endpoint:           bigBadRequestServer(t, bodyLen),
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
	}
	err := c.WriteConditionalTuples(context.Background(),
		[]clients.ConditionalTuple{{User: "user:u1", Relation: "viewer", Object: "iam_access_binding:acb1"}}, nil)
	if err == nil {
		t.Fatalf("expected an error for a non-idempotent 400, got nil")
	}
	if len(err.Error()) > bodyCapBytes+128 {
		t.Fatalf("WriteConditionalTuples must cap the 400-body read at %d bytes "+
			"(mirroring openfga_list.go), got error length %d for a %d-byte body",
			bodyCapBytes, len(err.Error()), bodyLen)
	}
}

// TestWriteOrDelete_CapsErrorBody asserts the same cap on the RelationStore
// WriteTuples path (openfga_client.go writeOrDelete).
func TestWriteOrDelete_CapsErrorBody(t *testing.T) {
	const bodyLen = 200 * 1024
	c := &clients.OpenFGAHTTPClient{
		Endpoint:           bigBadRequestServer(t, bodyLen),
		StoreID:            "store_test",
		AuthorizationModel: "model_test",
	}
	err := c.WriteTuples(context.Background(),
		[]clients.RelationTuple{{User: "user:u1", Relation: "viewer", Object: "iam_access_binding:acb1"}})
	if err == nil {
		t.Fatalf("expected an error for a non-idempotent 400, got nil")
	}
	if len(err.Error()) > bodyCapBytes+128 {
		t.Fatalf("writeOrDelete must cap the 400-body read at %d bytes "+
			"(mirroring openfga_list.go), got error length %d for a %d-byte body",
			bodyCapBytes, len(err.Error()), bodyLen)
	}
}
