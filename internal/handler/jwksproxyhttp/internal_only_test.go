// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package jwksproxyhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/registrytokenhttp"
)

// RJU-06 — internal-only lock: the /.well-known/jwks.json route is served ONLY by
// the jwks-proxy mux (mounted on the cluster-INTERNAL :9097 listener), and is NOT
// reachable on the EXTERNAL registry-token mux (:9096). Publishing JWKS on an
// external-reachable surface would regress ban #6.
func TestJWKSProxy_RJU06_NotOnExternalRegistryTokenMux(t *testing.T) {
	// External registry-token mux (docker clients hit /iam/token through the edge).
	externalMux := registrytokenhttp.NewMux(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, jwksproxyhttp.WellKnownJWKSPath, nil)
	externalMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("external registry-token mux served %s → %d; want 404 (route must be internal-only, ban #6)",
			jwksproxyhttp.WellKnownJWKSPath, rec.Code)
	}

	// The dedicated jwks-proxy mux DOES route the well-known path to the handler.
	jwksMux := jwksproxyhttp.NewMux(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
	)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, jwksproxyhttp.WellKnownJWKSPath, nil)
	jwksMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("jwks-proxy mux did not route %s to its handler (got %d)",
			jwksproxyhttp.WellKnownJWKSPath, rec.Code)
	}
}
