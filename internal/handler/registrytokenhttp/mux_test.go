// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
)

// TestNewMux_RoutesToken — the mux dispatches the canonical token path to its
// handler. There is no JWKS endpoint: the data-plane verifies against Hydra's
// JWKS, not an IAM-served key set.
func TestNewMux_RoutesToken(t *testing.T) {
	iss := &fakeIssuer{out: registrytokenuc.IssueOutput{Token: "t", ExpiresIn: 60}}
	mux := NewMux(newTokenHandler(iss))

	// token path — Basic-authed → 200.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, TokenPath+"?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cid-ci", "key"))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token path status = %d; want 200", rec.Code)
	}

	// The former /iam/token/jwks path is gone → the mux does not route it (404).
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/iam/token/jwks", nil))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("jwks path status = %d; want 404 (endpoint removed)", rec2.Code)
	}
}
