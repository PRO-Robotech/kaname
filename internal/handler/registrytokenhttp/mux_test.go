// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// TestNewMux_RoutesTokenAndJWKS — the mux dispatches the canonical token + JWKS
// paths to their handlers.
func TestNewMux_RoutesTokenAndJWKS(t *testing.T) {
	iss := &fakeIssuer{out: registrytokenuc.IssueOutput{Token: "t", ExpiresIn: 60}}
	jwks := fakeJWKS{set: registrytoken.JWKS{Keys: []registrytoken.JWK{{Kty: "RSA", Kid: "k"}}}}
	mux := NewMux(newTokenHandler(iss), NewJWKSHandler(jwks))

	// token path — Basic-authed → 200.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, TokenPath+"?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("sva1", "key"))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token path status = %d; want 200", rec.Code)
	}

	// jwks path → 200.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, JWKSPath, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("jwks path status = %d; want 200", rec2.Code)
	}
}
