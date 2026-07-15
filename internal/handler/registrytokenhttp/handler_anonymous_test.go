// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
)

// TestToken_AnonymousEnabled_NoCreds_200Token — RG-1-B13 (handler edge). When
// anonymous pull is ENABLED, a `/token` request WITHOUT Basic creds issues the
// read-only public bearer (200 Docker body) instead of a 401 challenge. The
// requested ?service= is forwarded to the anonymous use-case path.
func TestToken_AnonymousEnabled_NoCreds_200Token(t *testing.T) {
	iss := &fakeIssuer{
		anonEnabled: true,
		anonOut:     registrytokenuc.IssueOutput{Token: "anon.jwt.token", ExpiresIn: 120, IssuedAt: 1700000000},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local&scope=repository:reg-A/public/img:pull", nil)
	newTokenHandler(iss).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if body["token"] != "anon.jwt.token" || body["access_token"] != "anon.jwt.token" {
		t.Fatalf("token/access_token = %v/%v", body["token"], body["access_token"])
	}
	if iss.gotAnonSvc != "registry.kacho.local" {
		t.Errorf("anon service = %q; want registry.kacho.local", iss.gotAnonSvc)
	}
}

// TestToken_AnonymousDisabled_NoCreds_401 — with anonymous pull DISABLED
// (secure-by-default), a no-Basic-creds request still fails closed to the 401
// Bearer challenge (back-compat with the SA-key-only shim; anon is opt-in).
func TestToken_AnonymousDisabled_NoCreds_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	newTokenHandler(&fakeIssuer{anonEnabled: false}).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (anon disabled)", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatal("disabled-anon no-creds must carry a Bearer challenge")
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("401 body must not carry a token: %s", rec.Body.String())
	}
}

// TestToken_AnonymousEnabled_IssuerUnavailable_503 — Hydra unreachable on the
// anon mint path is fail-closed 503 (no token), same as the SA-key path.
func TestToken_AnonymousEnabled_IssuerUnavailable_503(t *testing.T) {
	iss := &fakeIssuer{anonEnabled: true, anonErr: registrytokenuc.ErrIssuerUnavailable}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	newTokenHandler(iss).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("503 body must not carry a token: %s", rec.Body.String())
	}
}

// TestToken_AnonymousEnabled_Unauthenticated_401 — an anon path returning
// ErrUnauthenticated (e.g. Hydra rejects the anon client) falls back to the 401
// challenge, never leaking a token.
func TestToken_AnonymousEnabled_Unauthenticated_401(t *testing.T) {
	iss := &fakeIssuer{anonEnabled: true, anonErr: registrytokenuc.ErrUnauthenticated}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	newTokenHandler(iss).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatal("401 must carry a Bearer challenge")
	}
}
