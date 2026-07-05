// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestHydraTokenClient_ClientCredentials_Happy — a private_key_jwt
// client_credentials exchange posts the RFC 7523 form parameters and returns the
// Hydra access_token + expires_in.
func TestHydraTokenClient_ClientCredentials_Happy(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"hydra-jwt-abc","token_type":"bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	c := NewHydraTokenClient(srv.URL)
	out, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{
		ClientAssertion: "assertion.jws.value",
		Audience:        "registry.kacho.local",
		Scope:           "reg",
	})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if out.AccessToken != "hydra-jwt-abc" {
		t.Errorf("access_token = %q", out.AccessToken)
	}
	if out.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d; want 3600", out.ExpiresIn)
	}
	if gotForm.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %q", gotForm.Get("client_assertion_type"))
	}
	if gotForm.Get("client_assertion") != "assertion.jws.value" {
		t.Errorf("client_assertion = %q", gotForm.Get("client_assertion"))
	}
	if gotForm.Get("audience") != "registry.kacho.local" {
		t.Errorf("audience = %q", gotForm.Get("audience"))
	}
	if gotForm.Get("scope") != "reg" {
		t.Errorf("scope = %q", gotForm.Get("scope"))
	}
}

// TestHydraTokenClient_Rejected — Hydra 4xx OAuth2 error (invalid_client /
// invalid_grant) maps to ErrHydraRejected (→ 401 at the shim), NOT unavailable.
func TestHydraTokenClient_Rejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"invalid_client", http.StatusUnauthorized, `{"error":"invalid_client"}`},
		{"invalid_grant", http.StatusBadRequest, `{"error":"invalid_grant"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := NewHydraTokenClient(srv.URL).ClientCredentials(context.Background(),
				ClientCredentialsRequest{ClientAssertion: "a"})
			if !errors.Is(err, ErrHydraRejected) {
				t.Fatalf("err = %v; want ErrHydraRejected", err)
			}
			// The raw Hydra body must NOT be embedded verbatim in the sentinel
			// message (no-leak): only a fixed classification.
			if err != nil && contains(err.Error(), "invalid_client") {
				t.Errorf("error leaks raw Hydra body: %v", err)
			}
		})
	}
}

// TestHydraTokenClient_Unavailable — network failure, 5xx and a malformed 2xx
// body all map to ErrHydraUnavailable (→ fail-closed 503 at the shim).
func TestHydraTokenClient_Unavailable(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now.
		_, err := NewHydraTokenClient(url).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrHydraUnavailable) {
			t.Fatalf("err = %v; want ErrHydraUnavailable", err)
		}
	})
	t.Run("5xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()
		_, err := NewHydraTokenClient(srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrHydraUnavailable) {
			t.Fatalf("err = %v; want ErrHydraUnavailable", err)
		}
	})
	t.Run("malformed 2xx body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer srv.Close()
		_, err := NewHydraTokenClient(srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrHydraUnavailable) {
			t.Fatalf("err = %v; want ErrHydraUnavailable", err)
		}
	})
	t.Run("2xx empty access_token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"bearer","expires_in":60}`))
		}))
		defer srv.Close()
		_, err := NewHydraTokenClient(srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrHydraUnavailable) {
			t.Fatalf("err = %v; want ErrHydraUnavailable", err)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
