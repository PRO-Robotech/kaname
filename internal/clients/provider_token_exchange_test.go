// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestProviderTokenClient_ClientCredentials_Happy — a private_key_jwt
// client_credentials exchange posts the RFC 7523 form parameters and returns the
// provider's access_token + expires_in.
func TestProviderTokenClient_ClientCredentials_Happy(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"provider-jwt-abc","token_type":"bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	c := tokenClient(t, srv.URL)
	out, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{
		ClientAssertion: "assertion.jws.value",
		Audience:        "registry.kacho.local",
		Scope:           "reg",
	})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if out.AccessToken != "provider-jwt-abc" {
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

// TestProviderTokenClient_Rejected — a provider 4xx OAuth2 error (invalid_client /
// invalid_grant) maps to ErrProviderTokenRejected (→ 401 at the shim), NOT unavailable.
func TestProviderTokenClient_Rejected(t *testing.T) {
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

			_, err := tokenClient(t, srv.URL).ClientCredentials(context.Background(),
				ClientCredentialsRequest{ClientAssertion: "a"})
			if !errors.Is(err, ErrProviderTokenRejected) {
				t.Fatalf("err = %v; want ErrProviderTokenRejected", err)
			}
			// The raw provider body must NOT be embedded verbatim in the sentinel
			// message (no-leak): only a fixed classification.
			if err != nil && contains(err.Error(), "invalid_client") {
				t.Errorf("error leaks raw provider body: %v", err)
			}
			// «Only a fixed classification» is asserted as the WHOLE text, not
			// only by the absence of one known fragment: a body the fixture does
			// not happen to contain would pass the check above.
			const want = "provider rejected the token exchange"
			if err != nil && err.Error() != want {
				t.Errorf("error text = %q; want exactly %q", err.Error(), want)
			}
		})
	}
}

// TestProviderTokenClient_Unavailable — network failure, 5xx and a malformed 2xx
// body all map to ErrProviderTokenUnavailable (→ fail-closed 503 at the shim).
func TestProviderTokenClient_Unavailable(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now.
		_, err := tokenClient(t, url).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrProviderTokenUnavailable) {
			t.Fatalf("err = %v; want ErrProviderTokenUnavailable", err)
		}
	})
	t.Run("5xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()
		_, err := tokenClient(t, srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrProviderTokenUnavailable) {
			t.Fatalf("err = %v; want ErrProviderTokenUnavailable", err)
		}
	})
	t.Run("malformed 2xx body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer srv.Close()
		_, err := tokenClient(t, srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrProviderTokenUnavailable) {
			t.Fatalf("err = %v; want ErrProviderTokenUnavailable", err)
		}
	})
	t.Run("2xx empty access_token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"bearer","expires_in":60}`))
		}))
		defer srv.Close()
		_, err := tokenClient(t, srv.URL).ClientCredentials(context.Background(),
			ClientCredentialsRequest{ClientAssertion: "a"})
		if !errors.Is(err, ErrProviderTokenUnavailable) {
			t.Fatalf("err = %v; want ErrProviderTokenUnavailable", err)
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

// tokenClient — построитель, которым полосу «без якоря» строит ПРОД
// (`registrytokenwire.providerExchangeFor` → `NewProviderTokenClientWithCA`).
//
// Отдельного построителя «без якоря» в дереве больше нет намеренно: пустой якорь
// у `ProviderHopHTTPClient` даёт ровно `&http.Client{Timeout: …}` с умолчательным
// транспортом, то есть тот же объект, — а лишний построитель был ловушкой. Проба
// дороги к издателю по нему уже один раз оказалась ЗЕЛЁНОЙ при производственной
// ветке, переставшей проверять пира (см. provider_hop_tls_test.go).
func tokenClient(t *testing.T, tokenURL string) *ProviderTokenClient {
	t.Helper()
	c, err := NewProviderTokenClientWithCA(tokenURL, "")
	if err != nil {
		t.Fatalf("пустой якорь — законный вход построителя, получено: %v", err)
	}
	return c
}
