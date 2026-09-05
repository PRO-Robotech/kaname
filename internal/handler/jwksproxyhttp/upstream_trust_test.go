// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// upstream_trust_test.go — the keyset this mirror re-serves is the data-plane's
// only anchor for deciding whether a token was signed by the provider. So the
// mirror must refuse material that did not arrive over a hop it can verify, and it
// must tell a misconfigured ADDRESS apart from an unavailable provider.
//
// Both are behavioural: a substituted keyset either reaches the response body or
// it does not, and the two failure classes either read differently to an operator
// or they do not. Asserting the configuration instead would say nothing about what
// the data-plane receives.
package jwksproxyhttp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/jwksproxyhttp"
)

// legitKeyset / substitutedKeyset — well-formed, non-empty JWKS documents. The
// substituted one is exactly as well-formed as the real one: nothing about the
// DOCUMENT tells them apart, which is why the transport has to.
const (
	legitKeyset       = `{"keys":[{"kty":"RSA","kid":"provider-1","n":"AQAB","e":"AQAB"}]}`
	substitutedKeyset = `{"keys":[{"kty":"RSA","kid":"attacker-1","n":"AQAB","e":"AQAB"}]}`
)

type ca struct {
	pemPath string
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	der     []byte
}

func newCA(t *testing.T, cn string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return &ca{pemPath: path, key: key, cert: parsed, der: der}
}

func (c *ca) serveTLS(t *testing.T, body string) *httptest.Server {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "hydra-public"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der, c.der}, PrivateKey: leafKey}},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// get — one request through the mirror.
func get(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, jwksproxyhttp.WellKnownJWKSPath, nil))
	return rec
}

// A keyset served by an authority the hop was NOT pinned to never reaches the
// data-plane: the mirror fail-closes and caches nothing.
func TestMirror_RefusesKeysetFromAnUnverifiableHop(t *testing.T) {
	pinned := newCA(t, "kacho-internal-ca")
	impostor := newCA(t, "impostor-ca")
	srv := impostor.serveTLS(t, substitutedKeyset)

	client, err := clients.ProviderHopHTTPClient(2*time.Second, pinned.pemPath, clients.JWKSHopCASetting)
	if err != nil {
		t.Fatalf("build pinned client: %v", err)
	}
	h := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: srv.URL, Client: client})

	rec := get(t, h)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 — a keyset from an unverifiable hop must not be served", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "attacker-1") {
		t.Fatalf("the substituted key reached the data-plane: %s", rec.Body.String())
	}
	// And it must not be cached either: a second request must fail the same way
	// rather than serve the substitute from memory.
	if again := get(t, h); again.Code != http.StatusBadGateway {
		t.Fatalf("second status = %d, want 502 — the refused keyset must not have been cached", again.Code)
	}
}

// The other direction of the same injection, and the reason the pinned client had
// to be buildable at all: with NO anchor on the hop, the mirror cannot tell the
// provider from anything else that answers the address — it re-serves the
// substituted keyset verbatim, and the data-plane then accepts tokens signed by
// whoever supplied it.
//
// This is NOT an endorsement of that shape. It is the property that makes the
// anchor load-bearing, asserted so that "the transport does not matter, the
// document is validated anyway" cannot be argued from the code again:
// validateNonEmptyKeyset is satisfied by the substitute exactly as by the real one.
func TestMirror_WithoutAPinnedAnchor_CannotTellTheProviderFromAnImpostor(t *testing.T) {
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(substitutedKeyset))
	}))
	defer impostor.Close()

	h := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: impostor.URL})
	rec := get(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an unanchored hop has nothing to reject with", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "attacker-1") {
		t.Fatalf("expected the substituted keyset to be mirrored verbatim, got: %s", rec.Body.String())
	}
}

// Control, so the assertion above is about the AUTHORITY and not about https
// generally: the same document, same code path, served by the pinned authority, is
// mirrored verbatim.
func TestMirror_ServesKeysetFromThePinnedHop(t *testing.T) {
	pinned := newCA(t, "kacho-internal-ca")
	srv := pinned.serveTLS(t, legitKeyset)

	client, err := clients.ProviderHopHTTPClient(2*time.Second, pinned.pemPath, clients.JWKSHopCASetting)
	if err != nil {
		t.Fatalf("build pinned client: %v", err)
	}
	h := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: srv.URL, Client: client})

	rec := get(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the pinned authority (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "provider-1") {
		t.Fatalf("the mirror must serve the upstream document verbatim, got: %s", rec.Body.String())
	}
}

// A WRONG ADDRESS and an UNAVAILABLE PROVIDER must not read the same. The first is
// a permanent misconfiguration that no retry fixes; if both look like "upstream
// unavailable", a stand pointed at the wrong port stays that way for as long as
// nobody happens to try a docker pull.
func TestMirror_DistinguishesAWrongAddressFromAnOutage(t *testing.T) {
	cases := []struct {
		name      string
		upstream  http.HandlerFunc
		wantToken string
	}{
		{
			name: "path serves nothing",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				http.NotFound(w, nil)
			},
			wantToken: "jwks_upstream_misconfigured",
		},
		{
			name: "address answers with a web page",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html><body>login</body></html>"))
			},
			wantToken: "jwks_upstream_misconfigured",
		},
		{
			name: "address answers JSON that is not a keyset",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			},
			wantToken: "jwks_upstream_misconfigured",
		},
		{
			name: "provider is failing",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantToken: "jwks_upstream_unavailable",
		},
		{
			name: "provider has no signing keys yet",
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[]}`))
			},
			wantToken: "jwks_upstream_unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.upstream)
			defer srv.Close()
			h := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: srv.URL})

			rec := get(t, h)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502 (fail-closed) for %s", rec.Code, tc.name)
			}
			if !strings.Contains(rec.Body.String(), tc.wantToken) {
				t.Fatalf("body = %s, want the %q classification", rec.Body.String(), tc.wantToken)
			}
		})
	}
}

// The counts are the answer to "has this control ever refused anything?". Without
// them a mirror that has fail-closed on every single fetch since the stand came up
// is indistinguishable from one that never had to.
func TestMirror_CountsRefusalsByClass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	h := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{UpstreamURL: srv.URL})

	if st := h.Stats(); st.Misconfigured != 0 || st.Unavailable != 0 || st.Served != 0 {
		t.Fatalf("a fresh mirror must start at zero, got %+v", st)
	}
	get(t, h)
	get(t, h)
	st := h.Stats()
	if st.Misconfigured != 2 {
		t.Fatalf("misconfigured = %d, want 2", st.Misconfigured)
	}
	if st.Unavailable != 0 {
		t.Fatalf("unavailable = %d, want 0 — a wrong address is not an outage", st.Unavailable)
	}
	if st.Served != 0 {
		t.Fatalf("served = %d, want 0", st.Served)
	}
}
