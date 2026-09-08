// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_hop_tls_test.go — every hop iam makes to the identity provider is
// verified against the anchor it was given, and against nothing else.
//
// The admin hop already had this. The two hops to the provider's PUBLIC listener
// — the token exchange and the JWKS upstream — had no way to be given an anchor
// at all: their clients were built as `&http.Client{Timeout: …}`, so an operator
// who moved the address to https would get the SYSTEM roots, which an internal-CA
// certificate never chains to. The address would read as hardened and every call
// would fail. Worse for the JWKS upstream, whose fetched keyset decides which
// signatures the whole data-plane accepts: an anchor there is not a nicety, it is
// the difference between "the provider said so" and "whatever answered said so".
//
// These assertions are behavioural on purpose: a handshake either happens or it
// does not. Checking the struct would only say the transport was installed.
package clients_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// testCA — a generated certificate authority plus the material to serve and to
// verify with. Generated rather than pasted: a hard-coded blob stops parsing when
// it expires and the test then passes for the wrong reason.
type testCA struct {
	caPEMPath string
	key       *ecdsa.PrivateKey
	cert      *x509.Certificate
	certDER   []byte
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
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
	return &testCA{caPEMPath: path, key: key, cert: parsed, certDER: der}
}

// serverCert issues a leaf for 127.0.0.1 so a local listener can present it.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.certDER}, PrivateKey: key}
}

// tlsServer starts an https server presenting a leaf issued by ca.
//
// Журнал сервера уводится в t.Logf, и это не косметика. Две пробы ниже ОТКАЗЫВАЮТ
// в рукопожатии намеренно — это и есть проверяемое свойство, — а `httptest.Server`
// пишет отказ через журнал по умолчанию, то есть в общий stderr пакета, без имени
// теста:
//
//	http: TLS handshake error from 127.0.0.1:NNNNN: remote error: tls: bad certificate
//
// В общем выводе пакета такая строка выглядит поломкой TLS и приклеивается к
// СОСЕДНЕЙ пробе, упавшей по своей причине. Так и вышло 2026-08-08: строка про
// сертификат стояла рядом с красной интеграционной пробой дренажа, к которой не
// имела отношения, и увела разбор в сторону. Привязка к тесту делает намеренный
// отказ отличимым от неожиданного: с `-v` строка помечена именем своей пробы, без
// `-v` она вообще не печатается у зелёного теста.
func tlsServer(t *testing.T, ca *testCA, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}, MinVersion: tls.VersionTLS12}
	// testLoggerWriter — общий для пакета переходник t.Log→io.Writer
	// (testmain_pgtest_test.go). Заводить рядом второй такой же было бы двумя
	// вещами на одну работу.
	srv.Config.ErrorLog = log.New(testLoggerWriter{t}, "[tlsServer] ", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func tokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":900}`))
	})
}

// The pinned anchor makes the hop work over TLS — the capability that was missing
// entirely, so an operator could not move the address to https at all.
func TestHydraTokenClient_PinnedAnchor_CompletesTheExchange(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srv := tlsServer(t, ca, tokenHandler())

	c, err := clients.NewHydraTokenClientWithCA(srv.URL, ca.caPEMPath)
	if err != nil {
		t.Fatalf("a usable anchor must be accepted, got: %v", err)
	}
	got, err := c.ClientCredentials(context.Background(), clients.ClientCredentialsRequest{ClientAssertion: "assertion"})
	if err != nil {
		t.Fatalf("exchange over the pinned hop failed: %v", err)
	}
	if got.AccessToken != "at" {
		t.Fatalf("access token = %q, want %q", got.AccessToken, "at")
	}
}

// Moving the address to https WITHOUT an anchor does not half-work: it fails on an
// unknown authority. This is the trap the boot guard refuses, asserted here as
// behaviour so nobody "simplifies" the guard away.
func TestHydraTokenClient_NoAnchor_RefusesTheInternalCAPeer(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srv := tlsServer(t, ca, tokenHandler())

	c := clients.NewHydraTokenClient(srv.URL)
	if _, err := c.ClientCredentials(context.Background(), clients.ClientCredentialsRequest{ClientAssertion: "assertion"}); err == nil {
		t.Fatal("an internal-CA peer must not be accepted on the system roots, got nil error")
	}
}

// An anchor for one authority does not accept a peer signed by another. This is
// the substitution case: something else answering that address, with a
// well-formed response, is refused rather than believed.
func TestHydraTokenClient_ForeignPeer_IsRefusedByThePinnedAnchor(t *testing.T) {
	legit := newTestCA(t, "kacho-internal-ca")
	impostor := newTestCA(t, "impostor-ca")
	srv := tlsServer(t, impostor, tokenHandler())

	c, err := clients.NewHydraTokenClientWithCA(srv.URL, legit.caPEMPath)
	if err != nil {
		t.Fatalf("a usable anchor must be accepted, got: %v", err)
	}
	if _, err := c.ClientCredentials(context.Background(), clients.ClientCredentialsRequest{ClientAssertion: "assertion"}); err == nil {
		t.Fatal("a peer signed by another authority must be refused, got nil error")
	}
}

// No anchor ⇒ the default transport, unchanged: a plaintext in-cluster address
// needs none, and inventing one would refuse a stand deliberately configured that
// way. The boot guard is what forbids the combination in production.
func TestHydraTokenClient_NoAnchorConfigured_LeavesDefaultTransport(t *testing.T) {
	c, err := clients.NewHydraTokenClientWithCA("http://hydra-public:4444/oauth2/token", "")
	if err != nil {
		t.Fatalf("no anchor must be accepted, got: %v", err)
	}
	if c.HTTPClient.Transport != nil {
		t.Fatalf("no anchor must leave the default transport in place, got %T", c.HTTPClient.Transport)
	}
}

// An anchor that cannot be read, or that holds no certificate, REFUSES and names
// the setting — the refusal is what an operator reads to fix the stand.
func TestHydraTokenClient_UnusableAnchor_RefusesNamingTheSetting(t *testing.T) {
	if _, err := clients.NewHydraTokenClientWithCA(
		"https://hydra-public:4444/oauth2/token", filepath.Join(t.TempDir(), "absent.crt"),
	); err == nil {
		t.Fatal("an unreadable anchor must refuse, got nil")
	} else if !strings.Contains(err.Error(), "hydra-token-ca-file") {
		t.Fatalf("the refusal must name the setting, got: %v", err)
	}

	empty := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := clients.NewHydraTokenClientWithCA("https://hydra-public:4444/oauth2/token", empty); err == nil {
		t.Fatal("an anchor holding no certificate must refuse, got nil")
	}
}

// The JWKS upstream is built from the same helper, so the mirror gets the same
// property: a client pinned to one authority will not accept a keyset served by
// another. The handler-level consequence (fail-closed 502 rather than a cached
// substitute) is asserted in the jwksproxyhttp package.
func TestProviderHopHTTPClient_PinnedAnchorIsTheOnlyPool(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	c, err := clients.ProviderHopHTTPClient(5*time.Second, ca.caPEMPath, clients.JWKSHopCASetting)
	if err != nil {
		t.Fatalf("a usable anchor must be accepted, got: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("a configured anchor must install its own transport, got %T", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("a configured anchor must install a pinned root pool")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want >= TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
	if c.Timeout != 5*time.Second {
		t.Fatalf("timeout = %v, want the per-call timeout it was given", c.Timeout)
	}
}
