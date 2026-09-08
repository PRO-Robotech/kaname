// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hydra_admin_trust_anchor_test.go — the facade's hop to the provider's admin
// API must verify the peer against the anchor it was given, and must refuse to
// start on an anchor it cannot use.
//
// Moving this hop to TLS only helps if the certificate is VERIFIED, and the
// provider's in-cluster certificate is issued by the internal CA — which this
// process does not trust by default, because its default pool is the system
// roots. So the anchor is configuration, exactly like the address, and an anchor
// that cannot be read must stop the process rather than quietly leave it
// verifying against the wrong pool: that state reads as configured, works until
// a certificate rotates, and then fails everywhere at once.
package clients_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// writeTestCA generates a real self-signed CA and writes it as PEM, returning the
// path. Generated rather than pasted: a hard-coded blob silently stops parsing
// when it expires, and the test would then pass for the wrong reason.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kacho-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return path
}

// No anchor configured ⇒ the default transport, unchanged. A provider served over
// plaintext http inside the cluster needs none, and inventing one would refuse a
// developer stand that is deliberately configured that way.
func TestNewHydraAdminClient_NoAnchor_UsesDefaultTransport(t *testing.T) {
	c, err := clients.NewHydraAdminClientWithCA("http://hydra-admin:4445", "", "")
	if err != nil {
		t.Fatalf("no anchor must be accepted, got: %v", err)
	}
	if c.HTTPClient == nil {
		t.Fatal("client must carry an HTTP client")
	}
	if c.HTTPClient.Transport != nil {
		t.Fatalf("no anchor must leave the default transport in place, got %T", c.HTTPClient.Transport)
	}
}

// An anchor that cannot be read REFUSES. Carrying on with the system roots would
// read as configured while verifying nothing the operator asked for.
func TestNewHydraAdminClient_UnreadableAnchor_Refuses(t *testing.T) {
	_, err := clients.NewHydraAdminClientWithCA(
		"https://hydra-admin:4445", "", filepath.Join(t.TempDir(), "absent.crt"))
	if err == nil {
		t.Fatal("an unreadable anchor must refuse, got nil")
	}
	// The refusal is operator diagnostics: it must name the setting to fix.
	if !strings.Contains(err.Error(), "hydra-admin-ca-file") {
		t.Fatalf("the refusal must name the setting, got: %v", err)
	}
}

// A file holding no certificate refuses too — the resulting pool would be EMPTY,
// so every handshake on the hop would fail permanently.
func TestNewHydraAdminClient_AnchorWithoutCertificate_Refuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := clients.NewHydraAdminClientWithCA("https://hydra-admin:4445", "", path); err == nil {
		t.Fatal("an anchor holding no certificate must refuse, got nil")
	}
}

// A usable anchor becomes the ONLY trust anchor for the hop — not an addition to
// the system roots. An internal-CA hop has no business accepting a publicly
// issued certificate for the same name; narrowing the pool is the point.
func TestNewHydraAdminClient_UsableAnchor_PinsItAsTheOnlyPool(t *testing.T) {
	c, err := clients.NewHydraAdminClientWithCA("https://hydra-admin:4445", "", writeTestCA(t))
	if err != nil {
		t.Fatalf("a usable anchor must be accepted, got: %v", err)
	}
	tr, ok := c.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("a configured anchor must install its own transport, got %T", c.HTTPClient.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("a configured anchor must install a pinned root pool on the transport")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want >= TLS 1.2", tr.TLSClientConfig.MinVersion)
	}
}
