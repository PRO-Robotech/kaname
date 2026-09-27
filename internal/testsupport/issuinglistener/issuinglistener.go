// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package issuinglistener — настоящий слушатель поверхности выдачи для проб
// (приёмка ceremony-pace-is-named-by-number.md, группа F и KN-PACE-06).
//
// Транспорт собирает ТОТ ЖЕ строитель, что у процесса
// (`config.MTLSConfig.RegistryTokenServerTLSConfig`), в режиме
// `optional-mutual`, над тестовым внутренним УЦ: сертификат запрашивается и,
// предъявленный, проверяется; без сертификата соединение продолжается. Своего
// `tls.Config` проба не пишет — иначе она судила бы свою копию режима, а не
// режим, который уходит в слушатель.
package issuinglistener

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
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Идентичности проб: домен доверия, SAN края и SAN соседней службы того же УЦ.
const (
	TrustDomain = "kacho.cloud"
	EdgeSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	NeighborSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
)

// Stand — поднятый слушатель и его УЦ.
type Stand struct {
	URL string
	ca  *authority
}

type authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

var serial atomic.Int64

// Start поднимает слушатель над handler в режиме `optional-mutual`.
func Start(t *testing.T, handler http.Handler) *Stand {
	t.Helper()
	ca := newAuthority(t)
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", "CERTIFICATE", ca.cert.Raw)
	serverCert, serverKey := ca.issue(t, "", x509.ExtKeyUsageServerAuth)
	certFile := writePEM(t, dir, "tls.crt", "CERTIFICATE", serverCert)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("issuinglistener: server key: %v", err)
	}
	keyFile := writePEM(t, dir, "tls.key", "PRIVATE KEY", keyDER)

	var m config.MTLSConfig
	m.RegistryTokenServerMTLS = grpcsrv.TLSServer{Enable: true, CertFile: certFile, KeyFile: keyFile,
		ClientCAFiles: []string{caFile}}
	m.RegistryTokenClientAuthMode = config.IssuingListenerRequestingModeName()
	tlsCfg, err := m.RegistryTokenServerTLSConfig()
	if err != nil || tlsCfg == nil {
		t.Fatalf("issuinglistener: транспорт слушателя выдачи не собран: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &Stand{URL: srv.URL, ca: ca}
}

// Client — клиент слушателя; san пуст — без клиентского сертификата.
func (s *Stand) Client(t *testing.T, san string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if san != "" {
		der, key := s.ca.issue(t, san, x509.ExtKeyUsageClientAuth)
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuinglistener: ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "probe-internal-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issuinglistener: ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("issuinglistener: ca parse: %v", err)
	}
	return &authority{key: key, cert: cert}
}

func (a *authority) issue(t *testing.T, san string, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuinglistener: leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "probe-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if san != "" {
		u, err := url.Parse(san)
		if err != nil {
			t.Fatalf("issuinglistener: san: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("issuinglistener: leaf: %v", err)
	}
	return der, key
}

func writePEM(t *testing.T, dir, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatalf("issuinglistener: write %s: %v", name, err)
	}
	return path
}
