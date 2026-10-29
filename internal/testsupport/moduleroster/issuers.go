// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// CA — удостоверяющий центр проб привязки листа к выпустившему (kaname#988).
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA — самоподписанный центр с именем name.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ центра %s: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат центра %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("разбор центра %s: %v", name, err)
	}
	return &CA{cert: cert, key: key}
}

// Cert — сертификат центра: якорь цепочки.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// Leaf — клиентский лист с URI SAN san, выпущенный этим центром.
func (c *CA) Leaf(t testing.TB, san string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(san)
	if err != nil {
		t.Fatalf("SAN %q: %v", san, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ листа: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("лист %q: %v", san, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("разбор листа %q: %v", san, err)
	}
	return leaf
}

// ConnectionState — состояние рукопожатия, в котором слушатель ПРОВЕРИЛ лист
// san цепочкой до этого центра.
func (c *CA) ConnectionState(t testing.TB, san string) *tls.ConnectionState {
	t.Helper()
	leaf := c.Leaf(t, san)
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, c.cert}},
	}
}

// PeerContext — контекст вызова gRPC-слушателя так, как его оставляют
// транспорт и извлекатель личности сертификата: пир с проверенной цепочкой до
// этого центра и идентификатор листа.
func (c *CA) PeerContext(t testing.TB, san string) context.Context {
	t.Helper()
	st := c.ConnectionState(t, san)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *st}})
	return grpcsrv.WithCertIdentityIn(ctx, Domain(), san, true)
}
