// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// f1b_binding_source_test.go — Ф1б-10, входная половина: материал привязки
// берётся из ПРОВЕРЕННОГО клиентского сертификата хопа выдачи и ниоткуда больше.
//
// Различие «предъявлен» / «предъявлен и проверен» здесь несущее. Сертификат,
// который пир прислал, но цепочка которого не проверена, привязкой быть не
// может: тогда отпечаток назначал бы себе сам предъявитель, а привязка, которую
// выбирает предъявитель, не привязывает ни к чему.
package registrytokenhttp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
)

// f1bCertPair — самоподписанный сертификат-заглушка и его ожидаемый отпечаток.
func f1bCert(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	// Содержимое сертификата пробе безразлично: отпечаток считается по DER
	// целиком, поэтому годится любой набор байт, лишь бы он был стабилен.
	c := &x509.Certificate{Raw: []byte("f1b-fake-der-bytes-for-thumbprint")}
	sum := sha256.Sum256(c.Raw)
	return c, base64.RawURLEncoding.EncodeToString(sum[:])
}

func f1bHandler(t *testing.T) (*TokenHandler, *fakeIssuer) {
	t.Helper()
	f := &fakeIssuer{out: registrytokenuc.IssueOutput{
		Token: "the.jwt.token", ExpiresIn: 300, IssuedAt: 1700000000,
	}}
	return NewTokenHandler(Config{Realm: "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local"}, f), f
}

func TestF1b10_VerifiedClientCertBecomesTheBindingMaterial(t *testing.T) {
	h, f := f1bHandler(t)
	cert, want := f1bCert(t)

	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cli", "pem"))
	// ПРОВЕРЕННАЯ цепочка — то, что доказано, а не то, что прислано.
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	h.ServeHTTP(httptest.NewRecorder(), req)

	if f.gotConfirmationX5TS256 == "" {
		t.Fatalf("проверенный клиентский сертификат предъявлен, а материал привязки до " +
			"выдачи не доехал — возможность подписанта осталась без вызывающего")
	}
	if f.gotConfirmationX5TS256 != want {
		t.Fatalf("отпечаток посчитан не по тому материалу: получено %q, ожидалось %q",
			f.gotConfirmationX5TS256, want)
	}
}

func TestF1b10_UnverifiedOrAbsentCertYieldsNoBinding(t *testing.T) {
	cert, _ := f1bCert(t)

	// (1) Сертификат ПРИСЛАН, но цепочка НЕ проверена — привязкой не становится.
	h, f := f1bHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cli", "pem"))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	h.ServeHTTP(httptest.NewRecorder(), req)
	if f.gotConfirmationX5TS256 != "" {
		t.Fatalf("непроверенный сертификат стал материалом привязки — тогда отпечаток " +
			"назначает себе сам предъявитель, и привязка не привязывает ни к чему")
	}

	// (2) Соединение без TLS вовсе — материала нет, и он не выдумывается.
	h2, f2 := f1bHandler(t)
	req2 := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req2.Header.Set("Authorization", basic("cli", "pem"))
	h2.ServeHTTP(httptest.NewRecorder(), req2)
	if f2.gotConfirmationX5TS256 != "" {
		t.Fatalf("материал привязки появился на соединении без TLS — он выдуман")
	}
}
