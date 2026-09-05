// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/registrytokenwire"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// TestRequireRegistryTokenTLS — по слушателю docker-token (`/iam/token`) едет
// HTTP Basic, чей пароль — ПРИВАТНЫЙ КЛЮЧ ключа служебной учётки: сервер его не
// хранит вовсе (сверяет выведенный SPKI с сохранённым публичным), поэтому этот
// хоп — единственное место в системе, где приватный ключ вообще транзитит. Срок
// жизни ключа не ограничен, ротации нет: снятый с провода credential предъявляется
// напрямую и без окна TTL.
//
// Отсюда гейт: в production слушатель либо несёт TLS, либо не поднимается. Молча
// возить бессрочный секрет открытым текстом между подами нельзя — тем более что
// СЛАБЕЙШАЯ соседняя нога (5-минутный bearer на loopback) собственный ack-гейт
// давно получила.
func TestRequireRegistryTokenTLS(t *testing.T) {
	on := grpcsrv.TLSServer{Enable: true, CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key"}
	off := grpcsrv.TLSServer{}
	cases := []struct {
		name       string
		production bool
		addr       string
		edge       grpcsrv.TLSServer
		wantErr    bool
	}{
		{"dev-plaintext-ok", false, "0.0.0.0:9096", off, false},
		{"prod-listener-disabled-ok", true, "", off, false},
		{"prod-tls-on-ok", true, "0.0.0.0:9096", on, false},
		{"prod-plaintext-rejected", true, "0.0.0.0:9096", off, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m config.MTLSConfig
			m.RegistryTokenServerMTLS = tc.edge
			err := requireRegistryTokenTLS(tc.production, tc.addr, m)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want refusal, got nil")
				}
				// Оператор обязан узнать из отказа, ЧТО включить.
				if !strings.Contains(err.Error(), "KACHO_IAM_REGISTRYTOKEN_SERVER_MTLS_ENABLE") {
					t.Fatalf("refusal does not name the knob: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestRegistryTokenListener_TLSRefusesCleartextClient — наблюдаемая регрессия:
// когда ребро включено, слушатель обслуживает ТОЛЬКО TLS. Клиент, заговоривший
// открытым текстом, не получает ни 401-вызова, ни чего-либо ещё — то есть
// приватный ключ по этому проводу уже не уедет; TLS-клиент, доверяющий тому же
// CA, получает штатный вызов.
func TestRegistryTokenListener_TLSRefusesCleartextClient(t *testing.T) {
	dir := t.TempDir()
	caPEM := writeSelfSignedCert(t, dir)

	var m config.MTLSConfig
	m.RegistryTokenServerMTLS = grpcsrv.TLSServer{
		Enable:   true,
		CertFile: filepath.Join(dir, "tls.crt"),
		KeyFile:  filepath.Join(dir, "tls.key"),
	}
	tlsCfg, err := m.RegistryTokenServerTLSConfig()
	if err != nil {
		t.Fatalf("RegistryTokenServerTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("enabled edge produced no TLS config — the listener would stay in the clear")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln = tls.NewListener(ln, tlsCfg)

	mux, err := registrytokenwire.Build(nil, registrytokenwire.BuildConfig{
		Realm:   "https://api.kacho.local/iam/token",
		Service: "registry.kacho.local",
	})
	if err != nil {
		t.Fatalf("build registry-token mux: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// (а) Открытым текстом эндпоинт НЕ обслуживается: запрос до обработчика не
	// доходит, поэтому вызывающий не получает ни 401-вызова, ни заголовка вызова —
	// то есть штатному клиенту (docker идёт по realm) предъявить приватный ключ на
	// открытом проводе просто некуда. Утверждение точное, а не «любой из исходов»:
	// признак — отсутствие ответа ИМЕННО этого обработчика.
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + addr + "/iam/token") //nolint:noctx // короткий локальный запрос
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "" {
			t.Fatalf("cleartext request REACHED the token handler (HTTP %d, WWW-Authenticate %q) — "+
				"the service-account private key would still transit in the clear on this hop",
				resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}

	// (б) По TLS с доверием к тому же CA — штатный вызов.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA is not parseable")
	}
	secure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	resp, err = secure.Get("https://" + addr + "/iam/token") //nolint:noctx // короткий локальный запрос
	if err != nil {
		t.Fatalf("TLS client could not reach the token endpoint: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("TLS GET /iam/token = %d, want 401 challenge", resp.StatusCode)
	}
}

// TestServeCarriesRegistryTokenTLSIntoItsSurface — гейт композиционного корня:
// собранный транспорт обязан ДОЕХАТЬ до объявления поверхности выдачи токена.
//
// Прежняя редакция искала здесь литерал обёртки слушателя. Обёртка переехала на
// этаж ниже — её надевает профиль не-gRPC поверхности, — и продолжать искать имя
// снятого поля значило бы требовать дефекта. Предмет при этом не изменился и не
// ослаблен: снять транспорт с этого хопа по-прежнему нельзя, а доказывается это
// теперь ДВУМЯ пробами вместо одной текстовой —
// `TestSurfaceDeclaredTLSReachesTheListener` (pkg/servicehost, на проводе) и той
// частью проверки ниже, которая принадлежит именно этому корню.
func TestServeCarriesRegistryTokenTLSIntoItsSurface(t *testing.T) {
	src := readFileT(t, "serve.go")
	for _, want := range []string{
		"mtlsCfg.RegistryTokenServerTLSConfig()",
		"TLS: registryTokenTLSConfig,",
		"requireRegistryTokenTLS(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: транспорт поверхности выдачи docker-токена не доехал: нет %q", want)
		}
	}
}

// writeSelfSignedCert кладёт в dir самоподписанный leaf (tls.crt/tls.key) и
// возвращает его же PEM как доверяемый корень.
func writeSelfSignedCert(t *testing.T, dir string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kacho-iam-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPEM
}
