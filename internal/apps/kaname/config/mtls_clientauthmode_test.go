// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Sub-phase 5.5 — per-edge clientAuthMode for the HTTP listeners. Written for the
// hooks (:9092) and metrics (:9095) listeners; the hooks listener of the external
// identity provider is gone with it (kaname#363), and the scenarios that were
// about the edge MECHANICS (not about the hooks' HMAC) are held here on the
// key-set publisher (:9097) and metrics edges. The :9092 server-side mTLS was
// SHIPPED but gated OFF in prod (#122/#137) because serverTLSConfig hardcoded
// ClientAuth = RequireAndVerifyClientCert, which rejected the HMAC-authed
// webhooks (no client cert) at the TLS handshake. 5.5 introduced a per-edge
// clientAuthMode:
//
//   - "server-tls-only" → tls.NoClientCert (encryption only; client-CA NOT required;
//     for edges whose caller presents no client cert — the metrics scrape and
//     the key-set publisher's registry data plane);
//   - "mutual"          → tls.RequireAndVerifyClientCert (current behaviour; needs
//     a full cert-trio incl. client-CA);
//   - unknown mode      → fail-closed error (never default to insecure);
//   - empty/unset mode  → explicit safe per-edge default (server-tls-only for the
//     metrics and key-set publisher edges).
//
// Env families: KANAME_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE /
// KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE (read via the existing
// config.LoadPrefixed("KANAME") envconfig hierarchy).

// ── Scenario 5.5-01 — server-tls-only → NoClientCert, no client-CA needed ──
func TestMTLS_55_01_JWKSProxyServerTLSOnly_NoClientCert(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")
	// CLIENTCAFILES intentionally UNSET — server-tls-only must not require it.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.True(t, m.JWKSProxyServerMTLS.Enable)

	cfg, err := m.JWKSProxyServerTLSConfig()
	require.NoError(t, err, "server-tls-only with no client-CA must NOT error")
	require.NotNil(t, cfg)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth,
		"server-tls-only → NoClientCert (the registry data plane presents no client cert)")
	assert.Len(t, cfg.Certificates, 1, "server cert presented (tls.crt/tls.key)")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// ── Scenario 5.5-02 — metrics mutual → RequireAndVerifyClientCert + client-CA pool ──
func TestMTLS_55_02_MetricsMutual_RequireAndVerify(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth, "mutual → RequireAndVerifyClientCert")
	assert.NotNil(t, cfg.ClientCAs, "mutual builds a client-CA pool from CLIENTCAFILES")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// ── Scenario 5.5-03 — edge disabled → (nil, nil); cert files NOT read ──
func TestMTLS_55_03_Disabled_NilNoRead(t *testing.T) {
	// A non-existent cert path proves the builder does NOT read files when disabled.
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CERTFILE", "/nonexistent/tls.crt")
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_KEYFILE", "/nonexistent/tls.key")
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE", "mutual")
	// ENABLE intentionally unset → false.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.False(t, m.JWKSProxyServerMTLS.Enable)

	jwksCfg, err := m.JWKSProxyServerTLSConfig()
	require.NoError(t, err, "disabled edge must not error even with bad paths")
	assert.Nil(t, jwksCfg, "disabled key-set publisher edge → nil *tls.Config (plaintext)")

	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	assert.Nil(t, metricsCfg, "disabled metrics edge → nil *tls.Config (plaintext)")
}

// ── Scenario 5.5-04 — enabled with incomplete cert-trio → Validate fail-closed ──
func TestMTLS_55_04_EnabledNoCert_ValidateFailClosed(t *testing.T) {
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")
	// no CERTFILE/KEYFILE → fail-closed even in server-tls-only mode.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	err = m.Validate()
	require.Error(t, err, "metrics enabled without cert/key must fail Validate (fail-closed, ban #11)")
	assert.Contains(t, err.Error(), "metrics-server mTLS edge")
	assert.Contains(t, err.Error(), "cert_file/key_file is empty")
}

// ── Scenario 5.5-05 — mutual + empty client-CA → fail-closed; server-tls-only + empty CA → OK ──
func TestMTLS_55_05_MutualEmptyCA_FailClosed(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")
	// CLIENTCAFILES intentionally empty → mutual requires it → fail-closed.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	err = m.Validate()
	require.Error(t, err, "mutual without client-CA must fail Validate")
	assert.Contains(t, err.Error(), "metrics-server mTLS edge")
	assert.Contains(t, err.Error(), "clientAuthMode=mutual requires a non-empty client_ca_files")
}

// TestMTLS_55_05b_ServerTLSOnlyEmptyCA_OK — boundary: server-tls-only + empty
// client-CA passes Validate (client-cert not verified → no client-CA needed).
func TestMTLS_55_05b_ServerTLSOnlyEmptyCA_OK(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "server-tls-only without client-CA must pass Validate")
	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
}

// ── Scenario 5.5-06 — unknown clientAuthMode → fail-closed (never insecure default) ──
func TestMTLS_55_06_UnknownMode_FailClosed(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "open")

	m, err := config.LoadMTLS()
	require.NoError(t, err)

	// Builder fails closed on the unknown mode.
	_, berr := m.MetricsServerTLSConfig()
	require.Error(t, berr, "unknown clientAuthMode must fail-closed in the builder")
	assert.Contains(t, berr.Error(), `unknown clientAuthMode "open"`)
	assert.Contains(t, berr.Error(), "server-tls-only|mutual")

	// Validate also reports the unknown mode (boot fail-closed).
	verr := m.Validate()
	require.Error(t, verr, "unknown clientAuthMode must fail Validate")
	assert.Contains(t, verr.Error(), "metrics-server mTLS edge")
	assert.Contains(t, verr.Error(), `unknown clientAuthMode "open"`)
}

// ── Scenario 5.5-07 — default clientAuthMode per edge when unset (enabled) ──
// Key-set publisher default = server-tls-only (the registry data plane presents
// no client cert); metrics default = server-tls-only (no scrape client cert yet). The default is an
// explicit safe choice — NOT a silent fall-through to RequireAndVerifyClientCert
// (that was bug #122).
func TestMTLS_55_07_DefaultMode_ServerTLSOnly(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	// Key-set publisher: enabled, cert+key, NO clientAuthMode, NO client-CA.
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_KEYFILE", keyFile)
	// Metrics: enabled, cert+key, NO clientAuthMode, NO client-CA.
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "enabled edge with empty mode must default safely, not fail")

	jwksCfg, err := m.JWKSProxyServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, jwksCfg)
	assert.Equal(t, tls.NoClientCert, jwksCfg.ClientAuth,
		"key-set publisher default = server-tls-only → NoClientCert (NOT RequireAndVerifyClientCert; bug #122)")

	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, metricsCfg)
	assert.Equal(t, tls.NoClientCert, metricsCfg.ClientAuth,
		"metrics default = server-tls-only → NoClientCert")
}

// ── Scenario 5.5-13 (Go-httptest analogue) — plaintext http against the
// server-tls-only listener is rejected at the transport (no insecure downgrade). ──
func TestMTLS_55_13_PlaintextRejected(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	plainCl := &http.Client{Timeout: 2 * time.Second}
	resp, gerr := plainCl.Get("http://" + ln.Addr().String() + "/metrics")
	if gerr == nil {
		defer resp.Body.Close()
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"plaintext HTTP must not get a clean 200 from a server-tls-only listener")
	}
}

// ── Scenario 5.5-15 — metrics server-tls-only: CA-trusting client without a
// client cert handshakes and scrapes /metrics; plaintext is rejected. ──
func TestMTLS_55_15_MetricsServerTLSOnly_ScrapeNoClientCert(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Equal(t, tls.NoClientCert, tlsCfg.ClientAuth)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	pool := x509.NewCertPool()
	caPEM, rerr := os.ReadFile(caFile)
	require.NoError(t, rerr)
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	cl := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "kaname.kacho.svc",
			MinVersion: tls.VersionTLS12,
		}},
	}
	resp, gerr := cl.Get("https://" + ln.Addr().String() + "/metrics")
	require.NoError(t, gerr, "server-tls-only metrics must be scrapable without a client cert")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// plaintext rejected at transport.
	plainCl := &http.Client{Timeout: 2 * time.Second}
	presp, perr := plainCl.Get("http://" + ln.Addr().String() + "/metrics")
	if perr == nil {
		defer presp.Body.Close()
		require.NotEqual(t, http.StatusOK, presp.StatusCode, "plaintext /metrics must not 200 against TLS listener")
	}
}

// ── Scenario 5.5-16 (option, not in prod 5.5) — metrics mutual: a client WITH an
// internal-CA client cert is accepted; a client WITHOUT one is rejected at the
// handshake (RequireAndVerifyClientCert). Proves the mutual mode is ready. ──
func TestMTLS_55_16_MetricsMutual_ClientCertRequired(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsCfg.ClientAuth)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	pool := x509.NewCertPool()
	caPEM, rerr := os.ReadFile(caFile)
	require.NoError(t, rerr)
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	// WITH client cert → accepted.
	clientCert, lerr := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, lerr)
	withCert := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
			ServerName:   "kaname.kacho.svc",
			MinVersion:   tls.VersionTLS12,
		}},
	}
	resp, gerr := withCert.Get("https://" + ln.Addr().String() + "/metrics")
	require.NoError(t, gerr, "mutual must accept a client presenting an internal-CA client cert")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// WITHOUT client cert → handshake rejected.
	noCert := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "kaname.kacho.svc",
			MinVersion: tls.VersionTLS12,
		}},
	}
	nresp, nerr := noCert.Get("https://" + ln.Addr().String() + "/metrics")
	if nresp != nil {
		_ = nresp.Body.Close()
	}
	require.Error(t, nerr, "mutual must reject a client without a client cert at the handshake")
}
