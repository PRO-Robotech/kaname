// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// Sub-phase 5.5 — per-edge clientAuthMode for the HTTP hooks (:9092) + metrics
// (:9095) listeners. The :9092 server-side mTLS was SHIPPED but gated OFF in prod
// (#122/#137) because serverTLSConfig hardcoded ClientAuth =
// RequireAndVerifyClientCert, which rejects the HMAC-authed Ory webhooks (no client
// cert) at the TLS handshake. 5.5 introduces a per-edge clientAuthMode:
//
//   - "server-tls-only" → tls.NoClientCert (encryption only; client-CA NOT required;
//     for the HMAC hooks edge and the (no-cert) metrics scrape edge);
//   - "mutual"          → tls.RequireAndVerifyClientCert (current behaviour; needs
//     a full cert-trio incl. client-CA);
//   - unknown mode      → fail-closed error (never default to insecure);
//   - empty/unset mode  → explicit safe per-edge default (server-tls-only for both
//     hooks and metrics in this phase).
//
// Env families: KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE /
// KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE (read via the existing
// config.LoadPrefixed("KACHO_IAM") envconfig hierarchy).

// ── Scenario 5.5-01 — hooks server-tls-only → NoClientCert, no client-CA needed ──
func TestMTLS_55_01_HooksServerTLSOnly_NoClientCert(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")
	// CLIENTCAFILES intentionally UNSET — server-tls-only must not require it.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.True(t, m.HooksServerMTLS.Enable)

	cfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err, "server-tls-only with no client-CA must NOT error")
	require.NotNil(t, cfg)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth,
		"server-tls-only → NoClientCert (Ory webhooks present no client cert)")
	assert.Len(t, cfg.Certificates, 1, "server cert presented (tls.crt/tls.key)")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// ── Scenario 5.5-02 — metrics mutual → RequireAndVerifyClientCert + client-CA pool ──
func TestMTLS_55_02_MetricsMutual_RequireAndVerify(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

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
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", "/nonexistent/tls.crt")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", "/nonexistent/tls.key")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")
	// ENABLE intentionally unset → false.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.False(t, m.HooksServerMTLS.Enable)

	hooksCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err, "disabled edge must not error even with bad paths")
	assert.Nil(t, hooksCfg, "disabled hooks edge → nil *tls.Config (plaintext)")

	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	assert.Nil(t, metricsCfg, "disabled metrics edge → nil *tls.Config (plaintext)")
}

// ── Scenario 5.5-04 — enabled with incomplete cert-trio → Validate fail-closed ──
func TestMTLS_55_04_EnabledNoCert_ValidateFailClosed(t *testing.T) {
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")
	// no CERTFILE/KEYFILE → fail-closed even in server-tls-only mode.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	err = m.Validate()
	require.Error(t, err, "hooks enabled without cert/key must fail Validate (fail-closed, ban #11)")
	assert.Contains(t, err.Error(), "hooks-server mTLS edge")
	assert.Contains(t, err.Error(), "cert_file/key_file is empty")
}

// ── Scenario 5.5-05 — mutual + empty client-CA → fail-closed; server-tls-only + empty CA → OK ──
func TestMTLS_55_05_MutualEmptyCA_FailClosed(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")
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
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

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
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "open")

	m, err := config.LoadMTLS()
	require.NoError(t, err)

	// Builder fails closed on the unknown mode.
	_, berr := m.HooksServerTLSConfig()
	require.Error(t, berr, "unknown clientAuthMode must fail-closed in the builder")
	assert.Contains(t, berr.Error(), `unknown clientAuthMode "open"`)
	assert.Contains(t, berr.Error(), "server-tls-only|mutual")

	// Validate also reports the unknown mode (boot fail-closed).
	verr := m.Validate()
	require.Error(t, verr, "unknown clientAuthMode must fail Validate")
	assert.Contains(t, verr.Error(), "hooks-server mTLS edge")
	assert.Contains(t, verr.Error(), `unknown clientAuthMode "open"`)
}

// ── Scenario 5.5-07 — default clientAuthMode per edge when unset (enabled) ──
// Hooks default = server-tls-only (Ory cannot present a client cert); metrics
// default = server-tls-only (no scrape client cert yet). The default is an
// explicit safe choice — NOT a silent fall-through to RequireAndVerifyClientCert
// (that was bug #122).
func TestMTLS_55_07_DefaultMode_ServerTLSOnly(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	// Hooks: enabled, cert+key, NO clientAuthMode, NO client-CA.
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	// Metrics: enabled, cert+key, NO clientAuthMode, NO client-CA.
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "enabled edge with empty mode must default safely, not fail")

	hooksCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, hooksCfg)
	assert.Equal(t, tls.NoClientCert, hooksCfg.ClientAuth,
		"hooks default = server-tls-only → NoClientCert (NOT RequireAndVerifyClientCert; bug #122)")

	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, metricsCfg)
	assert.Equal(t, tls.NoClientCert, metricsCfg.ClientAuth,
		"metrics default = server-tls-only → NoClientCert")
}

// ── Scenario 5.5-12 / 5.5-14 (Go-httptest analogue) — hooks server-tls-only:
// a CA-trusting client WITHOUT a client cert handshakes OK; HMAC is independent
// of TLS (no token → 401). Proves removing the client-cert requirement did NOT
// open the edge to unauthenticated callers. ──
func TestMTLS_55_12_HooksServerTLSOnly_HandshakeOK_HMACIndependent(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// Stand up a TLS listener wired exactly as serve.go does. The handler mirrors
	// the requireHookAuth contract: missing HMAC → 401 invalid_hook_token.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()

	const expectedToken = "test-hook-secret"
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Kacho-Hook-Token") != expectedToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kacho-iam-hooks"`)
			http.Error(w, `{"error":"invalid_hook_token"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// CA-trusting client WITHOUT a client cert → handshake must succeed
	// (server-tls-only does not request a client cert).
	pool := x509.NewCertPool()
	caPEM, rerr := os.ReadFile(caFile)
	require.NoError(t, rerr)
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	cl := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "kacho-iam.kacho.svc.cluster.local",
			MinVersion: tls.VersionTLS12,
			// NO Certificates → no client cert presented.
		}},
	}

	// Valid HMAC → 200 (5.5-12 analogue): handshake + HMAC pass.
	reqOK, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/iam/v1/hooks/token", http.NoBody)
	reqOK.Header.Set("X-Kacho-Hook-Token", expectedToken)
	respOK, err := cl.Do(reqOK)
	require.NoError(t, err, "server-tls-only must accept a CA-trusting client without a client cert")
	defer respOK.Body.Close()
	assert.Equal(t, http.StatusOK, respOK.StatusCode)

	// No HMAC → 401 (5.5-14 analogue): TLS up, HMAC barrier intact.
	reqNoAuth, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/iam/v1/hooks/token", http.NoBody)
	respNoAuth, err := cl.Do(reqNoAuth)
	require.NoError(t, err, "handshake still succeeds without HMAC")
	defer respNoAuth.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, respNoAuth.StatusCode,
		"TLS does NOT replace HMAC — no token → 401")
	assert.Equal(t, `Bearer realm="kacho-iam-hooks"`, respNoAuth.Header.Get("WWW-Authenticate"))
}

// ── Scenario 5.5-13 (Go-httptest analogue) — plaintext http against the
// server-tls-only listener is rejected at the transport (no insecure downgrade). ──
func TestMTLS_55_13_PlaintextRejected(t *testing.T) {
	certFile, keyFile, _ := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.HooksServerTLSConfig()
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
	resp, gerr := plainCl.Get("http://" + ln.Addr().String() + "/iam/v1/hooks/token")
	if gerr == nil {
		defer resp.Body.Close()
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"plaintext HTTP must not get a clean 200 from a server-tls-only listener")
	}
}

// ── Scenario 5.5-14b (Go-httptest analogue) — Kratos provision endpoint, TLS OK
// but NO HMAC → 401: server-tls-only did not open provision to unauthenticated
// callers (same requireHookAuth as token/refresh). ──
func TestMTLS_55_14b_ProvisionNoHMAC_401(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// provision uses the SAME requireHookAuth contract as token/refresh.
		if r.Header.Get("X-Kacho-Hook-Token") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kacho-iam-hooks"`)
			http.Error(w, `{"error":"invalid_hook_token"}`, http.StatusUnauthorized)
			return
		}
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
			ServerName: "kacho-iam.kacho.svc.cluster.local",
			MinVersion: tls.VersionTLS12,
		}},
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/iam/v1/hooks/provision", http.NoBody)
	resp, derr := cl.Do(req)
	require.NoError(t, derr, "TLS handshake succeeds for provision without a client cert")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"provision without HMAC → 401 (HMAC barrier symmetric across all three hook endpoints)")
}

// ── Scenario 5.5-15 — metrics server-tls-only: CA-trusting client without a
// client cert handshakes and scrapes /metrics; plaintext is rejected. ──
func TestMTLS_55_15_MetricsServerTLSOnly_ScrapeNoClientCert(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "server-tls-only")

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
			ServerName: "kacho-iam.kacho.svc.cluster.local",
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
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

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
			ServerName:   "kacho-iam.kacho.svc.cluster.local",
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
			ServerName: "kacho-iam.kacho.svc.cluster.local",
			MinVersion: tls.VersionTLS12,
		}},
	}
	nresp, nerr := noCert.Get("https://" + ln.Addr().String() + "/metrics")
	if nresp != nil {
		_ = nresp.Body.Close()
	}
	require.Error(t, nerr, "mutual must reject a client without a client cert at the handshake")
}
