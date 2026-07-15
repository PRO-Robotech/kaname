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

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestMTLS_Hooks_DefaultOffServesPlaintext — behavioural proof that the
// DEFAULT-OFF hooks edge yields a PLAINTEXT listener byte-identical to today: a
// plain HTTP client (no TLS) reaches it. Mirrors how serve.go wires the listener
// (build *tls.Config; nil → no tls.NewListener wrap).
func TestMTLS_Hooks_DefaultOffServesPlaintext(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)

	tlsCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err)
	require.Nil(t, tlsCfg, "default-off → nil (no TLS wrap)")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// serve.go: only wraps when tlsCfg != nil → here it stays the raw plaintext
	// listener, exactly as today.
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// Plain HTTP (no TLS) succeeds → confirms plaintext transport unchanged.
	cl := &http.Client{Timeout: 2 * time.Second}
	resp, err := cl.Get("http://" + ln.Addr().String() + "/")
	require.NoError(t, err, "default-off hooks listener must accept plaintext HTTP")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestMTLS_Metrics_EnabledRejectsPlaintext — behavioural proof that when the
// metrics edge is ENABLED (clientAuthMode=mutual), the listener is TLS-wrapped and
// a plaintext HTTP client is rejected (no silent downgrade). Uses the same wiring
// as serve.go. (5.5: explicit mutual — server-tls-only is the new default.)
func TestMTLS_Metrics_EnabledRejectsPlaintext(t *testing.T) {
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
	require.NotNil(t, tlsCfg, "enabled → TLS-wrapped")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// Plaintext HTTP against a TLS listener must NOT yield a clean 200 — the TLS
	// listener rejects the bare HTTP request (no silent plaintext downgrade).
	plainCl := &http.Client{Timeout: 2 * time.Second}
	resp, err := plainCl.Get("http://" + ln.Addr().String() + "/")
	if err == nil {
		defer resp.Body.Close()
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"plaintext HTTP must not get a 200 from a TLS-enabled metrics listener")
	}

	// A TLS client trusting the server cert handshakes and reaches the handler →
	// proves the listener is genuinely TLS (not broken). Client presents the
	// internal-CA cert (RequireAndVerifyClientCert).
	clientCert, lerr := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, lerr)
	pool := x509.NewCertPool()
	caPEM, rerr := os.ReadFile(caFile)
	require.NoError(t, rerr)
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	tlsCl := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
			ServerName:   "kacho-iam.kacho.svc.cluster.local",
			MinVersion:   tls.VersionTLS12,
		}},
	}
	tresp, terr := tlsCl.Get("https://" + ln.Addr().String() + "/")
	require.NoError(t, terr, "mTLS client must reach the TLS-enabled metrics listener")
	defer tresp.Body.Close()
	require.Equal(t, http.StatusOK, tresp.StatusCode)
}
