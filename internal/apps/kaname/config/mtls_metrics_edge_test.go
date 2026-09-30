// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// P0 hardening — the :9095 /metrics listener was PLAINTEXT (net.Listen). These
// tests pin the per-edge, default-off server-side mTLS contract for the HTTP
// listener, mirroring SEC-H (grpcsrv.TLSServer per-edge envconfig +
// fail-closed). Env family: KANAME_METRICS_SERVER_MTLS_*.
//
// The hooks listener of the external identity provider (:9092) was pinned here
// too; it is gone with the provider (kaname#363), and the per-edge independence
// probe below pairs the metrics edge with the key-set publisher instead.

// TestMTLS_Metrics_DisabledDefaultPlaintext — DEFAULT-OFF for the /metrics edge.
func TestMTLS_Metrics_DisabledDefaultPlaintext(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.False(t, m.MetricsServerMTLS.Enable, "metrics server mTLS off by default")

	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err, "disabled edge must not error")
	assert.Nil(t, cfg, "disabled metrics edge → nil *tls.Config (plaintext listener)")
}

// TestMTLS_Metrics_EnabledNoCertErrors — enable=true but no cert-trio → fail-closed.
func TestMTLS_Metrics_EnabledNoCertErrors(t *testing.T) {
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.True(t, m.MetricsServerMTLS.Enable)
	_, err = m.MetricsServerTLSConfig()
	require.Error(t, err, "enabled metrics mTLS without a valid cert-trio must fail-closed")
}

// TestMTLS_Metrics_EnabledMutualBuildsRequireAndVerifyClientCert — metrics
// clientAuthMode=mutual builds RequireAndVerifyClientCert (the option ready for a
// future internal-CA scrape client). Default is server-tls-only (5.5).
func TestMTLS_Metrics_EnabledMutualBuildsRequireAndVerifyClientCert(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KANAME_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.True(t, m.MetricsServerMTLS.Enable)
	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// TestMTLS_JWKSProxyMetrics_PerEdgeIndependent — the key-set publisher edge
// enable=true while metrics enable=false → the two HTTP edges resolve
// independently (per-edge rollback), AND they are independent of the gRPC
// public/internal edges.
func TestMTLS_JWKSProxyMetrics_PerEdgeIndependent(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_JWKSPROXY_SERVER_MTLS_CLIENTCAFILES", caFile)
	// metrics + public + internal intentionally left unset → enable=false.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.True(t, m.JWKSProxyServerMTLS.Enable, "key-set publisher edge on")
	assert.False(t, m.MetricsServerMTLS.Enable, "metrics edge stays off, independent")
	assert.False(t, m.PublicServerMTLS.Enable, "public gRPC edge unaffected")
	assert.False(t, m.InternalServerMTLS.Enable, "internal gRPC edge unaffected")

	jwksCfg, err := m.JWKSProxyServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, jwksCfg)
	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	assert.Nil(t, metricsCfg, "metrics disabled → nil (plaintext)")
}

// TestMTLS_Validate_FailClosedWhenEnabledNoCert — MTLSConfig.Validate() reports a
// fail-closed error for any edge that is enabled without a complete cert-trio
// (used by the composition root so a misconfigured prod boot fails fast).
func TestMTLS_Validate_FailClosedWhenEnabledNoCert(t *testing.T) {
	t.Setenv("KANAME_METRICS_SERVER_MTLS_ENABLE", "true")
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	err = m.Validate()
	require.Error(t, err, "metrics enabled without cert paths must fail Validate")
}

// TestMTLS_Validate_OKWhenDisabled — all edges off → Validate passes (default-off,
// zero regression).
func TestMTLS_Validate_OKWhenDisabled(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "all edges off → Validate clean")
}
