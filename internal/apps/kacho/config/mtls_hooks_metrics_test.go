// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// P0 hardening — the :9092 Hydra/Kratos hooks listener and the :9095 /metrics
// listener were PLAINTEXT (net.Listen). These tests pin the per-edge, default-off
// server-side mTLS contract for both HTTP listeners, mirroring SEC-H
// (grpcsrv.TLSServer per-edge envconfig + fail-closed). Env families:
// KACHO_IAM_HOOKS_SERVER_MTLS_* / KACHO_IAM_METRICS_SERVER_MTLS_*.

// TestMTLS_Hooks_DisabledDefaultPlaintext — DEFAULT-OFF: no mTLS env set → the
// hooks edge is off (zero-value); HooksServerTLSConfig() returns (nil, nil) — the
// caller serves PLAINTEXT, byte-identical to today (dev/newman stand unchanged).
func TestMTLS_Hooks_DisabledDefaultPlaintext(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.False(t, m.HooksServerMTLS.Enable, "hooks server mTLS off by default")

	cfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err, "disabled edge must not error")
	assert.Nil(t, cfg, "disabled hooks edge → nil *tls.Config (plaintext listener)")
}

// TestMTLS_Metrics_DisabledDefaultPlaintext — DEFAULT-OFF for the /metrics edge.
func TestMTLS_Metrics_DisabledDefaultPlaintext(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.False(t, m.MetricsServerMTLS.Enable, "metrics server mTLS off by default")

	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err, "disabled edge must not error")
	assert.Nil(t, cfg, "disabled metrics edge → nil *tls.Config (plaintext listener)")
}

// TestMTLS_Hooks_EnabledNoCertErrors — enable=true but no/bad cert-trio →
// HooksServerTLSConfig() returns an error (fail-closed, never silent plaintext;
// ban #11).
func TestMTLS_Hooks_EnabledNoCertErrors(t *testing.T) {
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	// no CERTFILE/KEYFILE/CLIENTCAFILES → fail-closed.
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.True(t, m.HooksServerMTLS.Enable)
	_, err = m.HooksServerTLSConfig()
	require.Error(t, err, "enabled hooks mTLS without a valid cert-trio must fail-closed")
}

// TestMTLS_Metrics_EnabledNoCertErrors — enable=true but no cert-trio → fail-closed.
func TestMTLS_Metrics_EnabledNoCertErrors(t *testing.T) {
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.True(t, m.MetricsServerMTLS.Enable)
	_, err = m.MetricsServerTLSConfig()
	require.Error(t, err, "enabled metrics mTLS without a valid cert-trio must fail-closed")
}

// TestMTLS_Hooks_EnabledMutualBuildsRequireAndVerifyClientCert — hooks
// clientAuthMode=mutual with a valid server cert + client-CA builds a *tls.Config
// with RequireAndVerifyClientCert + MinVersion TLS1.2. (Sub-phase 5.5: mutual is
// no longer the DEFAULT for hooks — it must be requested explicitly; the default
// is server-tls-only. See mtls_clientauthmode_test.go.)
func TestMTLS_Hooks_EnabledMutualBuildsRequireAndVerifyClientCert(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.True(t, m.HooksServerMTLS.Enable)
	cfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err, "valid cert-trio → *tls.Config builds")
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth, "mutual → RequireAndVerifyClientCert")
	assert.NotNil(t, cfg.ClientCAs, "client CA pool set")
	assert.Len(t, cfg.Certificates, 1, "server cert presented")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// TestMTLS_Metrics_EnabledMutualBuildsRequireAndVerifyClientCert — metrics
// clientAuthMode=mutual builds RequireAndVerifyClientCert (the option ready for a
// future internal-CA scrape client). Default is server-tls-only (5.5).
func TestMTLS_Metrics_EnabledMutualBuildsRequireAndVerifyClientCert(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KACHO_IAM_METRICS_SERVER_MTLS_CLIENTAUTHMODE", "mutual")

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.True(t, m.MetricsServerMTLS.Enable)
	cfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// TestMTLS_HooksMetrics_PerEdgeIndependent — hooks enable=true while metrics
// enable=false → the two new edges resolve independently (per-edge rollback),
// AND they are independent of the gRPC public/internal edges.
func TestMTLS_HooksMetrics_PerEdgeIndependent(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_CLIENTCAFILES", caFile)
	// metrics + public + internal intentionally left unset → enable=false.

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	assert.True(t, m.HooksServerMTLS.Enable, "hooks edge on")
	assert.False(t, m.MetricsServerMTLS.Enable, "metrics edge stays off, independent")
	assert.False(t, m.PublicServerMTLS.Enable, "public gRPC edge unaffected")
	assert.False(t, m.InternalServerMTLS.Enable, "internal gRPC edge unaffected")

	hooksCfg, err := m.HooksServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, hooksCfg)
	metricsCfg, err := m.MetricsServerTLSConfig()
	require.NoError(t, err)
	assert.Nil(t, metricsCfg, "metrics disabled → nil (plaintext)")
}

// TestMTLS_Validate_FailClosedWhenEnabledNoCert — MTLSConfig.Validate() reports a
// fail-closed error for any edge that is enabled without a complete cert-trio
// (used by the composition root so a misconfigured prod boot fails fast).
func TestMTLS_Validate_FailClosedWhenEnabledNoCert(t *testing.T) {
	t.Setenv("KACHO_IAM_HOOKS_SERVER_MTLS_ENABLE", "true")
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	err = m.Validate()
	require.Error(t, err, "hooks enabled without cert paths must fail Validate")
}

// TestMTLS_Validate_OKWhenDisabled — all edges off → Validate passes (default-off,
// zero regression).
func TestMTLS_Validate_OKWhenDisabled(t *testing.T) {
	m, err := config.LoadMTLS()
	require.NoError(t, err)
	require.NoError(t, m.Validate(), "all edges off → Validate clean")
}
