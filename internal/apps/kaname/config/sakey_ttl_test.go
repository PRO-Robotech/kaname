// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// sakey_ttl_test.go — the SA-key lifetime knobs must have bounded defaults and
// be overridable by the flat env names the deploy chart sets.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestLoad_SAKeyTTL_Defaults — the shipped defaults must be FINITE. A machine
// principal is exempt from step-up because a machine has no second factor;
// that exemption is defensible only while its credential expires on its own.
func TestLoad_SAKeyTTL_Defaults(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, 90*24*time.Hour, cfg.AuthN.SAKeyDefaultTTL,
		"an omitted ttl_seconds must resolve to a finite default, never to 'no expiry'")
	require.Equal(t, 365*24*time.Hour, cfg.AuthN.SAKeyMaxTTL,
		"there must be a shipped ceiling on how long a machine credential may live")
	require.Greater(t, cfg.AuthN.SAKeyMaxTTL, cfg.AuthN.SAKeyDefaultTTL,
		"the ceiling must leave room above the default, otherwise the default is unusable")
}

// TestLoad_SAKeyAccessTokenTTL_DefaultsToProviderInherit — the per-client token
// lifespan defaults to unset so an existing deployment is unchanged until its
// profile pins a value. Pinning it is a deploy-profile decision (values.prod
// does), not a silent behaviour change on upgrade.
func TestLoad_SAKeyAccessTokenTTL_DefaultsToProviderInherit(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Zero(t, cfg.AuthN.SAKeyAccessTokenTTL)
}

// TestLoad_SAKeyTTL_EnvOverride — the flat env names the chart emits win.
func TestLoad_SAKeyTTL_EnvOverride(t *testing.T) {
	t.Setenv("KANAME_SAKEY_DEFAULT_TTL", "720h")
	t.Setenv("KANAME_SAKEY_MAX_TTL", "1440h")
	t.Setenv("KANAME_SAKEY_ACCESS_TOKEN_TTL", "15m")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, 720*time.Hour, cfg.AuthN.SAKeyDefaultTTL)
	require.Equal(t, 1440*time.Hour, cfg.AuthN.SAKeyMaxTTL)
	require.Equal(t, 15*time.Minute, cfg.AuthN.SAKeyAccessTokenTTL)
}

// TestLoad_SAKeyBindDPoP_DefaultsOff — the issuance half of machine-token
// binding must be opt-in. Binding is per-client REGISTRATION metadata, so it
// only affects keys issued after it is on; turning the edge requirement on
// first would reject every existing service-account token.
func TestLoad_SAKeyBindDPoP_DefaultsOff(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.False(t, cfg.AuthN.SAKeyBindDPoP)
}

// TestLoad_SAKeyBindDPoP_EnvOverride — the flat env name the chart emits wins.
func TestLoad_SAKeyBindDPoP_EnvOverride(t *testing.T) {
	t.Setenv("KANAME_SAKEY_BIND_DPOP", "true")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.True(t, cfg.AuthN.SAKeyBindDPoP)
}
