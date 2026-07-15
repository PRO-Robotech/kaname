// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// unsetAuthModeEnv removes both the legacy and the namespaced AUTH_MODE env
// vars for the duration of the test so Load() exercises the compiled-in default.
func unsetAuthModeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"KACHO_IAM_AUTH_MODE", "KACHO_IAM_AUTHN__MODE"} {
		if old, ok := os.LookupEnv(k); ok {
			require.NoError(t, os.Unsetenv(k))
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
	}
}

// TestLoad_UnsetMode_DefaultsToFailClosed — an un-configured binary (no YAML,
// no AUTH_MODE env) must resolve to a fail-closed production mode, NOT the
// anonymous-allowed dev mode. Safe-by-default posture (prod-readiness F14):
// forgetting to set authn.mode must never silently open the service to
// anonymous full-access. Local fixtures opt INTO dev explicitly.
func TestLoad_UnsetMode_DefaultsToFailClosed(t *testing.T) {
	unsetAuthModeEnv(t)

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.True(t, cfg.AuthN.Mode.IsProduction(),
		"unset authn.mode must resolve to a fail-closed production mode, got %q", cfg.AuthN.Mode)
	require.Equal(t, config.ModeProduction, cfg.AuthN.Mode,
		"compiled-in default must be production (fail-closed), not dev (anonymous-allowed)")
}

// TestLoad_ExplicitDevMode_OptIn — local fixtures can still explicitly select
// dev mode (anonymous-allowed); the secure default must not break the opt-in.
func TestLoad_ExplicitDevMode_OptIn(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTH_MODE", "dev")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, config.ModeDev, cfg.AuthN.Mode,
		"explicit KACHO_IAM_AUTH_MODE=dev must select dev mode")
}
