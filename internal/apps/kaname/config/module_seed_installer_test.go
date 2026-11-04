// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/stretchr/testify/require"
)

func TestModuleSeedInstallerLiteralInputPresence(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		present      bool
		target       string
	}{
		{"omission", "", false, ""},
		{"explicit null", "  tenantAccountId: null\n", true, ""},
		{"explicit empty", "  tenantAccountId: ''\n", true, ""},
		{"single tenant", "  tenantAccountId: acc_0123456789abcdefg\n", true, "acc_0123456789abcdefg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte("moduleSeedInstaller:\n  credentialFile: /run/secrets/C.json\n"+tc.suffix), 0600))
			cfg, err := config.Load(path)
			require.NoError(t, err)
			require.Equal(t, "/run/secrets/C.json", cfg.ModuleSeedInstaller.CredentialFile)
			if !tc.present {
				require.Nil(t, cfg.ModuleSeedInstaller.TenantAccountID)
			} else {
				require.NotNil(t, cfg.ModuleSeedInstaller.TenantAccountID)
				require.Equal(t, tc.target, *cfg.ModuleSeedInstaller.TenantAccountID)
			}
		})
	}
}

func TestModuleSeedInstallerExplicitEmptyEnvironmentIsPresent(t *testing.T) {
	t.Setenv("KANAME_MODULESEEDINSTALLER__TENANTACCOUNTID", "")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg.ModuleSeedInstaller.TenantAccountID)
	require.Empty(t, *cfg.ModuleSeedInstaller.TenantAccountID)
}
