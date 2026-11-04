// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestProdProfile_RenderedModuleSeedInstallerPresenceAndTypes — настоящий
// Helm→Config decode, включая отсутствие/пустоту и опасное экранирование.
func TestProdProfile_RenderedModuleSeedInstallerPresenceAndTypes(t *testing.T) {
	for _, tc := range []struct {
		name, overlay, credential, tenant string
		present, refusal                  bool
	}{
		{"секция отсутствует", "", "", "", false, false},
		{"S2 только путь", "moduleSeedInstaller:\n  credentialFile: /run/secrets/C.json\n", "/run/secrets/C.json", "", false, false},
		{"S1 аккаунт", "moduleSeedInstaller:\n  credentialFile: /run/secrets/C.json\n  tenantAccountId: acc00000000000000001\n", "/run/secrets/C.json", "acc00000000000000001", true, false},
		{"явная пустота", "moduleSeedInstaller:\n  tenantAccountId: ''\n", "", "", true, false},
		{"null", "moduleSeedInstaller:\n  tenantAccountId: null\n", "", "", false, true},
		{"число", "moduleSeedInstaller:\n  tenantAccountId: 7\n", "", "", false, true},
		{"карта вместо строки", "moduleSeedInstaller:\n  tenantAccountId: {unexpected: value}\n", "", "", false, true},
		{"unknown key", "moduleSeedInstaller:\n  unknownCredentialContents: SECRET_CONTENT_SENTINEL\n", "", "", false, true},
		{"кавычки и новая строка", "moduleSeedInstaller:\n  credentialFile: \"/run/secrets/\\\"name\\nsecond\"\n  tenantAccountId: \"acc\\\"quoted\\nline\"\n", "/run/secrets/\"name\nsecond", "acc\"quoted\nline", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := chartCopy(t)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "installer-overlay.yaml"), []byte(tc.overlay), 0600))
			profiles := append(append([]string{}, chartProfiles...), "installer-overlay.yaml")
			out, err := renderChartAtAllowingFailure(t, dir, profiles, minimalOperatorCoordinates...)
			if tc.refusal {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			in := readRenderedInput(t, out)
			require.NotContains(t, in.ConfigBody, "SECRET_CONTENT_SENTINEL")
			requireCleanEnv(t)
			for k, v := range in.Envs {
				t.Setenv(k, v)
			}
			p := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(p, []byte(in.ConfigBody), 0600))
			cfg, err := config.Load(p)
			require.NoError(t, err)
			require.Equal(t, tc.credential, cfg.ModuleSeedInstaller.CredentialFile)
			if tc.present {
				require.NotNil(t, cfg.ModuleSeedInstaller.TenantAccountID)
				require.Equal(t, tc.tenant, *cfg.ModuleSeedInstaller.TenantAccountID)
			} else {
				require.Nil(t, cfg.ModuleSeedInstaller.TenantAccountID)
			}
			if tc.overlay == "" {
				require.NotContains(t, in.ConfigBody, "moduleSeedInstaller:")
			}
		})
	}
}
