// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Настоящий Helm→файл→Config→страж держит оба раздела одновременно.
// Отсутствие writer plan остаётся отказом, явная пустота не становится выдачей.
func TestRenderedInstallerAndRegistrationWriterPlanTogether(t *testing.T) {
	tenant := "acc00000000000000001"
	for _, tc := range []struct {
		name string
		plan *installruntime.RegistrationWriterPlan
	}{
		{"omitted", nil},
		{"explicit-empty", installruntime.EmptyRegistrationWriterPlan()},
		{"exact-registry", installruntime.RegistryRegistrationWriterPlan([]string{tenant})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := chartCopy(t)
			doc := map[string]any{"moduleSeedInstaller": map[string]any{"credentialFile": "/run/secrets/C.json", "tenantAccountId": tenant}}
			if tc.plan != nil {
				doc["registrationAccountWriters"] = tc.plan
			}
			overlay, err := yaml.Marshal(doc)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "writer-installer.yaml"), overlay, 0600))
			profiles := append(append([]string{}, chartProfiles...), "writer-installer.yaml")
			out, err := renderChartAtAllowingFailure(t, dir, profiles, minimalOperatorCoordinates...)
			require.NoError(t, err)
			in := readRenderedInput(t, out)
			requireCleanEnv(t)
			for key, value := range in.Envs {
				t.Setenv(key, value)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(in.ConfigBody), 0600))
			cfg, err := config.Load(path)
			require.NoError(t, err)
			require.Equal(t, "/run/secrets/C.json", cfg.ModuleSeedInstaller.CredentialFile)
			require.NotNil(t, cfg.ModuleSeedInstaller.TenantAccountID)
			require.Equal(t, tenant, *cfg.ModuleSeedInstaller.TenantAccountID)
			cfg.AuthN.Mode = config.ModeProduction
			if tc.plan == nil {
				require.Nil(t, cfg.RegistrationAccountWriters)
				require.Error(t, cfg.ValidateRegistrationAccountWriters())
			} else {
				require.NoError(t, cfg.ValidateRegistrationAccountWriters())
				require.Equal(t, tc.plan.Assignments, cfg.RegistrationAccountWriters.Assignments)
				require.Equal(t, tc.plan.Disabled, cfg.RegistrationAccountWriters.Disabled)
				require.Equal(t, tc.plan.RetireClusterWriter, cfg.RegistrationAccountWriters.RetireClusterWriter)
			}
		})
	}
}
