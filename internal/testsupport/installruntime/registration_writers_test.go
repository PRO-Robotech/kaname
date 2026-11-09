// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/stretchr/testify/require"
)

// Проверяется настоящий путь файл→Load→страж, включая оба несвязанных раздела.
func TestFullStartupWriterPlanFileContract(t *testing.T) {
	tenant := "acc00000000000000001"
	for _, tc := range []struct {
		name    string
		plan    *RegistrationWriterPlan
		refused bool
	}{
		{"omission", nil, true},
		{"null-assignments", &RegistrationWriterPlan{}, true},
		{"explicit-empty", EmptyRegistrationWriterPlan(), false},
		{"concrete-registry", RegistryRegistrationWriterPlan([]string{tenant}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := map[string]any{"moduleSeedInstaller": map[string]any{"credentialFile": "/private/C.json", "tenantAccountId": tenant}}
			body, err := FullStartupConfig(doc, tc.plan)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, body, 0600))
			cfg, err := config.Load(path)
			require.NoError(t, err)
			require.Equal(t, "/private/C.json", cfg.ModuleSeedInstaller.CredentialFile)
			require.NotNil(t, cfg.ModuleSeedInstaller.TenantAccountID)
			require.Equal(t, tenant, *cfg.ModuleSeedInstaller.TenantAccountID)
			cfg.AuthN.Mode = config.ModeProduction
			if tc.refused {
				require.Error(t, cfg.ValidateRegistrationAccountWriters())
			} else {
				require.NoError(t, cfg.ValidateRegistrationAccountWriters())
				require.Equal(t, tc.plan.Assignments, cfg.RegistrationAccountWriters.Assignments)
				require.Equal(t, tc.plan.RetireClusterWriter, cfg.RegistrationAccountWriters.RetireClusterWriter)
			}
		})
	}
	for _, key := range []string{"registration-account-writers", "registrationAccountWriters", "REGISTRATION_ACCOUNT_WRITERS"} {
		_, err := FullStartupConfig(map[string]any{key: map[string]any{"assignments": []any{}}}, EmptyRegistrationWriterPlan())
		require.Error(t, err, "ExtraConfig cannot supply the typed plan")
	}
	for _, env := range []string{"KANAME_REGISTRATION_ACCOUNT_WRITERS__ASSIGNMENTS=x", "KANAME_REGISTRATION-ACCOUNT-WRITERS__ASSIGNMENTS=x", "KANAME_REGISTRATION_ACCOUNT_WRITERS=x"} {
		s := Session{Environment: []string{env}}
		require.Error(t, s.checkEnvironment(), "environment cannot override the typed plan")
	}
	first := RegistryRegistrationWriterPlan([]string{tenant})
	again := RegistryRegistrationWriterPlan([]string{tenant})
	require.Equal(t, first, again)
	cloned := CloneRegistrationWriterPlan(first)
	cloned.Assignments[0].AssignmentID += "-changed"
	require.NotEqual(t, first, cloned, "restoration evidence owns a deep copy")
}
