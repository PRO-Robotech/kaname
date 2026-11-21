// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// kaname#1034: privileged credential попадает только в настоящий init-container.
func TestAuthorityMigrationCredentialStaysInInitContainer(t *testing.T) {
	for _, separate := range []bool{false, true} {
		settings := []string{}
		if separate {
			settings = []string{"db.migrationDSNSecretName=authority-migration", "db.migrationDSNSecretKey=dsn"}
		}
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
		require.NoError(t, err)
		found := 0
		migrators := 0
		specs := podSpecsOfDeployments(t, out)
		require.NotEmpty(t, specs)
		for _, spec := range specs {
			for _, kind := range []string{"initContainers", "containers"} {
				containers, _ := spec[kind].([]any)
				for _, raw := range containers {
					container := raw.(map[string]any)
					env, _ := container["env"].([]any)
					if container["name"] == "migrate" {
						migrators++
						require.Equal(t, []any{"/usr/local/bin/kaname-migrator", "up"}, container["command"], "прямой CLI без shell/дополнительного --dsn")
						addressEnv := map[string]any{}
						for _, item := range env {
							e := item.(map[string]any)
							addressEnv[e["name"].(string)] = e
						}
						mounts, _ := container["volumeMounts"].([]any)
						configMounted := false
						for _, rawMount := range mounts {
							mount := rawMount.(map[string]any)
							if mount["name"] == "config" {
								configMounted = true
							}
						}
						if separate {
							require.NotContains(t, addressEnv, "KANAME_CONFIG_PATH", "resolveDSN отвергает файл службы вместе с MIGRATOR_DSN")
							require.NotContains(t, addressEnv, "KANAME_DB_PASSWORD")
							require.False(t, configMounted)
						} else {
							require.Equal(t, "/etc/kaname/config.yaml", addressEnv["KANAME_CONFIG_PATH"].(map[string]any)["value"])
							require.Contains(t, addressEnv, "KANAME_DB_PASSWORD")
							require.True(t, configMounted)
						}
					}
					for _, item := range env {
						e := item.(map[string]any)
						if e["name"] != "MIGRATOR_DSN" {
							continue
						}
						require.True(t, separate)
						require.Equal(t, "initContainers", kind)
						require.Equal(t, "migrate", container["name"])
						from := e["valueFrom"].(map[string]any)
						secret := from["secretKeyRef"].(map[string]any)
						require.Equal(t, "authority-migration", secret["name"])
						require.Equal(t, "dsn", secret["key"])
						found++
					}
				}
			}
		}
		require.Equal(t, 1, migrators)
		if separate {
			require.Equal(t, 1, found)
		} else {
			require.Zero(t, found)
		}
	}
	for _, setting := range []string{"db.migrationDSNSecretName=authority-migration", "db.migrationDSNSecretKey=dsn"} {
		_, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(setting)...)
		require.Error(t, err, "неполная пара не должна возвращаться к runtime credential")
	}
}

// kaname#1034: legacy — явное умолчание, participant только по настройке.
func TestAuthorityParticipationChartRendersTheProcessSection(t *testing.T) {
	for _, tc := range []struct{ setting, want string }{
		{"", "legacy"}, {"authorityProtocol.participation=participant", "participant"},
	} {
		settings := []string{}
		if tc.setting != "" {
			settings = append(settings, tc.setting)
		}
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
		require.NoError(t, err)
		require.Contains(t, out, "authority-protocol:")
		require.Contains(t, out, "participation: \""+tc.want+"\"")
	}
}
