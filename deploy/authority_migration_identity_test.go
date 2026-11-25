// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// kaname#1034: privileged credential попадает только в настоящий init-container.
func TestAuthorityMigrationCredentialStaysInInitContainer(t *testing.T) {
	for _, mode := range []string{"legacy", "separate", "bootstrap"} {
		separate := mode != "legacy"
		bootstrap := mode == "bootstrap"
		settings := []string{}
		if separate {
			settings = []string{"db.migrationDSNSecretName=authority-migration", "db.migrationDSNSecretKey=dsn"}
		}
		if bootstrap {
			settings = append(settings, "authorityProtocol.bootstrapRuntimeRole=actual_runtime")
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
						if bootstrap {
							require.Contains(t, []string{"migrate", "authority-bootstrap"}, container["name"])
						} else {
							require.Equal(t, "migrate", container["name"])
						}
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
		if bootstrap {
			require.Equal(t, 2, found)
		} else if separate {
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

// Bootstrap использует тот же источник модели, что служба, и отдельный owner DSN.
func TestAuthorityBootstrapUsesExplicitIdentityAndSharedDelivery(t *testing.T) {
	for _, delivery := range []bool{false, true} {
		for _, participation := range []string{"legacy", "participant"} {
			name := participation + "/image_only"
			if delivery {
				name = participation + "/mounted"
			}
			t.Run(name, func(t *testing.T) {
				settings := []string{
					"authorityProtocol.bootstrapRuntimeRole=actual_runtime",
					"authorityProtocol.participation=" + participation,
					"db.user=different_config_user",
					"db.migrationDSNSecretName=authority-migration",
					"db.migrationDSNSecretKey=dsn",
					"env.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=false",
					"secrets.KANAME_REPOSITORY__POSTGRES__URL.secretName=runtime-dsn",
					"secrets.KANAME_REPOSITORY__POSTGRES__URL.secretKey=dsn",
				}
				const dir = "/etc/kaname/delivered"
				if delivery {
					settings = append(settings, "moduleManifests.dir="+dir)
					settings = append(settings, moduleManifestsEntry(0, "registry-module-manifest", "registry.manifest.yaml")...)
					settings = append(settings, moduleManifestsEntry(1, "compute-kaname-module", "compute.manifest.yaml")...)
				}
				out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
				require.NoError(t, err)
				specs := podSpecsOfDeployments(t, out)
				require.Len(t, specs, 1)
				initContainers := specs[0]["initContainers"].([]any)
				require.Len(t, initContainers, 2)
				migrate := initContainers[0].(map[string]any)
				bootstrap := initContainers[1].(map[string]any)
				service := specs[0]["containers"].([]any)[0].(map[string]any)
				require.Equal(t, "migrate", migrate["name"])
				require.Equal(t, []any{"/usr/local/bin/kaname-migrator", "up"}, migrate["command"])
				require.Equal(t, "authority-bootstrap", bootstrap["name"])
				require.Equal(t, []any{"/usr/local/bin/kaname-migrator", "authority-bundle", "bootstrap"}, bootstrap["command"])
				require.Equal(t, service["image"], bootstrap["image"])
				require.Equal(t, migrate["image"], bootstrap["image"])
				require.Equal(t, service["imagePullPolicy"], bootstrap["imagePullPolicy"])
				require.Equal(t, migrate["securityContext"], bootstrap["securityContext"])
				require.Equal(t, []any{map[string]any{
					"name":      "MIGRATOR_DSN",
					"valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "authority-migration", "key": "dsn"}},
				}}, bootstrap["env"], "owner init получает только свой DSN, без runtime credential/config")
				require.NotContains(t, bootstrap, "envFrom")
				pd := readPodDelivery(t, out)
				if delivery {
					require.Equal(t, []any{"--runtime-role", "actual_runtime", "--manifest-dir", dir}, bootstrap["args"])
					require.Equal(t, []any{map[string]any{"name": "module-manifests", "mountPath": dir, "readOnly": true}}, bootstrap["volumeMounts"])
					require.Equal(t, "module-manifests", pd.Mounts[dir], "служба читает тот же том по тому же пути")
					require.Equal(t, dir, pd.Env["KANAME_MANIFESTS__DIR"])
					require.Equal(t, "true", pd.Env["KANAME_MANIFESTS__REQUIRED"])
					require.Equal(t, map[string]string{
						dir + "/registry.manifest.yaml": "registry-module-manifest/registry.manifest.yaml",
						dir + "/compute.manifest.yaml":  "compute-kaname-module/compute.manifest.yaml",
					}, pd.Files)
					require.Empty(t, pd.Optional)
				} else {
					require.Equal(t, []any{"--runtime-role", "actual_runtime", "--image-only"}, bootstrap["args"])
					require.NotContains(t, bootstrap, "volumeMounts")
					require.Empty(t, pd.Files)
					require.NotContains(t, pd.Env, "KANAME_MANIFESTS__DIR")
					require.NotContains(t, pd.Env, "KANAME_MANIFESTS__REQUIRED")
				}
			})
		}
	}
}

// Отсутствие явного opt-in сохраняет прежние staged/FULL пути без второго init.
func TestAuthorityBootstrapDisabledPreservesExistingInit(t *testing.T) {
	for _, settings := range [][]string{
		{"authorityProtocol.participation=legacy"},
		{"authorityProtocol.participation=participant"},
		{"authorityProtocol.participation=participant", "env.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=true"},
	} {
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
		require.NoError(t, err)
		specs := podSpecsOfDeployments(t, out)
		require.Len(t, specs, 1)
		initContainers := specs[0]["initContainers"].([]any)
		require.Len(t, initContainers, 1)
		require.Equal(t, "migrate", initContainers[0].(map[string]any)["name"])
	}
}

func TestAuthorityBootstrapRefusesAmbiguousOrIncompatibleInputs(t *testing.T) {
	base := []string{
		"authorityProtocol.bootstrapRuntimeRole=actual_runtime",
		"db.migrationDSNSecretName=authority-migration",
		"db.migrationDSNSecretKey=dsn",
	}
	type refusal struct {
		name string
		sets []string
		want string
	}
	cases := []refusal{
		{"missing_owner", []string{"db.migrationDSNSecretName=", "db.migrationDSNSecretKey="}, "db.migrationDSNSecretName"},
		{"missing_owner_name", []string{"db.migrationDSNSecretName="}, "db.migrationDSNSecretName"},
		{"missing_owner_key", []string{"db.migrationDSNSecretKey="}, "db.migrationDSNSecretKey"},
		{"whitespace_role", []string{"authorityProtocol.bootstrapRuntimeRole=   "}, "bootstrapRuntimeRole"},
		{"boolean_role", []string{"authorityProtocol.bootstrapRuntimeRole=true"}, "bootstrapRuntimeRole"},
		{"full", []string{"env.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=true"}, "FULL"},
		{"full_numeric", []string{"env.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=1"}, "FULL"},
		{"full_secret", []string{"secrets.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS.secretName=mode", "secrets.KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS.secretKey=full"}, "FULL"},
	}
	for _, knob := range deliveryEnvKeys {
		cases = append(cases,
			refusal{"manual_env_" + knob, []string{"env." + knob + "=manual"}, knob},
			refusal{"manual_secret_" + knob, []string{"secrets." + knob + ".secretName=manual", "secrets." + knob + ".secretKey=value"}, knob},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := append(append([]string{}, base...), tc.sets...)
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
			requireRenderRefusal(t, out, err, tc.want)
		})
	}
}
