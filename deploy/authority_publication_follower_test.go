// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAuthorityPublicationFollowerIsOptInAndIsolated(t *testing.T) {
	const enabled = "authorityProtocol.publicationFollower.enabled=true"
	coordinates := []string{"db.migrationDSNSecretName=authority-migration", "db.migrationDSNSecretKey=dsn"}
	for _, on := range []bool{false, true} {
		settings := append([]string{}, coordinates...)
		if on {
			settings = append(settings, enabled)
		}
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
		require.NoError(t, err)
		var followers, secretConsumers int
		var followerLabels map[string]any
		var serviceSelectors []map[string]any
		for _, doc := range strings.Split(out, "\n---") {
			var object map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(doc), &object))
			if object["kind"] == "Service" {
				serviceSelectors = append(serviceSelectors, object["spec"].(map[string]any)["selector"].(map[string]any))
			}
			if object["kind"] != "Deployment" {
				continue
			}
			spec := object["spec"].(map[string]any)
			template := spec["template"].(map[string]any)
			pod := template["spec"].(map[string]any)
			for _, kind := range []string{"initContainers", "containers"} {
				containers, _ := pod[kind].([]any)
				for _, raw := range containers {
					container := raw.(map[string]any)
					follower := container["name"] == "authority-publications"
					if follower {
						followers++
						require.Equal(t, "containers", kind)
						require.EqualValues(t, 1, spec["replicas"])
						require.Equal(t, "Recreate", spec["strategy"].(map[string]any)["type"])
						followerLabels = template["metadata"].(map[string]any)["labels"].(map[string]any)
						require.Equal(t, followerLabels, spec["selector"].(map[string]any)["matchLabels"])
						require.Equal(t, false, pod["enableServiceLinks"])
						require.Equal(t, false, pod["automountServiceAccountToken"])
						require.Equal(t, true, pod["securityContext"].(map[string]any)["runAsNonRoot"])
						require.NotContains(t, pod, "volumes")
						require.NotContains(t, pod, "initContainers")
						require.NotContains(t, container, "ports")
						require.NotContains(t, container, "envFrom")
						require.NotContains(t, container, "volumeMounts")
						require.Equal(t, []any{"/usr/local/bin/kaname-migrator", "authority-bundle", "follow-publications"}, container["command"])
						require.Equal(t, []any{"--interval", "2s"}, container["args"])
						require.NotEmpty(t, container["resources"])
						require.Equal(t, false, container["securityContext"].(map[string]any)["allowPrivilegeEscalation"])
					}
					env, _ := container["env"].([]any)
					if follower {
						require.Len(t, env, 1, "runtime env и config не наследуются")
					}
					for _, rawEnv := range env {
						e := rawEnv.(map[string]any)
						if e["name"] != "MIGRATOR_DSN" {
							continue
						}
						secretConsumers++
						require.True(t, follower || kind == "initContainers" && container["name"] == "migrate")
						require.Equal(t, map[string]any{"name": "authority-migration", "key": "dsn"}, e["valueFrom"].(map[string]any)["secretKeyRef"])
					}
				}
			}
		}
		if on {
			require.Equal(t, 1, followers)
			require.Equal(t, 2, secretConsumers, "секрет только у init и отдельного follower")
			require.NotEmpty(t, serviceSelectors)
			for _, selector := range serviceSelectors {
				matches := true
				for key, value := range selector {
					if followerLabels[key] != value {
						matches = false
					}
				}
				require.False(t, matches, "Service не должен маршрутизировать трафик к владельцу")
			}
		} else {
			require.Zero(t, followers)
			require.Equal(t, 1, secretConsumers)
		}
	}
	for _, settings := range [][]string{{enabled}, {enabled, coordinates[0]}, {enabled, coordinates[1]}} {
		_, err := renderChartAtAllowingFailure(t, ".", chartProfiles, withOperatorOverlay(settings...)...)
		require.Error(t, err, "follower требует полную отдельную пару migration DSN")
	}
}
