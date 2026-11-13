// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// kaname#1034: настоящий resolver и runner принимают отдельную migration identity
// только без второго адресного источника. Правило double declaration сохранено.
func TestAuthorityMigrationIdentityUsesOneActualDSNSource(t *testing.T) {
	const runtimeDSN = "postgres://runtime@pg-a:5432/kaname"
	const migrationDSN = "postgres://migration_owner@pg-a:5432/kaname"
	for _, mode := range []string{"separate", "default", "both"} {
		t.Run(mode, func(t *testing.T) {
			clearAddressEnv(t)
			path := serviceConfigFile(t, runtimeDSN)
			if mode != "separate" {
				t.Setenv("KANAME_CONFIG_PATH", path)
			}
			if mode != "default" {
				t.Setenv("MIGRATOR_DSN", migrationDSN)
			}
			got, err := resolveDSN("")
			if mode == "both" {
				require.Error(t, err)
				require.Empty(t, got)
				require.ErrorContains(t, err, "MIGRATOR_DSN")
				require.ErrorContains(t, err, "repository.postgres.url")
				return
			}
			require.NoError(t, err)
			expected := migrationDSN
			if mode == "default" {
				expected = runtimeDSN
			}
			require.Equal(t, expected, got)
			runner, err := buildRunner(&rootOptions{dialect: defaultDialect}, fstest.MapFS{})
			require.NoError(t, err)
			require.NotNil(t, runner)
		})
	}
}
