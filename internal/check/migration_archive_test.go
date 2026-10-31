// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"
	"testing/fstest"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/stretchr/testify/require"
)

func TestHistoricalRegistrationArchiveRequiresIdentityAndNonExecutablePlacement(t *testing.T) {
	body, err := migrations.Historical.ReadFile("historical/20261026090000_module_writes_only_what_its_manifest_declares.sql")
	require.NoError(t, err)
	require.NoError(t, check.AuditHistoricalRegistrationMigration(body, migrations.FS))
	require.ErrorContains(t, check.AuditHistoricalRegistrationMigration(append(append([]byte{}, body...), ' '), migrations.FS), "immutable SQL")
	for _, name := range []string{"historical/20261026090000_module_writes_only_what_its_manifest_declares.sql", "20261032090000_renamed.sql"} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, check.AuditHistoricalRegistrationMigration(body, fstest.MapFS{name: &fstest.MapFile{Data: body}}), "executable")
		})
	}
}
