// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// The tests here reach the database through iampgtest.NewTestPostgres, which now
// asks pgtest for a database on the container this binary owns. The container
// belongs to the test BINARY, and each package is its own binary, so the wiring
// has to be repeated per package — see pkg/pgtest for why a clone of a
// migrated template is the same isolation a separate container gave.
//
// Nothing starts here: the container boots on the first NewDB, so a run where
// every test skips pays nothing.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
