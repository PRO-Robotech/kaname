// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package readauthz_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// The container belongs to the test BINARY, and each package is its own binary,
// so this wiring is repeated per package. Each test still gets its own database,
// cloned from a template migrated once — see internal/pgtest for why a clone is
// the same isolation a separate container gave.
//
// Nothing starts here: the container boots on the first NewDB, so a run where
// every test skips pays nothing.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
