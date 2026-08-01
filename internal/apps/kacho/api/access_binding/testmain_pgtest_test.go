// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// TestMain hands this package ONE Postgres and ONE OpenFGA instead of one of each
// per test.
//
// Both containers belong to the test BINARY, and each package is its own binary,
// so this wiring is repeated per package. Each test still gets its own database
// (cloned from a template migrated once) and its own OpenFGA store — see
// internal/pgtest and services/iam/internal/testsupport/fgatest for why a clone
// and a store are the isolation a separate container gave.
//
// Nothing starts here: both providers boot on first use, so a run where every
// test skips pays nothing. fgatest.Run only terminates the server afterwards; it
// wraps pgtest.Run because a TestMain returns exactly one exit code.
func TestMain(m *testing.M) {
	os.Exit(fgatest.Run(func() int {
		return pgtest.Run(m, pgtest.Config{
			Name:    "iam",
			Migrate: pgtest.Goose(migrations.FS),
		})
	}))
}
