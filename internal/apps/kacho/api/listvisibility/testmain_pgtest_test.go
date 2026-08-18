// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package listvisibility_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test — the same
// wiring readauthz uses. Each test still gets its own database, cloned from a
// template migrated once (internal/pgtest).
//
// Nothing starts here: the container boots on the first NewDB, so a run where
// every test skips pays nothing.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
