// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package one Postgres instead of one per test.
//
// iampgtest.NewTestPostgres — which every test here calls — used to boot a container and
// replay the whole iam migration chain per call. It now hands back a database on
// the one container this test BINARY owns, and the container belongs to the
// binary, so the wiring has to live in the package that owns the binary.
//
// Each test still gets its own database, cloned from the migrated template — see
// pkg/pgtest for why a clone is the isolation a separate container gave. The
// container starts lazily, so a -short run that skips every test starts nothing.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
