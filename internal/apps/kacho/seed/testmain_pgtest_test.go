// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
)

// TestMain hands this package one Postgres instead of one per test.
//
// setupBootstrapDB used to boot a container and replay the whole iam migration
// chain per call. The container belongs to the test BINARY, so the wiring has to
// live in the package that owns the binary.
//
// Each test still gets its own database, cloned from the migrated template — see
// pkg/pgtest for why a clone is the isolation a separate container gave. The
// container starts lazily, so a -short run that skips every test starts nothing.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `pkg/pgtest` §searchpath.
		SearchPath: "kacho_iam,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}
