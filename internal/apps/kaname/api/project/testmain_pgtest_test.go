// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// The container belongs to the test BINARY, and each package is its own binary,
// so this wiring is repeated per package (the audit package carries the same
// one). Each test still gets its own database, cloned from a template migrated
// once — see pkg/pgtest for why a clone is the same isolation a separate
// container gave.
//
// Nothing starts here: the container boots on the first NewDB, so a run where
// every test skips (`-short`) pays nothing — and the sixteen unit probes of this
// package keep running without Docker.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу; довод целиком —
		// `pkg/pgtest` §searchpath.
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}
