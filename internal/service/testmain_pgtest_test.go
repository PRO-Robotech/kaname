// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// TestMain hands this package one Postgres AND one OpenFGA instead of one of each
// per test.
//
// Both database-backed suites here — the cascade-queue proof and the conditions
// audit-outbox proofs — used to boot a container and replay the whole iam
// migration chain per test, and the cascade-queue proof booted a relation server
// on top of that. Both now hand back an isolated slice of the one container this
// test BINARY owns: a database cloned from the migrated template, and a store on
// the shared relation server. The containers belong to the binary, so the wiring
// has to live in the package that owns the binary.
//
// See internal/pgtest for why a clone is the isolation a separate container gave,
// and testsupport/fgatest for why a store is. Both start lazily, so a -short run
// that skips every test starts nothing.
//
// The two wrappers nest rather than compose: pgtest.Run is the one that calls
// m.Run, so it goes inside, and fgatest.Run takes down the relation server once
// pgtest.Run has taken down Postgres and returned the package's exit code.
func TestMain(m *testing.M) {
	os.Exit(fgatest.Run(func() int {
		return pgtest.Run(m, pgtest.Config{
			Name:    "iam",
			Migrate: pgtest.Goose(migrations.FS),
		})
	}))
}
