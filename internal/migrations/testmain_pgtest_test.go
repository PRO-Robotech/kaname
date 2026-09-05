// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestMain hands this package one Postgres instead of one per dropguard run.
//
// There is NO Migrate on purpose, and it is the whole point: the drop guard replays
// iam's chain itself, pausing at the version immediately before each drop to count the
// rows. It has to start from before the first migration, so the template stays empty and
// every call takes its own empty database. A migrated template would leave the guard
// nothing to walk and the census nothing to count.
//
// Each call still gets a genuinely separate database — separate catalog, separate rows,
// separate advisory-lock space — so nothing crosses between two runs that did not cross
// between two containers. See pkg/pgtest.
//
// The container starts lazily, so under -short — where the guard reports every drop as
// uncounted and skips — none is started.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{Name: "iamdrop"}))
}
