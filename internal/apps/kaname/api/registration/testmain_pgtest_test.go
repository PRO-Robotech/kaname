// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// Интеграционные пробы этого пакета (Ф4-01…05, Ф4-11…13, Ф4-17, Ф4-20,
// Ф4-23, Ф4-24, Ф1-62) берут базу через iampgtest.NewTestPostgres, который
// просит pgtest о базе на контейнере, принадлежащем этому бинарю. Контейнер
// стартует на первом NewDB: прогон под -short не платит ничего.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
