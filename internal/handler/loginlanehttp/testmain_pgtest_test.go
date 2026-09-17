// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// Интеграционная проба этого пакета (Ф12-13 «е», kaname#257) собирает
// слушатель над настоящим входом с адаптерами базы и берёт её через
// iampgtest.NewTestPostgres — pgtest просит контейнер, принадлежащий этому
// бинарю. Контейнер стартует на первом NewDB: прогон под -short не платит
// ничего, пробы транспорта над дублёром — тоже.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
