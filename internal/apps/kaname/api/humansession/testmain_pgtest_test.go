// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// Базу здесь берёт одна проба — сверка дублёра хранилища с адаптером базы
// (`store_double_parity_integration_test.go`): пробы вариантов использования
// идут над дублёром, и о базе они говорят ровно то, что дублёр делает как
// адаптер. Контейнер стартует на первом NewDB: прогон под -short не платит
// ничего, пробы над дублёром — тоже.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
