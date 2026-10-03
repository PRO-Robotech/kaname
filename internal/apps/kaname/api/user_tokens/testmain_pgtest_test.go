// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain hands this package ONE Postgres instead of one per test.
//
// Базу здесь берёт одна проба — источник момента выдачи против отсечки
// отзыва-всех (`one_clock_revoke_all_integration_test.go`, kaname#388). Пробы
// варианта использования идут над дублёрами; контейнер стартует на первом
// NewDB, и прогон под -short не платит ничего.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
