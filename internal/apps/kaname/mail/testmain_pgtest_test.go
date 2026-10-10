// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

import (
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"

	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь: каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
// Краткий прогон (-short) Postgres не поднимает.
func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "kaname-mail",
		Migrate: journalfixture.Migrate(migrations.FS),
	})
}
