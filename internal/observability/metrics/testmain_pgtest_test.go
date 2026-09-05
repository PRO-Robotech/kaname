// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь: каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
//
// Postgres поднимается по ПЕРВОМУ обращению, поэтому прогон без интеграционных
// проб (краткий режим) не платит за него ничем — а он здесь такой ровно один.
func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iam-metrics",
		Migrate: pgtest.Goose(migrations.FS),
	})
}
