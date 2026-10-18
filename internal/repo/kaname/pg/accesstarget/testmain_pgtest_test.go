// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package accesstarget_test

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь; проба получает
// свою базу, клонированную из шаблона, промигрированного один раз. Под -short
// контейнер не поднимается.

import (
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	})
}
