// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package parentedge_test

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь; каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
//
// Ничего, кроме Postgres, пакету не нужно: его предмет — таблицы iam. Прежде
// здесь оговаривалось, что внешний движок отношений поднимать не надо; со снятием
// движка оговорка лишилась предмета — поднимать больше нечего.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	})
}
