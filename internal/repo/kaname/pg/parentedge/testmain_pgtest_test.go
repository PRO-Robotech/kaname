// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package parentedge_test

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь; каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
//
// Ничего, кроме Postgres, пакету не нужно: его предмет — таблицы iam. Прежде
// здесь оговаривалось, что внешний движок отношений поднимать не надо; со снятием
// движка оговорка лишилась предмета — поднимать больше нечего.

import (
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"

	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: journalfixture.Migrate(migrations.FS),
	})
}
