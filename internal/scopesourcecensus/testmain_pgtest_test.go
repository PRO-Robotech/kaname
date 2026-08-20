// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package scopesourcecensus_test

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь; каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз, —
// то есть базу со ВСЕМИ миграциями iam, включая ту, что достраивает цепь.
//
// Это существенно, а не удобно: перепись читает представление
// `resource_scope_edge`, и проба, поднявшая базу без миграций, судила бы о
// приборе на схеме, которой в продукте нет.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iamcensus",
		Migrate: pgtest.Goose(migrations.FS),
	})
}
