// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain — база для интеграции глаголов над живой Postgres (kaname#865).
// Приведение схемы — один раз на пакет, у выдающего базу; короткий прогон
// контейнера не поднимает вовсе (`pgtest.NewDB` пропускает пробу).
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}
