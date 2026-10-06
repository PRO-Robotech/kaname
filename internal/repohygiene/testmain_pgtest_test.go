// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package repohygiene_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
)

// TestMain — один Postgres на двоичный файл пакета; каждая проба получает
// свой клон шаблона, на котором сыграна цепь миграций дерева. Контейнер
// стартует лениво.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: journalfixture.Migrate(migrations.FS),
	}))
}
