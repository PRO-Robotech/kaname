// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Точка входа харнесса базы. Без неё пакет просит базу и получает отказ
// «нет TestMain» — то есть прибор не отрабатывает вовсе, а причина читается
// как дефект продукта. Переезд пакета точку входа с собой не приносит: она
// принадлежит ПАКЕТУ, а не файлу.
package schemasnapshot_test

import (
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"

	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: journalfixture.Migrate(migrations.FS),
	}))
}
