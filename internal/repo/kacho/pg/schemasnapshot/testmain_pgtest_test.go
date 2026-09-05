// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Точка входа харнесса базы. Без неё пакет просит базу и получает отказ
// «нет TestMain» — то есть прибор не отрабатывает вовсе, а причина читается
// как дефект продукта. Переезд пакета точку входа с собой не приносит: она
// принадлежит ПАКЕТУ, а не файлу.
package schemasnapshot_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
