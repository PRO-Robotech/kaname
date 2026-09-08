// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain даёт пакету ОДИН Postgres с уже проигранной цепочкой миграций iam.
//
// Контейнер поднимается ЛЕНИВО — только когда проба его просит, — поэтому
// гейты дерева этого пакета (их здесь большинство) остаются такими же быстрыми,
// какими были, и под `-short` не поднимается ничего.
//
// Шаблон мигрируется однажды, каждая проба берёт свой клон: живая база пробы
// есть в точности то, что производят миграции дерева, и ничего сверх — ни посева
// стенда, ни следов чужих прогонов.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iamserveroot",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
