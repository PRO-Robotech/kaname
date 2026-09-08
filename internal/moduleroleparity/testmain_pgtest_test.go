// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroleparity_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain даёт пакету ОДИН Postgres с уже проигранной цепочкой миграций iam.
//
// Шаблон мигрируется однажды, каждая проба берёт свой клон — так живая база
// этого гейта есть в точности то, что производят миграции дерева, и ничего
// сверх: ни посева стенда, ни следов чужих прогонов. Именно поэтому вердикт
// здесь воспроизводим, а вердикт по общему стенду — нет: стенд отстаёт от линии
// и несёт данные чужих прогонов.
//
// Контейнер поднимается лениво: под `-short` гейт пропускается, и не
// поднимается ничего.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "iammoduleroleparity",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}
