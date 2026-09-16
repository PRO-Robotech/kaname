// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
)

// TestMain отдаёт пакету ОДИН Postgres на все контейнерные пробы вместо одного
// на прогон. Шаблон не мигрируется намеренно: страж обратного хода свода
// проверяется НА ЦЕПОЧКЕ, накатываемой самим средством миграций, — мигрированный
// шаблон отнял бы у пробы её предмет.
//
// Контейнер поднимается ЛЕНИВО: под `-short`, где контейнерные пробы пропущены,
// он не поднимается вовсе, и быстрый прогон остаётся быстрым.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{Name: "iammigratordown"}))
}
