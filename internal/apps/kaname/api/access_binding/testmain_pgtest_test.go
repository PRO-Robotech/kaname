// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь; каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
//
// Здесь стоял ВТОРОЙ провайдер — сервер внешнего движка отношений, обёрнутый
// вокруг этого вызова ради единственного кода выхода. Движка нет: вопрос о
// доступе отвечает реляционная форма В ЭТОЙ ЖЕ базе, поэтому источник состояния
// у проб один, и обёртка стала бы вторым провайдером без предмета.
//
// Ничего не стартует прямо здесь: Postgres поднимается на первом обращении, и
// прогон, где все пробы пропущены, не платит ничего.
func TestMain(m *testing.M) {
	// Модель процесса — до первой пробы: дверь решения читает её глобально, и
	// установка после первого чтения отвергается. Собрана из канона и
	// доставленного probemod (мир М2, kaname#904) — как на старте службы.
	if err := installATCModel(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: модель процесса не установлена: %v\n", err)
		os.Exit(1)
	}
	pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `pkg/pgtest` §searchpath.
		SearchPath: "kaname,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	})
}
