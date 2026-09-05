// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
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
	pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `pkg/pgtest` §searchpath.
		SearchPath: "kacho_iam,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	})
}
