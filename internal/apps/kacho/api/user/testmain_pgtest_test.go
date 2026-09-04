// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь.
//
// Здесь стоял TestMain, поднимавший внешний движок отношений. Движка в дереве
// нет, а предмет единственной пробы, которой он был нужен, — «кортежи личности
// снимаются вместе со строкой» — жив: состояние, из которого складывается ответ
// о доступе, есть свёртка СОБСТВЕННОГО журнала iam, и принимающая сторона формы
// снятия теперь тоже своя (триггер проекции журнала).
//
// Пакет по-прежнему подавляюще юнитовый — фиктивные порты, никакой базы. Ничего
// не запускается: контейнер поднимается на ПЕРВОМ обращении, поэтому прогон, где
// единственная база-зависимая проба пропущена (`-short`), не платит ничего.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `internal/pgtest` §searchpath.
		SearchPath: "kacho_iam,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}
