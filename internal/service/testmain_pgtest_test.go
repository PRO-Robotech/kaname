// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь: каждая проба
// получает свою базу, клонированную из шаблона, промигрированного один раз.
//
// Второго провайдера здесь больше нет. Прежняя редакция оборачивала это ещё и
// подъёмом внешнего движка прав, потому что проба каскада спрашивала его. Движка
// нет; на вопрос о доступе отвечает реляционная форма, и лежит она в ЭТОЙ ЖЕ
// базе — то есть провайдера ровно один, и обёртки над обёрткой не требуется.
//
// Postgres поднимается по первому обращению, поэтому прогон, где всё пропущено
// под кратким режимом, не платит ни за что.
func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: pgtest.Goose(migrations.FS),
	})
}
