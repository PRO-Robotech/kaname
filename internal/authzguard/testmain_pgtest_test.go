// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

import (
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"

	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestMain выдаёт пакету ОДИН Postgres на весь тестовый бинарь: пробы рубежа
// положения подтверждения (kaname#456) судят над настоящим читателем отметок.
// Postgres поднимается по первому обращению — прогон, где всё пропущено под
// кратким режимом, не платит ни за что.
func TestMain(m *testing.M) {
	pgtest.Run(m, pgtest.Config{
		Name:    "iam",
		Migrate: journalfixture.Migrate(migrations.FS),
	})
}
