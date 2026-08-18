// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package accesssnapshot

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// TestMain hands this package ONE Postgres and ONE OpenFGA for the whole binary.
//
// Инструменту нужны оба, и по разным причинам: страницы объектов он берёт
// курсором из СВОЕЙ базы (у неё нет серверного предела перечисления), а вопрос
// о доступе задаёт НАСТОЯЩЕМУ движку прав продовым клиентом. Подменив второе,
// он утверждал бы про свою копию правил.
//
// Ничего не стартует здесь: оба провайдера поднимаются по первому обращению, и
// прогон, где всё пропущено под кратким режимом, не платит ни за что.
func TestMain(m *testing.M) {
	os.Exit(fgatest.Run(func() int {
		return pgtest.Run(m, pgtest.Config{
			Name:    "iam",
			Migrate: pgtest.Goose(migrations.FS),
		})
	}))
}
