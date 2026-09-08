// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_cursor_plan_integration_test.go — задача #708, доказательство ДЕЙСТВИЯ.
//
// Гейт `internal/repohygiene` утверждает о схеме: индекс такой-то формы
// объявлен. Здесь утверждается о поведении: план настоящего Postgres на
// настоящей цепочке миграций iam берёт порядок страницы ИЗ ЭТОГО индекса и не
// содержит узла сортировки. Разбор обоих вопросов, довод в пользу
// детерминированной постановки и требование контроля — в шапке
// `pkg/listcursorplan`.
//
// Проба красна на состоянии ДО фикса: без `708001` план несёт узел сортировки,
// потому что порядок брать неоткуда.
package cursorplan_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/listcursorplan"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestIntegration_IAM_CursorPagesTakeTheirOrderFromAnIndex(t *testing.T) {
	listcursorplan.Run(t, listcursorplan.Options{
		Service: "iam",
		Schema:  "kaname",
		FS:      migrations.FS,
		Cases: []listcursorplan.Case{
			{
				Table: "operations", Index: "operations_cursor_idx", Order: "created_at ASC, id ASC",
				Seed: listcursorplan.SeedOperations("kaname"),
			},
			// ОБРАТНЫЙ обход счёта выдач аккаунта. Существующий
			// `access_bindings_cursor_idx (created_at, id)` ему не помогает:
			// обратное чтение даёт `created_at DESC, id DESC` — не ту вторичную
			// сортировку. Здесь это проверяется планом, а не рассуждением.
			{
				Table: "access_bindings", Index: "access_bindings_recent_cursor_idx",
				Order: "created_at DESC, id ASC",
			},
			// Прямой обход той же таблицы — положительный контроль: он обязан
			// по-прежнему идти по СВОЁМ индексе. Без этой половины проба не
			// отличала бы «завели нужный индекс» от «сломали прежний».
			{
				Table: "access_bindings", Index: "access_bindings_cursor_idx",
				Order: "created_at ASC, id ASC",
			},
		},
		Control: listcursorplan.Control{Table: "operations", Order: "description ASC"},
	})
}
