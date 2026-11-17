// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import "strings"

// Только тестовый SQL: исходные CTE и все 12 аргументов остаются на месте.
// Наблюдение не добавляет счётчиков или полей в продуктовый List.
func ListNecessaryRootCountsSQLForTest(labelTable string, nesting bool) string {
	sql, err := listQuerySQL(labelTable, nesting)
	if err != nil {
		panic(err)
	}
	const tail = "SELECT c.object_id, COALESCE(a.allowed, false) AS allowed\n"
	if strings.Count(sql, tail) != 1 {
		panic("List necessary-root diagnostic anchor changed")
	}
	return sql[:strings.Index(sql, tail)] + `SELECT
    (SELECT count(*) FROM candidate),
    (SELECT count(*) FROM needed_candidate),
    (SELECT count(*) FROM adjudicated),
    (SELECT count(*) FROM adjudicated WHERE allowed)`
}
