// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// active_identity_has_a_way_in_census_integration_test.go — перепись AWI-13 на
// уровне кода (задача PRO-Robotech/kaname#608, приёмка
// `docs/engineering/acceptance/active-identity-has-a-way-in.md`, AWI-13).
//
// AWI-13 читает стенд дважды: до выкатки миграции переноса и после неё. Здесь
// утверждается сам ЗАПРОС переписи — тот, которым читается стенд, — на базе,
// поднятой пошагово: до миграции предмета он обязан находить тупиковые строки
// (близнец: первое число равно второму), после — ни одной, при неизменном
// втором числе.
//
// Несущее: до выкатки колонки отметки в схеме нет. Запрос, называющий её
// напрямую, до выкатки не исполняется, и близнец становится неисполнимым —
// перепись «после» тогда нечем сверить. Поэтому отметка читается из образа
// строки (`to_jsonb`): на схеме без колонки её значение — NULL, то есть
// «отметки нет», и один и тот же текст запроса верен на обеих ревизиях.
// Перепись — только чтение и только числа: ни идентификаторов, ни адресов.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// awiCensusSQL — перепись AWI-13: первое число — личности `ACTIVE` без строки
// пароля и без отметки открытого пути (тупик); второе — личности `ACTIVE` без
// строки пароля. Текст исполним и до миграции переноса, и после неё.
const awiCensusSQL = `
SELECT count(*) FILTER (WHERE (to_jsonb(u) ->> 'recovery_path_opened_at') IS NULL) AS dead_ends,
       count(*)                                                                  AS active_without_password
  FROM kaname.users u
 WHERE u.invite_status = 'ACTIVE'
   AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
                    WHERE m.user_id = u.id AND m.kind = 'password')`

type awiCensus struct{ deadEnds, activeWithoutPassword int }

func awiReadCensus(t *testing.T, db *sql.DB, phase string) awiCensus {
	t.Helper()
	var c awiCensus
	require.NoError(t, db.QueryRow(awiCensusSQL).Scan(&c.deadEnds, &c.activeWithoutPassword),
		"AWI-13: перепись обязана исполняться %s", phase)
	return c
}

// AWI-13 — до выкатки перепись находит тупики (первое = второму), после —
// тупиков ноль, второе число прежнее.
func TestIntegration_AWI13_CensusFindsDeadEndsBeforeAndNoneAfter(t *testing.T) {
	db, own := awiDBBefore(t)
	account := awiAccount(t, db, "awi13")

	// Посев на ревизии ДО предмета: два тупика (как в разборе стенда — два
	// `ACTIVE` без пароля), и по одному близнецу на каждый факт запроса:
	// `ACTIVE` с паролем (пароль), `BLOCKED` и `PENDING` без пароля (статус).
	type seed struct {
		tag, status string
		password    bool
	}
	seeds := []seed{
		{tag: "awi13a", status: "ACTIVE"},
		{tag: "awi13b", status: "ACTIVE"},
		{tag: "awi13c", status: "ACTIVE", password: true},
		{tag: "awi13d", status: "BLOCKED"},
		{tag: "awi13e", status: "PENDING"},
	}
	for _, s := range seeds {
		tx, err := db.Begin()
		require.NoError(t, err)
		id, err := awiInsertPerson(tx, account, s.tag, s.status)
		require.NoError(t, err, "посев %s", s.tag)
		if s.password {
			require.NoError(t, awiInsertPassword(tx, id))
		}
		require.NoError(t, tx.Commit(), "посев %s на ревизии до предмета", s.tag)
	}

	before := awiReadCensus(t, db, "до выкатки (колонки отметки в схеме нет)")
	require.Equal(t, awiCensus{deadEnds: 2, activeWithoutPassword: 2}, before,
		"AWI-13 близнец: до выкатки первое число обязано равняться второму и находить оба тупика")

	require.NoError(t, goose.UpTo(db, ".", own), "накат предмета")

	after := awiReadCensus(t, db, "после выкатки")
	require.Equal(t, 0, after.deadEnds, "AWI-13: после выкатки тупиковых строк обязано быть 0")
	require.Equal(t, before.activeWithoutPassword, after.activeWithoutPassword,
		"AWI-13: перенос статусов не меняет — второе число обязано остаться прежним")
}
