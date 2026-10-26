// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// group_member_from_another_account_survives_integration_test.go — ESC-32
// приёмки role-rights-stay-within-what-is-named.md (Р4; задача
// PRO-Robotech/kaname#1037).
//
// Строку состава с участником из чужого аккаунта новая редакция по построению
// не заводит (Р3), а прежняя принимала: триггер существования участника
// аккаунта не сверяет. Поэтому строка сеется НА СХЕМЕ прежней редакции — до
// наката, на версии последней миграции ревизии `ddd5681af`, — и исход не
// зависит от того, где новая редакция держит Р3.
//
// Без новой миграции проба держит вакуумно (накат пуст): держателем Р4 она
// становится в тот момент, когда цепь миграций вырастет за эту версию. Это и
// есть её предмет — ни одна будущая миграция не снимает и не отвергает
// прежних строк состава.

import (
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// escPriorVersion — версия последней миграции ревизии `ddd5681af`.
const escPriorVersion int64 = 20261025180000

// escSeedServiceAccount — учётка в аккаунте оператором вставки схемы этой версии.
func escSeedServiceAccount(t *testing.T, db *sql.DB, acc, tag string) string {
	t.Helper()
	id := "sva" + strings.Repeat("0", 17-len(tag)) + tag
	_, err := db.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`, id, acc, "sva-"+tag)
	require.NoErrorf(t, err, "Дано: учётка %s", tag)
	return id
}

// escMembers — строки состава группы так, как их читает `GroupService.ListMembers`.
func escMembers(t *testing.T, db *sql.DB, group string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT member_type || ':' || member_id FROM kaname.group_members WHERE group_id = $1`, group)
	require.NoError(t, err)
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

func TestRoleRightsStayNamed_ESC32_ForeignAccountGroupMemberSurvivesTheRollForward(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := serOpenAt(t, escPriorVersion)

	// Два аккаунта с владельцами, группа grp-1 в первом, учётки sva-1 (первый) и
	// sva-2 (второй).
	owner1 := serSeedPerson(t, db, "esc32a")
	owner2 := serSeedPerson(t, db, "esc32b")
	var acc1, acc2 string
	require.NoError(t, db.QueryRow(`SELECT account_id FROM kaname.users WHERE id = $1`, owner1).Scan(&acc1))
	require.NoError(t, db.QueryRow(`SELECT account_id FROM kaname.users WHERE id = $1`, owner2).Scan(&acc2))
	const grp = "grp000000000000esc32"
	_, err := db.Exec(`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, 'grp-esc32')`, grp, acc1)
	require.NoError(t, err, "Дано: группа grp-1")
	sva1 := escSeedServiceAccount(t, db, acc1, "esc32a")
	sva2 := escSeedServiceAccount(t, db, acc2, "esc32b")

	// Строки состава — оператором, который схема этой версии принимает. Близнец по
	// одному факту: sva-2 (чужой аккаунт) против sva-1 (аккаунт группы).
	for _, sva := range []string{sva2, sva1} {
		_, err := db.Exec(`INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ($1, 'service_account', $2)`, grp, sva)
		require.NoErrorf(t, err, "Дано: строка состава (grp-1, service_account, %s) на версии %d", sva, escPriorVersion)
	}
	want := []string{"service_account:" + sva1, "service_account:" + sva2}
	require.Equal(t, want, escMembers(t, db, grp), "контроль посева: обе строки состава на месте до наката")

	require.NoError(t, goose.Up(db, "."), "накат до головы")
	head, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	t.Logf("ESC-32: накат %d → %d", escPriorVersion, head)

	require.Equal(t, want, escMembers(t, db, grp), "ESC-32: строки состава после наката — те же (Р4)")
}
