// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_owner_links_are_immutable_integration_test.go — владелец аккаунта
// (`accounts.owner_user_id`) и аккаунт проекта (`projects.account_id`)
// неизменяемы, и держит это БАЗА (задача PRO-Robotech/kaname#484).
//
// Условие пробы — замысел `docs/changes/issue-2924/design.md` репозитория
// PRO-Robotech/kacho-workspace, З23 п. 4: смена значения — отказ `23514`;
// правка `name` — проходит (близнец).
//
// # Почему у каждого отказа два близнеца
//
// «Смена отвергается» неотличимо от «строку править нельзя вообще», если
// утверждать только отказ. Поэтому рядом с отрицанием стоят два положительных
// исхода, отличающихся от него ровно одним фактом:
//
//   - та же строка, правится `name` (и `description`/`labels`) — проходит;
//   - та же колонка названа в SET, но тем же значением — проходит.
//
// Второй близнец отделяет суждение по ЗНАЧЕНИЮ от суждения по списку SET:
// триггер «UPDATE OF <колонка>» без условия отверг бы и его.
//
// # Почему спор идёт за ЗАКОННОЕ новое значение
//
// Новое значение — существующий пользователь того же аккаунта и существующий
// аккаунт. Иначе отказ пришёл бы от внешнего ключа (`23503`), и проба зеленела
// бы без триггера.
package migrations_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const (
	immAccA   = "accimmutableprobea0"
	immAccB   = "accimmutableprobeb0"
	immUser1  = "usrimmutableprobe01"
	immUser2  = "usrimmutableprobe02"
	immUserB  = "usrimmutableprobeb1"
	immProjID = "prjimmutableprobe01"
)

// seedScopeOwnerLinks кладёт два аккаунта, двух пользователей аккаунта A
// (владелец и законный кандидат в владельцы) и проект в аккаунте A.
func seedScopeOwnerLinks(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	for _, u := range []struct{ id, ext, email, acc string }{
		{immUser1, "ext-imm-1", "imm-one@example.test", immAccA},
		{immUser2, "ext-imm-2", "imm-two@example.test", immAccA},
		{immUserB, "ext-imm-b", "imm-b@example.test", immAccB},
	} {
		_, err = tx.Exec(`
			INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ($1, $2, $3, 'probe', $4, 'ACTIVE')`, u.id, u.ext, u.email, u.acc)
		require.NoErrorf(t, err, "посев пользователя %s", u.id)
	}
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'imm-a', $2)`, immAccA, immUser1)
	require.NoError(t, err, "посев аккаунта A")
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'imm-b', $2)`, immAccB, immUserB)
	require.NoError(t, err, "посев аккаунта B")
	_, err = tx.Exec(`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, $2, 'imm-prj')`, immProjID, immAccA)
	require.NoError(t, err, "посев проекта")
	require.NoError(t, tx.Commit())
}

// requireCheckViolation требует отказ именно классом `23514` и текстом,
// называющим колонку: отказ иным классом (например, `23503` внешнего ключа)
// означал бы, что свойство держит не этот механизм.
func requireCheckViolation(t *testing.T, err error, column string) {
	t.Helper()
	require.Errorf(t, err, "смена %s прошла: неизменяемость базой не держится", column)
	var pgErr *pgconn.PgError
	require.Truef(t, errors.As(err, &pgErr), "отказ пришёл не от базы: %v", err)
	require.Equalf(t, "23514", pgErr.Code, "отказ обязан прийти классом check_violation: %v", err)
	require.Containsf(t, pgErr.Message, column, "текст отказа обязан называть колонку: %v", err)
}

// TestIntegration_AccountOwnerIsImmutable — смена `accounts.owner_user_id`
// отвергается `23514`; правка прочих колонок и запись тем же значением проходят.
func TestIntegration_AccountOwnerIsImmutable(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedScopeOwnerLinks(t, db)

	// ── отрицание: смена владельца на законного кандидата ────────────────────
	_, err := db.Exec(`UPDATE kaname.accounts SET owner_user_id = $1 WHERE id = $2`, immUser2, immAccA)
	requireCheckViolation(t, err, "owner_user_id")

	// Смена вместе с законной правкой — отказ целиком, name не меняется.
	_, err = db.Exec(`UPDATE kaname.accounts SET name = 'imm-a-mixed', owner_user_id = $1 WHERE id = $2`, immUser2, immAccA)
	requireCheckViolation(t, err, "owner_user_id")

	var owner, name string
	require.NoError(t, db.QueryRow(`SELECT owner_user_id, name FROM kaname.accounts WHERE id = $1`, immAccA).Scan(&owner, &name))
	require.Equal(t, immUser1, owner, "отвергнутая смена оставила след в строке")
	require.Equal(t, "imm-a", name, "отказ не откатил оператор целиком")

	// ── близнец 1: правка name/description/labels проходит ───────────────────
	res, err := db.Exec(`UPDATE kaname.accounts SET name = 'imm-a-renamed', description = 'd', labels = '{"k":"v"}' WHERE id = $1`, immAccA)
	require.NoError(t, err, "правка прочих колонок аккаунта отвергнута: триггер запер строку целиком")
	n, _ := res.RowsAffected()
	require.EqualValues(t, 1, n, "близнец не тронул строку — проба беспредметна")

	// ── близнец 2: колонка в SET тем же значением проходит ───────────────────
	res, err = db.Exec(`UPDATE kaname.accounts SET owner_user_id = $1, name = 'imm-a-same' WHERE id = $2`, immUser1, immAccA)
	require.NoError(t, err, "запись тем же владельцем отвергнута: суждение идёт по списку SET, а не по значению")
	n, _ = res.RowsAffected()
	require.EqualValues(t, 1, n, "близнец не тронул строку — проба беспредметна")
}

// TestIntegration_ProjectAccountIsImmutable — смена `projects.account_id`
// отвергается `23514`; правка прочих колонок и запись тем же значением проходят.
func TestIntegration_ProjectAccountIsImmutable(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedScopeOwnerLinks(t, db)

	// ── отрицание: перенос проекта в существующий аккаунт B ──────────────────
	_, err := db.Exec(`UPDATE kaname.projects SET account_id = $1 WHERE id = $2`, immAccB, immProjID)
	requireCheckViolation(t, err, "account_id")

	_, err = db.Exec(`UPDATE kaname.projects SET name = 'imm-prj-mixed', account_id = $1 WHERE id = $2`, immAccB, immProjID)
	requireCheckViolation(t, err, "account_id")

	var acc, name string
	require.NoError(t, db.QueryRow(`SELECT account_id, name FROM kaname.projects WHERE id = $1`, immProjID).Scan(&acc, &name))
	require.Equal(t, immAccA, acc, "отвергнутая смена оставила след в строке")
	require.Equal(t, "imm-prj", name, "отказ не откатил оператор целиком")

	// ── близнец 1: правка name/description/labels проходит ───────────────────
	res, err := db.Exec(`UPDATE kaname.projects SET name = 'imm-prj-renamed', description = 'd', labels = '{"k":"v"}' WHERE id = $1`, immProjID)
	require.NoError(t, err, "правка прочих колонок проекта отвергнута: триггер запер строку целиком")
	n, _ := res.RowsAffected()
	require.EqualValues(t, 1, n, "близнец не тронул строку — проба беспредметна")

	// ── близнец 2: колонка в SET тем же значением проходит ───────────────────
	res, err = db.Exec(`UPDATE kaname.projects SET account_id = $1, name = 'imm-prj-same' WHERE id = $2`, immAccA, immProjID)
	require.NoError(t, err, "запись тем же аккаунтом отвергнута: суждение идёт по списку SET, а не по значению")
	n, _ = res.RowsAffected()
	require.EqualValues(t, 1, n, "близнец не тронул строку — проба беспредметна")
}
