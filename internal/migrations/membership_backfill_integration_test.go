// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_backfill_integration_test.go — «одно членство на строку человека»
// (IAM-ID-1, задача kacho#470): взаимная однозначность держится на КАЖДОМ
// писателе.
//
// Приёмка требует (IAM-ID-1-11): членств ровно столько же, сколько строк
// пользователей; членство каждой строки ведёт В ТОТ ЖЕ аккаунт, что стоит в её
// колонке; обратная перепись пуста — нет ни членства без строки, ни строки без
// членства.
//
// # Что изменилось: измеряется ДЕРЕВО, а не разовое обратное заполнение
//
// Прежде проба останавливала цепочку перед миграцией членств `470001`, сеяла
// строки трёх классов и применяла миграцию — то есть судила ОБРАТНОЕ
// ЗАПОЛНЕНИЕ уже лежавших строк. Миграций сервиса теперь одна — свод, — и
// версии, на которой можно остановиться, не существует.
//
// Свойство при этом живо и стало ШИРЕ: взаимную однозначность держат ДВА
// производителя сразу, и проба видит обоих. Строки, приехавшие вместе со
// сводом (посевные служебные якоря, IAM-ID-1-40), несут свои членства из того
// же свода; строки, которые сеет сама проба, получают членство от зеркала
// `membership_mirror_from_user()`. Утверждение «одно членство на строку» верно
// о ДЕРЕВЕ, а не об одном стейтменте, и краснеет теперь от расхождения любого
// из двух — включая посевные данные свода, которых прежняя редакция не судила
// вовсе.
//
// # Почему census — предусловие, а не украшение
//
// «Ни одной строки без членства» на ПУСТОЙ таблице истинно тождественно. Поэтому
// проба сперва утверждает, что осмотренных строк не ноль, и печатает разбиение
// по классам (IAM-ID-1-41): «ноль находок» обязано быть отличимо от «ноль
// прочитанного» (testing.md §«Гейт на класс» п.3).
//
// # Почему у утверждения об ОТСУТСТВИИ стоит положительный контроль
//
// Запрос «строки без членства» молчит и когда их нет, и когда он сам сломан.
// Поэтому в конце проба УДАЛЯЕТ одно членство и требует, чтобы тот же запрос
// нашёл ровно одну строку и назвал её. Без этого исчезновение предмета и
// поломка предиката неразличимы by construction (testing.md §«Гейт на класс»
// п.2 — инъекция в обе стороны).
//
// # Здесь стояла проба ОТКАТА стадии S1 (IAM-ID-1-50) — предмета у неё нет
//
// Она применяла цепочку до `470001`, откатывала ОДИН шаг и требовала, чтобы
// после него не осталось ни таблицы членств, ни зеркала, ни его функций, а
// строки людей были целы. Обратный ход свода — `DROP SCHEMA kaname CASCADE`,
// и он объявляет это прямо: «свод откатывается только целиком». Пошагового
// отката, о котором проба говорила, в дереве нет ни в какой форме, поэтому она
// снята вместе со своим предметом. Сценарий приёмки IAM-ID-1-50 остался без
// держателя; он назван в отчёте линии как остаток, а не как починка.

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// seedUser вставляет строку пользователя вместе с её аккаунтом одной
// транзакцией. Оба ключа цикла объявлены DEFERRABLE INITIALLY DEFERRED, поэтому
// порядок внутри транзакции значения не имеет.
func seedUser(t *testing.T, db *sql.DB, tag, inviteStatus string) (userID, accountID string) {
	t.Helper()
	userID = "usr" + fmt.Sprintf("%017s", tag)
	accountID = "acc" + fmt.Sprintf("%017s", tag)
	externalID := "ext-" + tag
	if inviteStatus == "PENDING" {
		// CHECK users_invite_status_consistency: у приглашённого внешнего
		// идентификатора нет вовсе. Фикстура обязана быть не снисходительнее
		// продукта, иначе она прячет тот самый класс, ради которого стоит.
		externalID = ""
	}

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, externalID, tag+"@example.test", "User "+tag, accountID, inviteStatus)
	require.NoError(t, err, "посев строки класса %s", inviteStatus)

	_, err = tx.Exec(`
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ($1, $2, $3)`,
		accountID, "acc-"+tag, userID)
	require.NoError(t, err, "посев аккаунта для класса %s", inviteStatus)

	require.NoError(t, tx.Commit())
	return userID, accountID
}

func TestIntegration_MembershipBackfillIsBijective(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)

	// ── дерево целиком: останавливаться больше негде и незачем ───────────────
	db := upAllIAMMigrations(t, dsn)
	defer func() { _ = db.Close() }()

	// Строки, заведённые ПРИМЕНЁННЫМИ миграциями (посевные служебные якоря,
	// IAM-ID-1-40). Их не сеет проба — они уже лежат, и бэкфилл обязан взять их
	// наравне с прочими.
	//
	// Снимок берётся ДО посева — то есть отбором своих строк, а не вычитанием
	// чужих. Список «все, кроме моих трёх» стареет молча: он растёт от работы, к
	// пробе отношения не имеющей, и, исключив лишнее, даёт ноль — утверждение
	// зеленеет, не посмотрев ни на одну строку (issue #510).
	var seededByMigrations int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.users`).Scan(&seededByMigrations))
	require.Positive(t, seededByMigrations,
		"посевных строк обязано быть не ноль: на пустой таблице каждое утверждение "+
			"ниже истинно тождественно, и проба зеленела бы при полностью отсутствующем бэкфилле")

	// Строки всех трёх классов состояния (§5 группа E: К1 активен · К2
	// приглашён · К3 заблокирован). Разбиение по СОСТОЯНИЮ строки — оно взаимно
	// исключающее и исчерпывающее; владение и посевное происхождение суть срезы,
	// от них исключительности не требуется.
	activeUser, activeAcc := seedUser(t, db, "k1active", "ACTIVE")
	pendingUser, pendingAcc := seedUser(t, db, "k2pendng", "PENDING")
	blockedUser, blockedAcc := seedUser(t, db, "k3blockd", "BLOCKED")

	var usersBefore int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.users`).Scan(&usersBefore))

	// Взаимная однозначность «одно членство на строку» — свойство ЭТОГО дерева,
	// а не вечный инвариант: работа, дающая человеку ВТОРОЕ членство, ведётся
	// вставкой (см. `identity_merge_integration_test.go`), и проба этих строк не
	// сеет. Заведут второе членство писателем — эта проба обязана покраснеть и
	// потребовать переписать себя, а не молчать.

	// ── перепись: объём осмотренного печатается всегда (IAM-ID-1-41) ─────────
	var (
		usersAfter, memberships        int
		k1Active, k2Pending, k3Blocked int
	)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.users`).Scan(&usersAfter))
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.memberships`).Scan(&memberships))
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE invite_status = 'ACTIVE'),
		       count(*) FILTER (WHERE invite_status = 'PENDING'),
		       count(*) FILTER (WHERE invite_status = 'BLOCKED')
		  FROM kaname.users`).Scan(&k1Active, &k2Pending, &k3Blocked)) //nolint:gosec // счётчики переписи
	t.Logf("перепись: строк пользователей %d (К1 активен %d · К2 приглашён %d · К3 заблокирован %d), "+
		"членств %d, из них посевных строк до пробы %d",
		usersAfter, k1Active, k2Pending, k3Blocked, memberships, seededByMigrations)

	require.Equal(t, usersBefore, usersAfter,
		"миграция S1 — expand: она не вправе ни завести, ни снять ни одной строки пользователя")
	require.Equal(t, k1Active+k2Pending+k3Blocked, usersAfter,
		"IAM-ID-1-41: сумма К1+К2+К3 обязана сойтись с общим числом строк — "+
			"иначе классы не образуют разбиения и часть строк не проверена ничем")

	// ── IAM-ID-1-11: членств ровно столько же, сколько строк ─────────────────
	require.Equal(t, usersAfter, memberships,
		"бэкфилл взаимно однозначен: одно членство на строку, ни одного лишнего")

	// ── IAM-ID-1-11: обратная перепись пуста в ОБЕ стороны ───────────────────
	usersWithoutMembership := usersMissingMembership(t, db)
	require.Empty(t, usersWithoutMembership,
		"строки без членства: бэкфилл их пропустил — %v", usersWithoutMembership)

	var membershipsWithoutUser int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM kaname.memberships m
		 WHERE NOT EXISTS (SELECT 1 FROM kaname.users u WHERE u.id = m.user_id)`).
		Scan(&membershipsWithoutUser))
	require.Zero(t, membershipsWithoutUser, "членство без строки пользователя")

	// ── IAM-ID-1-11: членство ведёт В ТОТ ЖЕ аккаунт, что и колонка ──────────
	var mismatched int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM kaname.users u
		  JOIN kaname.memberships m ON m.user_id = u.id
		 WHERE m.account_id <> u.account_id`).Scan(&mismatched))
	require.Zero(t, mismatched,
		"членство обязано вести в тот же аккаунт, что стоит в снимаемой колонке — "+
			"иначе бэкфилл переписал принадлежность, а не перенёс её")

	// ── IAM-ID-1-39 / 72: состояние членства следует состоянию строки ────────
	require.Equal(t, "ACTIVE", membershipState(t, db, activeUser),
		"К1 активен → членство активно")
	require.Equal(t, "PENDING", membershipState(t, db, pendingUser),
		"IAM-ID-1-39: класс «приглашён» переезжает состоянием, а не теряет его")
	require.Equal(t, "ACTIVE", membershipState(t, db, blockedUser),
		"IAM-ID-1-72: блокировка — свойство ЛИЧНОСТИ, а не членства (решение по В-8), "+
			"поэтому у заблокированной строки членство обычное; сама строка остаётся заблокированной")

	// Та же половина IAM-ID-1-72, о которой проба обязана сказать прямо:
	// переход не оживляет заблокированного.
	require.Equal(t, "BLOCKED", inviteStatus(t, db, blockedUser),
		"переход не вправе снимать блокировку")

	// Аккаунты сеялись разные — иначе «членство ведёт в тот же аккаунт» прошло бы
	// и при бэкфилле, подставляющем один аккаунт всем.
	require.Equal(t, activeAcc, membershipAccount(t, db, activeUser))
	require.Equal(t, pendingAcc, membershipAccount(t, db, pendingUser))
	require.Equal(t, blockedAcc, membershipAccount(t, db, blockedUser))

	// ── положительный контроль предиката ОТСУТСТВИЯ ──────────────────────────
	// Утверждение «строк без членства нет» молчит и когда их нет, и когда сам
	// запрос сломан. Снимаем одно членство и требуем, чтобы предикат нашёл
	// ровно его.
	_, err := db.ExecContext(ctx,
		`DELETE FROM kaname.memberships WHERE user_id = $1`, activeUser)
	require.NoError(t, err)
	found := usersMissingMembership(t, db)
	require.Equal(t, []string{activeUser}, found,
		"предикат «строка без членства» обязан НАХОДИТЬ настоящую находку и называть её; "+
			"молчание здесь означало бы, что предыдущая пустота ничего не доказывала")
}

func usersMissingMembership(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT u.id FROM kaname.users u
		 WHERE NOT EXISTS (SELECT 1 FROM kaname.memberships m WHERE m.user_id = u.id)
		 ORDER BY u.id`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

func membershipState(t *testing.T, db *sql.DB, userID string) string {
	t.Helper()
	var st string
	require.NoError(t, db.QueryRow(
		`SELECT state FROM kaname.memberships WHERE user_id = $1`, userID).Scan(&st))
	return st
}

func membershipAccount(t *testing.T, db *sql.DB, userID string) string {
	t.Helper()
	var acc string
	require.NoError(t, db.QueryRow(
		`SELECT account_id FROM kaname.memberships WHERE user_id = $1`, userID).Scan(&acc))
	return acc
}

func inviteStatus(t *testing.T, db *sql.DB, userID string) string {
	t.Helper()
	var st string
	require.NoError(t, db.QueryRow(
		`SELECT invite_status FROM kaname.users WHERE id = $1`, userID).Scan(&st))
	return st
}
