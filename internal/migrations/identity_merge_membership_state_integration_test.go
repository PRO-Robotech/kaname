// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package migrations_test

// identity_merge_membership_state_integration_test.go — состояние ПЕРЕЕХАВШЕГО
// членства утверждается, а не подразумевается (задача #1044).
//
// # Что было измерено, прежде чем что-либо чинить
//
// Задача заявляла: после сведения строк личности переехавшее членство остаётся
// «приглашён» НАВСЕГДА. Замер по дереву показал, что это верно ровно до
// следующей миграции цепочки и неверно после неё:
//
//	группа (вошедший + приглашённый)   после переноса      после всей цепочки
//	                                   accB = PENDING      accB = ACTIVE
//	группа (никто не входил)           оба   PENDING       оба   PENDING
//
// То есть предмет — не состояние, а ОКНО, и окно это закрывается догоняющей
// правкой соседней миграции, внутри того же прогона мигратора. Правильное
// состояние выводится из ВЫЖИВШЕЙ строки («входил ли человек»), а не переносится
// со снимаемой, — и оба замера это подтверждают: там, где не входил никто,
// «приглашён» остаётся и остаётся ВЕРНО.
//
// # Почему проба всё-таки нужна, хотя состояние сегодня верное
//
// Верность держалась ничем. Соседние пробы сведения читают у членства ТОЛЬКО
// аккаунт (`membershipAccountsOf`), поэтому состояние могло разъехаться молча:
// снимут догоняющую правку — и никто не заметит; напишут следующую миграцию
// сведения по образцу этой — догоняющая правка второй раз не выполнится, потому
// что она одноразовая.
//
// Наблюдаемо для арендатора это выглядит так: человек вошёл, а второй аккаунт
// пропал из его собственного ответа «кто я» — при том что администратор того
// аккаунта власть над его личностью сохраняет (§16 реестра отступлений).
// Пропажа тише приобретения, и заметить её некому.
//
// # Что утверждается — ВЫХОД из состояния, а не вход в него
//
// Вход работает и без этих проб: зеркало ставит «приглашён» приглашённому. Здесь
// утверждается, что из «приглашён» есть выход для того, кто вошёл, — и что для
// того, кто не входил, выхода нет.

import (
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// membershipStatesOf — членства человека как «аккаунт=состояние». Читает
// СОСТОЯНИЕ, в отличие от `membershipAccountsOf`: именно его отсутствие в
// утверждениях и оставило класс без наблюдения.
func membershipStatesOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT account_id, state FROM kacho_iam.memberships WHERE user_id = $1`, userID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var account, state string
		require.NoError(t, rows.Scan(&account, &state))
		out = append(out, account+"="+state)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// pendingMembershipsOf — членства, оставшиеся «приглашён». ОДНА функция на все
// три пробы ниже, включая ту, что доказывает её способность увидеть нарушение:
// вторая копия предиката разошлась бы с первой молча.
func pendingMembershipsOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT account_id FROM kacho_iam.memberships
		 WHERE user_id = $1 AND state = 'PENDING' ORDER BY account_id`, userID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var account string
		require.NoError(t, rows.Scan(&account))
		out = append(out, account)
	}
	require.NoError(t, rows.Err())
	return out
}

// mergedPairOnTheFullChain — общая посадка: два дубля одной почты сводятся, и
// цепочка миграций доводится ДО КОНЦА.
//
// До конца — принципиально. Останавливаться на самой миграции сведения значило
// бы судить об одном её стейтменте, тогда как арендатор видит СОСТОЯНИЕ ДЕРЕВА:
// на поднятом стенде применено всё, что есть.
func mergedPairOnTheFullChain(t *testing.T, tagA, tagB, email, firstStatus, secondStatus string) (*sql.DB, string, string, string) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	t.Cleanup(func() { _ = db.Close() })

	_, accA := seedAccountWithOwner(t, db, tagA)
	_, accB := seedAccountWithOwner(t, db, tagB)

	first := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aa"+tagA), email, accA, firstStatus, "ext-"+tagA)
	second := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zz"+tagB), email, accB, secondStatus, "ext-"+tagB)

	require.Len(t, rowsWithEmail(t, db, email), 2,
		"ПРЕДПОСЫЛКА: дублей обязано быть два — на одной строке сведение беспредметно")

	require.NoError(t, goose.Up(db, "."),
		"цепочка обязана доходить до конца: арендатор видит применённое дерево, "+
			"а не отдельный стейтмент")

	survivors := rowsWithEmail(t, db, email)
	require.Len(t, survivors, 1,
		"после сведения у человека обязана остаться ОДНА строка, иначе проба говорит "+
			"не о переехавшем членстве")
	_ = second
	_ = first
	return db, survivors[0], accA, accB
}

// TestIntegration_MovedMembershipOfAPersonWhoLoggedInIsNotLeftPending — главное
// утверждение: у ВОШЕДШЕГО человека ни одно членство не остаётся «приглашён».
//
// «Приглашён» означает «приглашение выдано, человек ещё не вошёл». На выжившей
// строке это утверждение ложно by construction: строка выжила потому, что по ней
// входили. Членство, оставшееся в этом состоянии, лжёт о человеке — и лжёт
// единственному читателю состояния, `ListAccountsForUser`, который отдаёт ответ
// «кто я».
func TestIntegration_MovedMembershipOfAPersonWhoLoggedInIsNotLeftPending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	const email = "moved-in@example.test"
	db, survivor, accA, accB := mergedPairOnTheFullChain(t, "movedaaa", "movedbbb", email, "ACTIVE", "PENDING")

	t.Logf("осмотрено: выжившая строка %s, членств %d — %v",
		survivor, len(membershipStatesOf(t, db, survivor)), membershipStatesOf(t, db, survivor))

	// ПРЕДПОСЫЛКА: членство действительно ПЕРЕЕХАЛО. Без неё утверждение
	// «ничего не осталось приглашённым» зеленело бы на человеке, у которого
	// второго членства нет вовсе.
	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, survivor),
		"ПРЕДПОСЫЛКА: членства обоих аккаунтов обязаны быть на выжившей строке — "+
			"иначе переезжать было нечему и проба ни о чём не говорит")

	require.Empty(t, pendingMembershipsOf(t, db, survivor),
		"членство вошедшего человека осталось «приглашён». Состояние переехало со "+
			"снимаемой строки вместо того, чтобы быть выведенным из выжившей: "+
			"`ListAccountsForUser` отбирает по `state = 'ACTIVE'`, поэтому такой аккаунт "+
			"пропадает из ответа «кто я» — при том что власть администратора этого "+
			"аккаунта над личностью сохраняется (§16 реестра отступлений)")
}

// TestIntegration_MovedMembershipOfAPersonWhoNeverLoggedInStaysPending —
// ЗАКОННЫЙ БЛИЗНЕЦ, а не украшение.
//
// Утверждаемое свойство — «состояние выводится из выжившей строки», а НЕ «всё
// становится активным». Без этой стороны предыдущая проба осталась бы зелёной на
// коде, который переводит в «активно» ВСЁ подряд, — то есть на приглашении,
// объявившем человека вошедшим. Приобретение тише потери, и ловить его надо
// отдельным утверждением.
func TestIntegration_MovedMembershipOfAPersonWhoNeverLoggedInStaysPending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	const email = "never-in@example.test"
	db, survivor, accA, accB := mergedPairOnTheFullChain(t, "neveraaa", "neverbbb", email, "PENDING", "PENDING")

	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, survivor),
		"ПРЕДПОСЫЛКА: членства обоих аккаунтов обязаны быть на выжившей строке")

	require.Equal(t, []string{accA, accB}, pendingMembershipsOf(t, db, survivor),
		"членство человека, НЕ входившего ни разу, переведено в «активно». Это не "+
			"починка, а расширение: приглашение объявлено принятым за того, кто его "+
			"не принимал, и `ListAccountsForUser` назовёт ему аккаунт, в который он "+
			"не входил")
}

// TestIntegration_ThePendingMembershipPredicateCanSeeAViolation — ИНЪЕКЦИЯ.
//
// Проба выше утверждает ОТСУТСТВИЕ — «приглашённых членств нет». Такое
// утверждение зеленеет на предикате, который не видит ничего: на опечатке в
// имени состояния, на запросе не к той таблице, на пустой выборке из-за
// неверного идентификатора. Поэтому тот же самый предикат ставится перед
// нарушением, ВНЕСЁННЫМ в живые строки, и обязан его назвать.
//
// Дефект вносится не в миграцию, а в данные: миграция одноразова, и проба,
// привязанная к её версии, стала бы закреплять дефект как желаемое поведение —
// а он желаемым не является и, будучи однажды починен в самом стейтменте, сделал
// бы такую пробу ложной тревогой.
func TestIntegration_ThePendingMembershipPredicateCanSeeAViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	const email = "inject@example.test"
	db, survivor, _, accB := mergedPairOnTheFullChain(t, "injectaa", "injectbb", email, "ACTIVE", "PENDING")

	require.Empty(t, pendingMembershipsOf(t, db, survivor),
		"ПРЕДПОСЫЛКА инъекции: до внесения дефекта приглашённых членств быть не должно — "+
			"иначе инъекция ничего не доказывает")

	res, err := db.Exec(`
		UPDATE kacho_iam.memberships SET state = 'PENDING'
		 WHERE user_id = $1 AND account_id = $2`, survivor, accB)
	require.NoError(t, err)
	affected, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, affected,
		"дефект не внесён: строка, которую предикат обязан увидеть, не изменена")

	require.Equal(t, []string{accB}, pendingMembershipsOf(t, db, survivor),
		"предикат НЕ УВИДЕЛ внесённого нарушения — значит зелёное в пробах выше "+
			"означает «ничего не прочитано», а не «нарушений нет»")
}
