// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// identity_merge_membership_state_integration_test.go — ВЫХОД из состояния
// «приглашён» утверждается, а не подразумевается (задача #1044).
//
// # Что здесь держится
//
// У человека может быть больше одного членства, и состояние каждого обязано
// следовать ЛИЧНОСТИ, а не тому аккаунту, через который членство завелось.
// Держит это зеркало `membership_mirror_from_user()` — точнее, его ТРЕТЬЯ
// ветвь, отдельная от двух первых:
//
//	IF NEW.invite_status <> 'PENDING' THEN
//	    UPDATE kacho_iam.memberships SET state = 'ACTIVE'
//	     WHERE user_id = NEW.id AND state = 'PENDING';
//	END IF;
//
// Первые две ветви правят членство ТОГО аккаунта, что стоит в колонке строки
// (`account_id = NEW.account_id`), и до второго членства не достают вовсе.
// Значит без третьей ветви человек, вошедший в продукт, остаётся «приглашённым»
// во всех аккаунтах, кроме одного.
//
// # Почему проба нужна, хотя состояние сегодня верное
//
// Верность держится ничем, кроме этих трёх проб. Соседние пробы членства читают
// у него ТОЛЬКО аккаунт (`membershipAccountsOf`), а пробы зеркала —
// `pg/membership_mirror_integration_test.go` — утверждают ВХОД в состояние
// («приглашённому ставится PENDING») и ни одна не утверждает ВЫХОД из него.
// Снимут третью ветвь — не покраснеет ничто.
//
// Наблюдаемо для арендатора это выглядит так: человек вошёл, а второй аккаунт
// пропал из его собственного ответа «кто я» — `ListAccountsForUser` отбирает по
// `state = 'ACTIVE'`, — при том что администратор того аккаунта власть над его
// личностью сохраняет (§16 реестра отступлений). Пропажа тише приобретения, и
// заметить её некому.
//
// # Здесь стояли пробы СВЕДЕНИЯ строк личности — предмет у них снят
//
// Прежняя редакция строила второе членство сведением дублей: цепочка
// останавливалась перед миграцией переноса, сеялись две строки на одну почту,
// и перенос сводил их в одну. Ни того, ни другого в дереве больше нет — 171
// миграция сведена в один свод, а глобальный ключ `users_identity_email_uniq`
// делает две строки на одну почту НЕПРЕДСТАВИМЫМИ by construction.
//
// Умерла ЛЕСТНИЦА, а не свойство: второе членство строится прямой вставкой —
// ровно так же, как это делает соседняя проба зеркала
// (`TestIntegration_MirrorKeepsMembershipsItDidNotCreate`), — и утверждается то
// же самое. Инъекция стала СИЛЬНЕЕ прежней: она подаёт переход «первый вход»
// напрямую и потому судит третью ветвь, а не исход миграции, внутри которой та
// ветвь была лишь одним из стейтментов.

import (
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
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

// personInvitedToTwoAccounts — общая посадка: приглашённый человек, у которого
// ДВА членства и оба «приглашён».
//
// Второе членство вставляется ПРЯМО, а не заводится зеркалом: зеркало заводит
// членство только того аккаунта, что стоит в колонке строки, и второго не
// создаёт ни при каком входе. Именно поэтому оно и есть предмет — состояние
// такого членства правит только третья ветвь.
//
// Идентификатор берётся у `membership_mirror_id`, а не выдумывается: форму
// держит `memberships_id_form_check`, и фикстура обязана быть не снисходительнее
// продукта.
func personInvitedToTwoAccounts(t *testing.T, tagA, tagB, email string) (*sql.DB, string, string, string) {
	t.Helper()
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	t.Cleanup(func() { _ = db.Close() })

	_, accA := seedAccountWithOwner(t, db, tagA)
	_, accB := seedAccountWithOwner(t, db, tagB)

	person := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "pp"+tagA), email, accA, "PENDING", "")

	_, err := db.Exec(`
		INSERT INTO kacho_iam.memberships (id, user_id, account_id, state)
		VALUES (kacho_iam.membership_mirror_id($1, $2), $1, $2, 'PENDING')`, person, accB)
	require.NoError(t, err, "посев второго членства человека %s в аккаунте %s", person, accB)

	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, person),
		"ПРЕДПОСЫЛКА: членств обязано быть ДВА — на одном членстве третья ветвь "+
			"неотличима от второй, и всякое утверждение ниже зеленело бы при её отсутствии")
	require.Equal(t, []string{accA, accB}, pendingMembershipsOf(t, db, person),
		"ПРЕДПОСЫЛКА: оба членства обязаны быть «приглашён» — иначе выходить неоткуда "+
			"и проба ни о чём не говорит")

	return db, person, accA, accB
}

// logIn — первый вход человека. Ровно то, что делает `ActivateInvite`: строка
// перестаёт быть приглашением и получает внешний субъект.
func logIn(t *testing.T, db *sql.DB, person, externalID string) {
	t.Helper()
	res, err := db.Exec(`
		UPDATE kacho_iam.users
		   SET invite_status = 'ACTIVE', external_id = $2
		 WHERE id = $1`, person, externalID)
	require.NoError(t, err)
	affected, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, affected, "вход не состоялся: строка человека не изменена")
}

// TestIntegration_SecondMembershipOfAPersonWhoLoggedInIsNotLeftPending — главное
// утверждение: у ВОШЕДШЕГО человека ни одно членство не остаётся «приглашён».
//
// «Приглашён» означает «приглашение выдано, человек ещё не вошёл». После входа
// это утверждение ложно о человеке, а не об аккаунте, поэтому членство, в нём
// оставшееся, лжёт единственному читателю состояния — `ListAccountsForUser`,
// который отдаёт ответ «кто я».
func TestIntegration_SecondMembershipOfAPersonWhoLoggedInIsNotLeftPending(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	const email = "moved-in@example.test"
	db, person, accA, accB := personInvitedToTwoAccounts(t, "movedaaa", "movedbbb", email)

	logIn(t, db, person, "ext-moved")

	t.Logf("осмотрено: строка %s, членств %d — %v",
		person, len(membershipStatesOf(t, db, person)), membershipStatesOf(t, db, person))

	require.Empty(t, pendingMembershipsOf(t, db, person),
		"членство вошедшего человека осталось «приглашён». Состояние следует АККАУНТУ, через "+
			"который членство завелось, вместо того чтобы следовать личности: первые две ветви "+
			"зеркала правят только членство своего аккаунта (`account_id = NEW.account_id`), а "+
			"третья — та, что достаёт до остальных, — не сработала. `ListAccountsForUser` "+
			"отбирает по `state = 'ACTIVE'`, поэтому такой аккаунт пропадает из ответа «кто я» "+
			"— при том что власть администратора этого аккаунта над личностью сохраняется "+
			"(§16 реестра отступлений)")

	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, person),
		"зеркало сняло членство, которого не заводило: вход обязан активировать ВСЕ членства, "+
			"а не оставлять человека в одном аккаунте (IAM-ID-1-04)")
}

// TestIntegration_SecondMembershipOfAPersonWhoNeverLoggedInStaysPending —
// ЗАКОННЫЙ БЛИЗНЕЦ, а не украшение.
//
// Утверждаемое свойство — «состояние следует ЛИЧНОСТИ», а НЕ «всё становится
// активным». Без этой стороны проба выше осталась бы зелёной на зеркале,
// переводящем в «активно» любую правку строки, — то есть на приглашении,
// объявившем человека вошедшим.
//
// Утверждаются ДВА момента, потому что беззаботность зеркала бывает двух видов:
// «оно активирует при заведении» и «оно активирует при любой правке». Первый
// ловится состоянием сразу после посева, второй — правкой, входом НЕ являющейся.
func TestIntegration_SecondMembershipOfAPersonWhoNeverLoggedInStaysPending(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	const email = "never-in@example.test"
	db, person, accA, accB := personInvitedToTwoAccounts(t, "neveraaa", "neverbbb", email)

	// Правка строки, входом НЕ являющаяся: приглашение остаётся приглашением.
	_, err := db.Exec(`
		UPDATE kacho_iam.users SET display_name = 'renamed' WHERE id = $1`, person)
	require.NoError(t, err)

	t.Logf("осмотрено: строка %s, членств %d — %v",
		person, len(membershipStatesOf(t, db, person)), membershipStatesOf(t, db, person))

	require.Equal(t, []string{accA, accB}, pendingMembershipsOf(t, db, person),
		"членство человека, НЕ входившего ни разу, переведено в «активно». Это не починка, а "+
			"расширение: приглашение объявлено принятым за того, кто его не принимал, и "+
			"`ListAccountsForUser` назовёт ему аккаунт, в который он не входил")
}

// TestIntegration_ThePendingMembershipPredicateCanSeeAViolation — ИНЪЕКЦИЯ.
//
// Проба выше утверждает ОТСУТСТВИЕ — «приглашённых членств нет». Такое
// утверждение зеленеет на предикате, который не видит ничего: на опечатке в
// имени состояния, на запросе не к той таблице, на пустой выборке из-за
// неверного идентификатора. Поэтому тот же самый предикат ставится перед
// нарушением, ВНЕСЁННЫМ в живые строки, и обязан его назвать.
//
// Дефект вносится в ДАННЫЕ, а не в зеркало: зеркало правит состояние только на
// записи строки человека, и проба, чинящая его через строку, измеряла бы ту же
// третью ветвь второй раз вместо способности предиката видеть.
func TestIntegration_ThePendingMembershipPredicateCanSeeAViolation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	const email = "inject@example.test"
	db, person, _, accB := personInvitedToTwoAccounts(t, "injectaa", "injectbb", email)

	logIn(t, db, person, "ext-inject")

	require.Empty(t, pendingMembershipsOf(t, db, person),
		"ПРЕДПОСЫЛКА инъекции: до внесения дефекта приглашённых членств быть не должно — "+
			"иначе инъекция ничего не доказывает")

	res, err := db.Exec(`
		UPDATE kacho_iam.memberships SET state = 'PENDING'
		 WHERE user_id = $1 AND account_id = $2`, person, accB)
	require.NoError(t, err)
	affected, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, affected,
		"дефект не внесён: строка, которую предикат обязан увидеть, не изменена")

	require.Equal(t, []string{accB}, pendingMembershipsOf(t, db, person),
		"предикат НЕ УВИДЕЛ внесённого нарушения — значит зелёное в пробах выше "+
			"означает «ничего не прочитано», а не «нарушений нет»")
}
