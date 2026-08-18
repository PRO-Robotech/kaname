// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// membership_backfill_integration_test.go — стадия S1 отрыва аккаунта от строки
// пользователя (IAM-ID-1, задача kacho#470): бэкфилл взаимно однозначен.
//
// Приёмка требует (IAM-ID-1-11): после миграции S1 членств ровно столько же,
// сколько строк пользователей; членство каждой строки ведёт В ТОТ ЖЕ аккаунт,
// что стоит в её колонке; обратная перепись пуста — нет ни членства без строки,
// ни строки без членства.
//
// Проба ХОДИТ ПО ЦЕПОЧКЕ САМА: поднимает пустую базу, доводит её до версии
// НЕПОСРЕДСТВЕННО ПЕРЕД миграцией членств, сеет строки всех трёх классов
// состояния — и только потом применяет миграцию. Иначе она проверяла бы
// зеркало, которое строит триггер на её же вставках, а не бэкфилл УЖЕ ЛЕЖАЩИХ
// строк — то есть ровно то, ради чего миграция и пишется. Механизм тот же,
// которым идёт страж дропов в этом же пакете.
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
// нашёл ровно одну строку и назвала её. Без этого исчезновение предмета и
// поломка предиката неразличимы by construction (testing.md §«Гейт на класс»
// п.2 — инъекция в обе стороны).

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// membershipMigrationVersion — версия миграции, заводящей членства. Номер
// выведен из задачи (#470), а не выбран из каталога: порядковая эра закрыта
// именно потому, что номер, выбранный из каталога, две линии выбирают одинаково
// и слияние принимает это молча.
//
// Проба доводит цепочку до `version-1` — то есть до ВСЕГО, что нумеровано ниже,
// сколько бы его ни было. Хардкод «сто» здесь устарел бы от первой же соседней
// миграции.
const membershipMigrationVersion = 470001

// upTo доводит цепочку до version включительно.
func upTo(t *testing.T, dsn string, version int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", version),
		"цепочка обязана доходить до %d — иначе проба говорит не о том дереве", version)
	return db
}

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
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, externalID, tag+"@example.test", "User "+tag, accountID, inviteStatus)
	require.NoError(t, err, "посев строки класса %s", inviteStatus)

	_, err = tx.Exec(`
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
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

	// ── стадия «до»: цепочка доведена до версии перед членствами ──────────────
	db := upTo(t, dsn, membershipMigrationVersion-1)
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
		`SELECT count(*) FROM kacho_iam.users`).Scan(&seededByMigrations))
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
		`SELECT count(*) FROM kacho_iam.users`).Scan(&usersBefore))

	// ── миграция членств ─────────────────────────────────────────────────────
	//
	// Ровно ДО неё и не дальше. Взаимная однозначность «одно членство на строку»
	// — свойство КОНЦА СТАДИИ S1, а не вечный инвариант: следующая стадия
	// намеренно даёт человеку второе членство (владелец, состоящий в чужом
	// аккаунте по своей строке, получает членство и в том, которым владеет), и
	// человек в N аккаунтах — вообще предмет всего перехода. Прогнав здесь всю
	// цепочку, проба утверждала бы об S1 то, что дерево обязано нарушить дальше,
	// и краснела бы на верной работе соседней стадии.
	require.NoError(t, goose.UpTo(db, ".", membershipMigrationVersion),
		"миграция S1 обязана применяться на живой цепочке")

	// ── перепись: объём осмотренного печатается всегда (IAM-ID-1-41) ─────────
	var (
		usersAfter, memberships        int
		k1Active, k2Pending, k3Blocked int
	)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&usersAfter))
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.memberships`).Scan(&memberships))
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE invite_status = 'ACTIVE'),
		       count(*) FILTER (WHERE invite_status = 'PENDING'),
		       count(*) FILTER (WHERE invite_status = 'BLOCKED')
		  FROM kacho_iam.users`).Scan(&k1Active, &k2Pending, &k3Blocked)) //nolint:gosec // счётчики переписи
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
		SELECT count(*) FROM kacho_iam.memberships m
		 WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.users u WHERE u.id = m.user_id)`).
		Scan(&membershipsWithoutUser))
	require.Zero(t, membershipsWithoutUser, "членство без строки пользователя")

	// ── IAM-ID-1-11: членство ведёт В ТОТ ЖЕ аккаунт, что и колонка ──────────
	var mismatched int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM kacho_iam.users u
		  JOIN kacho_iam.memberships m ON m.user_id = u.id
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
		`DELETE FROM kacho_iam.memberships WHERE user_id = $1`, activeUser)
	require.NoError(t, err)
	found := usersMissingMembership(t, db)
	require.Equal(t, []string{activeUser}, found,
		"предикат «строка без членства» обязан НАХОДИТЬ настоящую находку и называть её; "+
			"молчание здесь означало бы, что предыдущая пустота ничего не доказывала")
}

// TestIntegration_MembershipExpandRollsBackWhole — IAM-ID-1-50: откат S1 полон.
//
// Expand безопасен ровно настолько, насколько обратим: пока читателей у новой
// таблицы нет, снятие её — ОДНО действие, и после него продукт обязан вести себя
// в точности как до стадии. Проба утверждает не «шаг отката выполнился», а
// состояние после него: зеркала нет, строки людей целы, запись строки снова
// работает.
func TestIntegration_MembershipExpandRollsBackWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)

	db := upTo(t, dsn, membershipMigrationVersion)
	defer func() { _ = db.Close() }()

	var usersBefore int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&usersBefore))
	require.Positive(t, usersBefore,
		"на пустой таблице «строки целы» истинно тождественно")

	// Зеркало на месте — иначе откат снимал бы то, чего нет, и проба зеленела бы
	// на дереве, где стадия не применилась вовсе.
	var memberships int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.memberships`).Scan(&memberships))
	require.Equal(t, usersBefore, memberships)

	require.NoError(t, goose.Down(db, "."), "обратный шаг обязан исполняться")

	// ── таблицы нет ──────────────────────────────────────────────────────────
	require.False(t, relationExists(t, db, "memberships"),
		"откат снимает таблицу членств целиком")

	// ── триггер и обе функции ушли вместе с ней ──────────────────────────────
	var triggers int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_trigger
		 WHERE NOT tgisinternal AND tgname = 'membership_mirrors_user_row'`).Scan(&triggers))
	require.Zero(t, triggers,
		"триггер, пишущий в снятую таблицу, ронял бы КАЖДУЮ запись строки пользователя — "+
			"то есть неполный откат был бы хуже отсутствующего")

	var funcs int
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'kacho_iam'
		   AND p.proname IN ('membership_mirror_from_user', 'membership_mirror_id')`).Scan(&funcs))
	require.Zero(t, funcs, "функции зеркала уходят вместе с ним")

	// ── строки людей целы: expand их не трогал, откат тем более ──────────────
	var usersAfter int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&usersAfter))
	require.Equal(t, usersBefore, usersAfter,
		"откат не вправе тронуть ни одной строки пользователя: авторитет принадлежности "+
			"всю стадию оставался у колонки, и откатывать в них нечего")

	// ── продукт снова работает: запись строки проходит ───────────────────────
	// Это и есть «поведение то же, что до S1». Без этого утверждения откат мог бы
	// оставить после себя нерабочую вставку и всё равно выглядеть полным.
	_, _ = seedUser(t, db, "rollback", "ACTIVE")
	t.Logf("перепись отката: строк пользователей до %d, после %d; членств до отката %d",
		usersBefore, usersAfter, memberships)
}

func relationExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
		 WHERE ns.nspname = 'kacho_iam' AND c.relname = $1`, name).Scan(&n))
	return n > 0
}

func usersMissingMembership(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT u.id FROM kacho_iam.users u
		 WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.memberships m WHERE m.user_id = u.id)
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
		`SELECT state FROM kacho_iam.memberships WHERE user_id = $1`, userID).Scan(&st))
	return st
}

func membershipAccount(t *testing.T, db *sql.DB, userID string) string {
	t.Helper()
	var acc string
	require.NoError(t, db.QueryRow(
		`SELECT account_id FROM kacho_iam.memberships WHERE user_id = $1`, userID).Scan(&acc))
	return acc
}

func inviteStatus(t *testing.T, db *sql.DB, userID string) string {
	t.Helper()
	var st string
	require.NoError(t, db.QueryRow(
		`SELECT invite_status FROM kacho_iam.users WHERE id = $1`, userID).Scan(&st))
	return st
}
