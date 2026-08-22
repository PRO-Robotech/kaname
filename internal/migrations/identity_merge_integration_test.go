// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// identity_merge_integration_test.go — стадия S2 перехода IAM-ID-1 (задача
// kacho#472): права переносятся при отрыве идентичности и НЕ расширяются.
//
// # Предмет — измерен, а не пересказан из задачи
//
// Задача формулирует предмет как «один человек в двух аккаунтах имеет два
// идентификатора и два набора прав». Приёмка (§5 группа D, выноска) сужает это
// до состояния, которое ДЕЙСТВИТЕЛЬНО конструируемо на дереве, и знать сужение
// обязательно — иначе Given неисполним:
//
//   - двух ACTIVE-строк у одного человека быть не может: глобальный ключ
//     `users_active_external_id_uniq` этого не допускает;
//   - а вот две строки «приглашён» — могут. Приглашение резолвит субъект в
//     старейшую ACTIVE-строку по почте; для ни разу не входившего таковой нет,
//     и право выдаётся на его ПЕР-АККАУНТНУЮ строку. Пригласив такого человека
//     в два аккаунта, получаем две строки с разными субъектами и по праву на
//     каждой. Первый вход активирует ОДНУ; вторая остаётся неактивируемой, а
//     выданное на неё право — ОСИРОТЕВШИМ: оно лежит в леджере и не действует
//     ни для кого.
//
// Отсюда предмет переноса: строки-дубли сводятся к одной личности, а права,
// выданные на снимаемые строки, переезжают на выжившую — С СОХРАНЕНИЕМ ОБЛАСТИ.
//
// # Почему «не расширяясь» — ОТДЕЛЬНАЯ проба, а не примечание к первой
//
// Проба переноса утверждает, что право ДОЕХАЛО. На вопрос «не приехало ли
// сверх того» она не отвечает вовсе: множество «после» может содержать
// доехавшее И лишнее одновременно, и первая проба останется зелёной. Это
// разные утверждения о разных множествах, и сливать их в одно значит потерять
// то, которое дороже: расширение доступа тише потери — потерю замечает
// пострадавший, приобретение не замечает никто.
//
// # Что здесь НЕ утверждается — граница названа
//
// Исход `Check` (материализованный вердикт) здесь не утверждается: его считает
// реконсайлер в Go, и в окне после переноса он ещё не сошёлся (IAM-ID-1-32 —
// перенос НЕ гейтится на видимость, ban #9). Предмет этих проб — ЛЕДЖЕР
// выдач: кто на каком объекте назван субъектом. Материализация читает его же,
// поэтому расширение ледждера есть необходимое условие расширения доступа, а
// отсутствие расширения в леджере — необходимое условие его отсутствия в
// вердикте. Проба на исход `Check` живёт уровнем выше и здесь не дублируется.

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// identityMergeVersion — версия миграции переноса. Метка времени заведения, а
// не номер задачи: `TestNewMigrationOutranksEveryAppliedOne` требует именно её —
// номер по задаче у #472 меньше уже применённых, и мигратор такую версию на
// живой базе не применит.
const identityMergeVersion = 20260822234500

// seedAccountWithOwner заводит аккаунт вместе с его владельцем одной
// транзакцией: оба ключа цикла объявлены DEFERRABLE INITIALLY DEFERRED, поэтому
// порядок внутри транзакции значения не имеет.
func seedAccountWithOwner(t *testing.T, db *sql.DB, tag string) (ownerID, accountID string) {
	t.Helper()
	ownerID = "usr" + fmt.Sprintf("%017s", "own"+tag)
	accountID = "acc" + fmt.Sprintf("%017s", tag)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		ownerID, "ext-own-"+tag, "owner-"+tag+"@example.test", "Owner "+tag, accountID)
	require.NoError(t, err)

	_, err = tx.Exec(`
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		accountID, "acc-"+tag, ownerID)
	require.NoError(t, err)

	require.NoError(t, tx.Commit())
	return ownerID, accountID
}

// seedRowInAccount заводит строку человека в уже существующем аккаунте.
// externalID у приглашённого пуст — этого требует CHECK
// `users_invite_status_consistency`, и фикстура обязана быть не снисходительнее
// продукта, иначе она прячет тот самый класс, ради которого стоит.
func seedRowInAccount(t *testing.T, db *sql.DB, id, email, accountID, inviteStatus, externalID string) string {
	t.Helper()
	if inviteStatus == "PENDING" {
		externalID = ""
	}
	_, err := db.Exec(`
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, externalID, email, "Person", accountID, inviteStatus)
	require.NoError(t, err, "посев строки %s в аккаунте %s", id, accountID)
	return id
}

// anyAssignableRole — FK `access_bindings_role_fk` — RESTRICT, поэтому
// идентификатор роли выдумать нельзя; плюс триггер `access_bindings_role_assignable_trg`
// судит право роли стоять на этой области. Системная роль назначаема где угодно.
func anyAssignableRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRow(`
		SELECT id FROM kacho_iam.roles WHERE is_system ORDER BY id LIMIT 1`).Scan(&id))
	require.NotEmpty(t, id, "ПРЕДПОСЫЛКА: в дереве обязана быть системная роль — "+
		"триггер назначаемости принимает её на любой области, поэтому фикстура "+
		"не спорит с продуктом о праве роли стоять на этой выдаче")
	return id
}

// grantOn кладёт ACTIVE-выдачу: субъект — названная строка человека, область —
// названный объект. Сырым SQL намеренно: предмет пробы — перенос, и он обязан
// держать любого писателя леджера, а не только use-case.
func grantOn(t *testing.T, db *sql.DB, bindingID, subjectUserID, roleID, resType, resID string) string {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE')`,
		bindingID, subjectUserID, roleID, resType, resID)
	require.NoError(t, err, "посев выдачи %s", bindingID)
	_, err = db.Exec(`
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'user', $2, 0)`, bindingID, subjectUserID)
	require.NoError(t, err, "посев субъекта выдачи %s", bindingID)
	return bindingID
}

// grantScopesOf — множество областей, на которых НАЗВАННАЯ строка человека
// является субъектом живой выдачи, в форме "<тип>:<идентификатор>".
//
// Читает ОБЕ проекции субъекта — легаси-одиночную (`access_bindings.subject_id`)
// и множественную (`access_binding_subjects`), — потому что перенос обязан
// пройти по обеим: строка, переехавшая в одной и оставшаяся в другой, дала бы
// расхождение проекций, невидимое пробе, которая смотрит в одну.
func grantScopesOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT DISTINCT b.resource_type || ':' || b.resource_id
		  FROM kacho_iam.access_bindings b
		 WHERE b.status = 'ACTIVE'
		   AND (
		         (b.subject_type = 'user' AND b.subject_id = $1)
		      OR EXISTS (SELECT 1 FROM kacho_iam.access_binding_subjects s
		                  WHERE s.binding_id = b.id
		                    AND s.subject_type = 'user' AND s.subject_id = $1)
		       )
		 ORDER BY 1`, userID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	out := []string{}
	for rows.Next() {
		var scope string
		require.NoError(t, rows.Scan(&scope))
		out = append(out, scope)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

func membershipAccountsOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT account_id FROM kacho_iam.memberships WHERE user_id = $1 ORDER BY account_id`, userID)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var a string
		require.NoError(t, rows.Scan(&a))
		out = append(out, a)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

func rowsWithEmail(t *testing.T, db *sql.DB, email string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT id FROM kacho_iam.users WHERE lower(email) = lower($1) ORDER BY id`, email)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 1 — зеркало пережило появление ВТОРОГО членства.
//
// Зеркало S1 (470001) на всякой правке строки снимает членства, ведущие НЕ в тот
// аккаунт, что стоит в колонке: `DELETE … WHERE account_id <> NEW.account_id`.
// Пока членство у человека одно, это верно. Как только перенос даёт человеку
// второе, ЛЮБАЯ правка его строки — активация первым входом, смена отображаемого
// имени, блокировка — уничтожает перенесённое членство молча.
//
// Это предусловие переноса, а не украшение: перенос, чей результат снимается
// первым же входом человека, переносом не является.
func TestIntegration_MirrorKeepsMembershipsItDidNotCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "mirrorxa")
	_, accB := seedAccountWithOwner(t, db, "mirrorxb")

	person := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "mirrorp"), "mirror@example.test", accA, "PENDING", "")

	// Второе членство — то, которое переносу и предстоит завести.
	_, err := db.ExecContext(ctx, `
		INSERT INTO kacho_iam.memberships (id, user_id, account_id, state)
		VALUES (kacho_iam.membership_mirror_id($1, $2), $1, $2, 'ACTIVE')`, person, accB)
	require.NoError(t, err)

	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, person),
		"ПРЕДПОСЫЛКА: у человека обязано быть два членства — иначе проба ниже "+
			"истинна тождественно и зеленела бы при полностью разрушающем зеркале")

	// Первый вход: строка активируется. Ровно то, что делает `ActivateInvite`.
	_, err = db.ExecContext(ctx, `
		UPDATE kacho_iam.users
		   SET invite_status = 'ACTIVE', external_id = $2
		 WHERE id = $1`, person, "ext-mirror")
	require.NoError(t, err)

	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, person),
		"зеркало сняло членство, которого не заводило: перенос, отменяемый первым же "+
			"входом человека, переносом не является (IAM-ID-1-04 — вход активирует ВСЕ членства)")
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 2 — перенос: одна строка, оба членства, права доехали со своей областью.
func TestIntegration_DuplicateIdentityRowsMergeAndRightsTravelWithTheirScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)

	// Цепочка доводится до версии ПЕРЕД переносом: дубли обязаны уже лежать,
	// когда перенос применяется, — иначе проба измеряла бы поведение писателей,
	// а не работу миграции над УЖЕ существующими строками.
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "mergeaaa")
	ownerB, accB := seedAccountWithOwner(t, db, "mergebbb")

	const email = "person@example.test"
	// Каноническая строка — старейшая ACTIVE по почте: в неё край резолвит токен
	// и на неё уже выданы права.
	canonical := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aacanon"), email, accA, "ACTIVE", "ext-person")
	// Дубль: тот же человек, приглашённый во второй аккаунт и ни разу не
	// входивший. Его право осиротело.
	duplicate := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zzdupli"), email, accB, "PENDING", "")

	role := anyAssignableRole(t, db)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "grantaa"), canonical, role, "account", accA)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "grantbb"), duplicate, role, "account", accB)
	// Контроль: чужая выдача в том же аккаунте B. Перенос не вправе её тронуть.
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "grantob"), ownerB, role, "account", accB)

	require.Len(t, rowsWithEmail(t, db, email), 2,
		"ПРЕДПОСЫЛКА: дублей обязано быть два — на одной строке перенос беспредметен")

	require.NoError(t, goose.UpTo(db, ".", identityMergeVersion),
		"миграция переноса обязана применяться на живой цепочке")

	// ── одна строка на человека ──────────────────────────────────────────────
	require.Equal(t, []string{canonical}, rowsWithEmail(t, db, email),
		"после переноса у человека обязана остаться ОДНА строка, и это каноническая "+
			"(старейшая ACTIVE по почте) — та, на которую права уже выданы и в которую "+
			"край резолвит токен; идентификатор личности не перечеканивается (ban #15)")

	// ── членства обоих аккаунтов на выжившей строке ──────────────────────────
	require.Equal(t, []string{accA, accB}, membershipAccountsOf(t, db, canonical),
		"членства снятых строк обязаны переехать на выжившую: принадлежность аккаунту "+
			"есть отдельная связь, и человек состоит в обоих")

	// ── права доехали, каждое со СВОЕЙ областью ──────────────────────────────
	require.Equal(t,
		[]string{"account:" + accA, "account:" + accB},
		grantScopesOf(t, db, canonical),
		"осиротевшее право обязано доехать до выжившей строки, оставшись в том аккаунте, "+
			"где выдано (IAM-ID-1-28)")

	// ── чужая выдача не тронута ──────────────────────────────────────────────
	require.Equal(t, []string{"account:" + accB}, grantScopesOf(t, db, ownerB),
		"перенос тронул выдачу, к переносимой личности отношения не имеющую")

	// ── ни одна ссылка не указывает на снятую строку ─────────────────────────
	require.Empty(t, danglingSubjectRefs(t, db, duplicate),
		"в леджере остались ссылки на снятую строку: право, субъект которого не резолвится, "+
			"не действует ни для кого и при этом выглядит выданным")
}

// danglingSubjectRefs — ссылки на строку человека, которой больше нет.
func danglingSubjectRefs(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	out := []string{}
	for _, q := range []struct{ what, sql string }{
		{"access_bindings.subject_id", `
			SELECT count(*) FROM kacho_iam.access_bindings
			 WHERE subject_type = 'user' AND subject_id = $1`},
		{"access_binding_subjects.subject_id", `
			SELECT count(*) FROM kacho_iam.access_binding_subjects
			 WHERE subject_type = 'user' AND subject_id = $1`},
		{"memberships.user_id", `
			SELECT count(*) FROM kacho_iam.memberships WHERE user_id = $1`},
	} {
		var n int
		require.NoError(t, db.QueryRow(q.sql, userID).Scan(&n))
		if n > 0 {
			out = append(out, fmt.Sprintf("%s: %d", q.what, n))
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 3 — ОТРИЦАНИЕ: перенос не расширил доступ ни в одном аккаунте.
//
// Отдельная проба, а не примечание к предыдущей: та отвечает «доехало ли», эта —
// «не приехало ли сверх того». Множество «после» может содержать доехавшее И
// лишнее одновременно, и первая проба останется зелёной.
func TestIntegration_MergeGrantsNoAccessThatWasNotAlreadyGranted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "widenaaa")
	ownerB, accB := seedAccountWithOwner(t, db, "widenbbb")

	const email = "widen@example.test"
	canonical := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aawiden"), email, accA, "ACTIVE", "ext-widen")
	duplicate := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zzwiden"), email, accB, "PENDING", "")

	role := anyAssignableRole(t, db)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "wgranta"), canonical, role, "account", accA)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "wgrantb"), duplicate, role, "account", accB)

	// Объект в аккаунте B, на который человек прав НЕ ИМЕЕТ ни одной строкой.
	// Он и есть предмет отрицания: если перенос его выдаст, доступ расширился.
	// Выдача на него принадлежит другому человеку — то есть объект в леджере
	// существует, и «его нет в множестве после» не может быть истинным лишь
	// оттого, что о нём никто не писал.
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "wgrantf"), ownerB, role, "account", accB)

	// ── снимок «до», поаккаунтно ─────────────────────────────────────────────
	before := map[string][]string{
		canonical: grantScopesOf(t, db, canonical),
		duplicate: grantScopesOf(t, db, duplicate),
	}
	wantAfter := unionSorted(before[canonical], before[duplicate])
	t.Logf("снимок «до»: каноническая строка %v · дубль %v · объединение %v",
		before[canonical], before[duplicate], wantAfter)
	require.NotEmpty(t, wantAfter,
		"ПРЕДПОСЫЛКА: множество «до» не пусто — на пустом отрицание истинно тождественно")

	require.NoError(t, goose.UpTo(db, ".", identityMergeVersion))

	after := grantScopesOf(t, db, canonical)
	t.Logf("снимок «после»: %v", after)

	// ── ни одного лишнего объекта (IAM-ID-1-30) ──────────────────────────────
	require.Empty(t, subtract(after, wantAfter),
		"перенос выдал доступ, которого не было ни у одной из сведённых строк: "+
			"право обязано оставаться в границах того аккаунта, где выдано")

	// ── и ни одного потерянного (IAM-ID-1-29) ────────────────────────────────
	require.Empty(t, subtract(wantAfter, after),
		"перенос потерял доступ: множества обязаны совпадать поаккаунтно, элемент в элемент")

	// ── положительный контроль сравнения ─────────────────────────────────────
	// Утверждения выше молчат и когда расхождения нет, и когда сравнение само
	// сломано. Подаём заведомо расходящееся множество и требуем, чтобы то же
	// сравнение НАШЛО расхождение и назвало его.
	require.NotEmpty(t, subtract(after, subtract(wantAfter, []string{"account:" + accB})),
		"сравнение обязано НАХОДИТЬ настоящее расхождение: молчание здесь означало бы, "+
			"что обе пустоты выше не доказывали ничего")
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// subtract — что есть в a и нет в b.
func subtract(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

var _ = migrations.FS

// ─────────────────────────────────────────────────────────────────────────────
// Пробы 4 и 5 — ОТКАЗ умеет сработать.
//
// Миграция объявляет две группы неразрешимыми и роняет прогон. Объявленный, но
// ни разу не проверенный отказ — форма без содержания: он выглядит защитой и
// молчит ровно тогда, когда обязан заговорить. Здесь он ставится в условия, где
// обязан сработать, и рядом — положительный контроль: на разрешимых данных
// та же миграция проходит (его несут пробы 2 и 3 выше).

// applyMergeExpectingRefusal применяет миграцию и возвращает текст отказа.
func applyMergeExpectingRefusal(t *testing.T, db *sql.DB) string {
	t.Helper()
	err := goose.UpTo(db, ".", identityMergeVersion)
	require.Error(t, err,
		"миграция обязана ОТКАЗАТЬ на неразрешимой группе: сведение, принявшее решение "+
			"за владельца продукта, меняет чей-то доступ молча")
	return err.Error()
}

// TestIntegration_MergeRefusesAGroupItCannotDecide_BlockedRow — заблокированная
// строка среди дублей.
func TestIntegration_MergeRefusesAGroupItCannotDecide_BlockedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "refuseba")
	_, accB := seedAccountWithOwner(t, db, "refusebb")

	const email = "refuse-blocked@example.test"
	seedRowInAccount(t, db, "usr"+fmt.Sprintf("%017s", "rbactiv"), email, accA, "ACTIVE", "ext-rb")
	// Третье состояние: о нём сведение рассуждать не умеет.
	seedRowInAccount(t, db, "usr"+fmt.Sprintf("%017s", "rbblock"), email, accB, "BLOCKED", "ext-rb2")

	msg := applyMergeExpectingRefusal(t, db)
	require.Contains(t, msg, "заблокированную строку",
		"отказ обязан НАЗЫВАТЬ предмет: «миграция упала» без предмета не даёт оператору "+
			"ни одного следующего шага. Получено: %s", msg)

	// Строки на месте: отказавшая миграция не оставляет половины работы.
	require.Len(t, rowsWithEmail(t, db, email), 2,
		"отказ обязан быть полным: транзакция миграции откатывается целиком")
}

// TestIntegration_MergeRefusesAGroupItCannotDecide_TwoActiveRows — две разные
// внешние личности на одной почте.
func TestIntegration_MergeRefusesAGroupItCannotDecide_TwoActiveRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "refuse2a")
	_, accB := seedAccountWithOwner(t, db, "refuse2b")

	const email = "refuse-two-active@example.test"
	// Внешние идентификаторы РАЗНЫЕ — иначе строку отверг бы глобальный ключ
	// `users_active_external_id_uniq`, и проба измеряла бы его, а не отказ.
	seedRowInAccount(t, db, "usr"+fmt.Sprintf("%017s", "r2first"), email, accA, "ACTIVE", "ext-r2-one")
	seedRowInAccount(t, db, "usr"+fmt.Sprintf("%017s", "r2secnd"), email, accB, "ACTIVE", "ext-r2-two")

	msg := applyMergeExpectingRefusal(t, db)
	require.Contains(t, msg, "больше одной активной строки",
		"отказ обязан назвать предмет. Получено: %s", msg)

	require.Len(t, rowsWithEmail(t, db, email), 2,
		"отказ обязан быть полным: транзакция миграции откатывается целиком")
}
