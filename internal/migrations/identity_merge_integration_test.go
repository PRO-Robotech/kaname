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
//
// # Что леджером НЕ исчерпывается — три оси, заведённые по найденным слепотам
//
// Леджер выдач — не всё, чем сведение может расширить доступ, и каждая из осей
// ниже заведена не из полноты, а по опыту:
//
//   - КЛАСТЕРНАЯ выдача живёт своей таблицей, которой запрос по леджеру не
//     касается вовсе, — а миграция её переставляет. Ярус верхний, ошибка
//     необратима (проба 3, ось 3);
//   - ЦЕПЬ ОБЛАСТЕЙ отвечает на другой вопрос — «через какой аккаунт до личности
//     достаёт администратор», — и сведение её РАСШИРЯЕТ. Это заявленное
//     следствие, а не побочное; проба 6 требует, чтобы расширение было РОВНО
//     объявленным, и истекает сама, когда объект аккаунт-скоупа переедет на
//     членство;
//   - ГРАНИЦА СТРАЖЕЙ: что именно не даёт снять строку человека, пока право на
//     неё живо. Проба 9 закрепляет настоящего держателя — комментарий миграции
//     называл не того, и такой комментарий приглашает переставить стейтменты.

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// seedProject заводит проект в уже существующем аккаунте. Он нужен как объект,
// на который у человека нет прав НИ ОДНОЙ строкой: аккаунт для этого не годится
// — обе сводимые строки держат выдачи именно на аккаунты.
func seedProject(t *testing.T, db *sql.DB, id, accountID, name string) string {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $3)`,
		id, accountID, name)
	require.NoError(t, err, "посев проекта %s в аккаунте %s", id, accountID)
	return id
}

// theCluster — единственный кластер дерева (`clusters_id_singleton_ck`).
func theCluster(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRow(`SELECT id FROM kacho_iam.clusters ORDER BY id LIMIT 1`).Scan(&id))
	require.NotEmpty(t, id, "ПРЕДПОСЫЛКА: кластер сеется 0001 — без него ось кластерной выдачи беспредметна")
	return id
}

// grantClusterAdmin кладёт кластерную выдачу на названную строку человека.
// Внешнего ключа на `users` у таблицы нет, поэтому состояние конструируется и
// для строки-дубля — именно это и делает ось измеримой.
func grantClusterAdmin(t *testing.T, db *sql.DB, grantID, subjectUserID string) string {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kacho_iam.cluster_admin_grants (id, cluster_id, subject_type, subject_id, granted_by)
		VALUES ($1, $2, 'user', $3, 'system:test')`,
		grantID, theCluster(t, db), subjectUserID)
	require.NoError(t, err, "посев кластерной выдачи %s", grantID)
	return grantID
}

// liveGrantPredicate — «названная строка человека является субъектом ЖИВОЙ
// выдачи», в обеих проекциях субъекта. Один текст на все три способа ключевать,
// чтобы способы различались только ключом, а не отбором.
const liveGrantPredicate = `
		 WHERE b.status = 'ACTIVE'
		   AND (
		         (b.subject_type = 'user' AND b.subject_id = $1)
		      OR EXISTS (SELECT 1 FROM kacho_iam.access_binding_subjects s
		                  WHERE s.binding_id = b.id
		                    AND s.subject_type = 'user' AND s.subject_id = $1)
		       )
		 ORDER BY 1`

func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// grantHandlesOf — те же живые выдачи, но ключом служит САМА ВЫДАЧА (её
// идентификатор), а не её область.
//
// Почему области НЕДОСТАТОЧНО — измерено, а не предположено. Область
// схлопывает разные выдачи в один элемент: украденная у постороннего выдача на
// `account:accB` даёт элемент, который в множестве «после» УЖЕ есть — законно,
// от собственной выдачи дубля. Отрицание тогда молчит на настоящей краже: проба
// с внесённым переносом чужой выдачи оставалась зелёной, а снимки «до»/«после»
// совпадали до символа. Идентификатор выдачи переезд субъекта не меняет,
// поэтому множество, ключёванное им, сравнимо поэлементно и кражу называет.
func grantHandlesOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	return queryStrings(t, db, `
		SELECT DISTINCT b.id || ' на ' || b.resource_type || ':' || b.resource_id ||
		                ' ролью ' || b.role_id
		  FROM kacho_iam.access_bindings b`+liveGrantPredicate, userID)
}

// clusterGrantHandlesOf — кластерные выдачи названной строки. Отдельная ось:
// `grantScopesOf` этой таблицы не читает ВОВСЕ, а переезд по ней меняет верхний
// ярус супер-доступа, где ошибка необратима.
func clusterGrantHandlesOf(t *testing.T, db *sql.DB, userID string) []string {
	t.Helper()
	return queryStrings(t, db, `
		SELECT g.id || ' на cluster:' || g.cluster_id
		  FROM kacho_iam.cluster_admin_grants g
		 WHERE g.subject_type = 'user' AND g.subject_id = $1
		 ORDER BY 1`, userID)
}

// scopeParentsOf — аккаунт-предки объекта в цепи областей: то, через что до
// объекта достаёт администратор (`iam_user.super_admin: admin from account`).
func scopeParentsOf(t *testing.T, db *sql.DB, objectType, objectID string) []string {
	t.Helper()
	return queryStrings(t, db, `
		SELECT DISTINCT e.parent_type || ':' || e.parent_id
		  FROM kacho_iam.resource_scope_edge e
		 WHERE e.object_type = $1 AND e.object_id = $2
		 ORDER BY 1`, objectType, objectID)
}

// canonicalModelText — канонический текст модели прав. Читается файлом, а не
// пересказывается: предмет проб ниже — что в нём есть и чего в нём нет.
func canonicalModelText(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..",
		"proto", "kacho", "cloud", "iam", "v1", "fga_model.fga")
	b, err := os.ReadFile(path)
	require.NoError(t, err,
		"ПРЕДПОСЫЛКА: канонический текст модели прав обязан читаться — его отсутствие "+
			"есть ровно тот дефект, ради которого проба стоит, и молчать о нём нельзя")
	return string(b)
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
//
// # ТРИ ОСИ, И НИ ОДНА НЕ ЛИШНЯЯ — каждая заведена по СЛЕПОТЕ, найденной опытом
//
//  1. ВЫДАЧА как ключ, а не её область. Область схлопывает разные выдачи в один
//     элемент: `DISTINCT <тип>:<id>` не отличает право дубля на `account:B` от
//     украденного права постороннего на тот же `account:B`. Проба с внесённым
//     переносом чужой выдачи оставалась ЗЕЛЁНОЙ, а снимки «до» и «после»
//     совпадали до символа. Ключ-идентификатор выдачи это различает.
//  2. ЧУЖОЙ ОБЪЕКТ, которого нет ни у одной из сводимых строк, — проект внутри
//     второго аккаунта. Прежний «посторонний объект» был выдачей на ТОТ ЖЕ
//     аккаунт, что и законная выдача дубля, то есть посторонним не был.
//  3. КЛАСТЕРНАЯ ВЫДАЧА. `grantScopesOf` этой таблицы не читает вовсе, а
//     миграция её переставляет. Ярус верхний, ошибка необратима — ось обязана
//     быть измеряемой, а не подразумеваемой.
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

	// Третье лицо на ТОЙ ЖЕ области, что и законная выдача дубля. По области
	// неотличимо от доехавшего — ловится только ключом выдачи (ось 1).
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "wgrantf"), ownerB, role, "account", accB)

	// Третье лицо на объекте, которого у человека нет НИ ОДНОЙ строкой (ось 2).
	prjB := seedProject(t, db, "prj"+fmt.Sprintf("%017s", "widenprj"), accB, "widen-foreign-project")
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "wgrantp"), ownerB, role, "project", prjB)

	// Кластерная ось (3): у дубля выдача есть, у канонической строки — нет,
	// у третьего лица — своя.
	cagDup := grantClusterAdmin(t, db, "cag_"+fmt.Sprintf("%017s", "dpgrant"), duplicate)
	cagOwn := grantClusterAdmin(t, db, "cag_"+fmt.Sprintf("%017s", "wnrgrant"), ownerB)
	require.NotEqual(t, cagDup, cagOwn, "ПРЕДПОСЫЛКА: кластерные выдачи различимы")

	// ── снимок «до», по трём осям ────────────────────────────────────────────
	beforeScopes := unionSorted(grantScopesOf(t, db, canonical), grantScopesOf(t, db, duplicate))
	beforeHandles := unionSorted(grantHandlesOf(t, db, canonical), grantHandlesOf(t, db, duplicate))
	beforeCluster := unionSorted(clusterGrantHandlesOf(t, db, canonical), clusterGrantHandlesOf(t, db, duplicate))
	t.Logf("снимок «до»: области %v · выдачи %v · кластерные выдачи %v",
		beforeScopes, beforeHandles, beforeCluster)

	require.NotEmpty(t, beforeScopes,
		"ПРЕДПОСЫЛКА: множество «до» не пусто — на пустом отрицание истинно тождественно")
	require.Len(t, beforeHandles, 2,
		"ПРЕДПОСЫЛКА: у сводимых строк ровно две выдачи — иначе ключ выдачи ничего не различает")
	require.Len(t, beforeCluster, 1,
		"ПРЕДПОСЫЛКА: кластерная выдача есть ровно у дубля — иначе ось 3 беспредметна")

	// Чужое «до» — то, чего перенос не вправе коснуться.
	foreignHandles := grantHandlesOf(t, db, ownerB)
	require.Len(t, foreignHandles, 2,
		"ПРЕДПОСЫЛКА: у третьего лица две выдачи — на общей с дублем области и на чужом объекте")

	require.NoError(t, goose.UpTo(db, ".", identityMergeVersion))

	afterScopes := grantScopesOf(t, db, canonical)
	afterHandles := grantHandlesOf(t, db, canonical)
	afterCluster := clusterGrantHandlesOf(t, db, canonical)
	t.Logf("снимок «после»: области %v · выдачи %v · кластерные выдачи %v",
		afterScopes, afterHandles, afterCluster)

	// ── ни одной лишней ВЫДАЧИ (ось 1 и 2, IAM-ID-1-30) ──────────────────────
	require.Empty(t, subtract(afterHandles, beforeHandles),
		"перенос назвал выжившую строку субъектом выдачи, которой не держала ни одна из "+
			"сведённых строк: право обязано оставаться у того, кому выдано")

	// ── и ни одной потерянной (IAM-ID-1-29) ──────────────────────────────────
	require.Empty(t, subtract(beforeHandles, afterHandles),
		"перенос потерял выдачу: множества обязаны совпадать элемент в элемент")

	// ── то же по областям: грубее ключом, зато ближе к тому, что видит человек ─
	require.Empty(t, subtract(afterScopes, beforeScopes),
		"перенос выдал доступ на область, которой не было ни у одной из сведённых строк")
	require.Empty(t, subtract(beforeScopes, afterScopes),
		"перенос потерял область")

	// ── кластерная ось (3) ───────────────────────────────────────────────────
	require.Equal(t, beforeCluster, afterCluster,
		"кластерная выдача обязана ПЕРЕЕХАТЬ и не размножиться: право остаётся у того же "+
			"человека, а чужая кластерная выдача переносом не затрагивается")
	require.Empty(t, clusterGrantHandlesOf(t, db, duplicate),
		"кластерная выдача снятой строки обязана уехать с неё, иначе она висит без субъекта")

	// ── третье лицо не тронуто ───────────────────────────────────────────────
	require.Equal(t, foreignHandles, grantHandlesOf(t, db, ownerB),
		"перенос тронул выдачи третьего лица")
	require.Equal(t, []string{cagOwn + " на cluster:" + theCluster(t, db)},
		clusterGrantHandlesOf(t, db, ownerB),
		"перенос тронул кластерную выдачу третьего лица")

	// ── положительные контроли сравнения ─────────────────────────────────────
	// Утверждения выше молчат и когда расхождения нет, и когда сравнение само
	// сломано. Контроль подаёт то самое, что проба обязана поймать — чужой
	// элемент, пришедший в множество «после», — и требует, чтобы ТО ЖЕ сравнение
	// его нашло. По каждой оси отдельно: сломаться они могут порознь.
	require.NotEmpty(t, subtract(withExtra(afterHandles, foreignHandles[0]), beforeHandles),
		"сравнение выдач обязано НАХОДИТЬ пришедшую чужую выдачу: молчание здесь означало "+
			"бы, что обе пустоты по этой оси не доказывали ничего")
	require.NotEmpty(t, subtract(withExtra(afterScopes, "project:"+prjB), beforeScopes),
		"сравнение областей обязано НАХОДИТЬ пришедшую чужую область")
	require.NotEmpty(t,
		subtract(withExtra(afterCluster, cagOwn+" на cluster:"+theCluster(t, db)), beforeCluster),
		"сравнение кластерных выдач обязано НАХОДИТЬ пришедшую чужую кластерную выдачу")
}

// withExtra — множество плюс один элемент. Нужен положительным контролям:
// сравнение обязано НАЙТИ чужой элемент, а не только смолчать на его отсутствии.
func withExtra(set []string, extra string) []string {
	return append(append([]string{}, set...), extra)
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
// Пробы 4, 5 и 8 — ОТКАЗ умеет сработать.
//
// Миграция объявляет ТРИ группы неразрешимыми и роняет прогон, называя число.
// Объявленный, но ни разу не проверенный отказ — форма без содержания: он
// выглядит защитой и молчит ровно тогда, когда обязан заговорить. Здесь он
// ставится в условия, где обязан сработать, и рядом — положительный контроль:
// на разрешимых данных та же миграция проходит (его несут пробы 2, 3 и 7).
//
// Третья группа (выдача-дубль, названная субъектом постороннего) проверяется
// пробой 8 — она стоит рядом со своей разрешимой сестрой, пробой 7, чтобы
// граница между «решается само» и «решает владелец продукта» читалась парой.

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

// addSubjectTo — второй субъект той же выдачи. Множественная проекция принимает
// нескольких грантополучателей, и каждый из них — САМОСТОЯТЕЛЬНЫЙ адресат права
// (0050). Именно поэтому выдачу, среди субъектов которой есть посторонний,
// сведение гасить не вправе.
func addSubjectTo(t *testing.T, db *sql.DB, bindingID, subjectUserID string, ordinal int) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'user', $2, $3)`, bindingID, subjectUserID, ordinal)
	require.NoError(t, err, "посев второго субъекта выдачи %s", bindingID)
}

// liveBindingsOnKey — живые выдачи с названным ключом живой выдачи: роль,
// область, слепок цели. Ключ тот же, каким их различает частичный уникальный
// индекс `access_bindings_active_grant_uniq`.
func liveBindingsOnKey(t *testing.T, db *sql.DB, roleID, resType, resID string) []string {
	t.Helper()
	return queryStrings(t, db, `
		SELECT b.id || ' субъект ' || b.subject_id
		  FROM kacho_iam.access_bindings b
		 WHERE b.revoked_at IS NULL
		   AND b.role_id = $1 AND b.resource_type = $2 AND b.resource_id = $3
		 ORDER BY 1`, roleID, resType, resID)
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 6 — ОКНО, КОТОРОЕ СВЕДЕНИЕ ОТКРЫВАЕТ, РАВНО ОБЪЯВЛЕННОМУ.
//
// # Предмет
//
// Цепь областей ведёт от личности к аккаунту через ЧЛЕНСТВО (944001, ветвь 4a).
// Пока членство одно, у объекта личности ровно один аккаунт-предок. Сведение
// даёт человеку второе членство — и предков становится два, то есть
// `iam_user.super_admin: admin from account` начинает выполняться
// администратором ОБОИХ аккаунтов.
//
// Это следствие ЗАЯВЛЕНО в шапке миграции (§«ОКНО, КОТОРОЕ ЭТА МИГРАЦИЯ
// ОТКРЫВАЕТ») и не является побочным: три поверхности дерева уже требуют, чтобы
// у человека со вторым членством назывались ОБА аккаунта (стадия S3, #471).
// Закрывается оно СМЕНОЙ ОБЪЕКТА — аккаунт-скоупным становится членство, а не
// личность (тип `iam_membership` в модели прав), и это отдельная стадия.
//
// # Что здесь утверждается
//
// Что расширение РОВНО такое, как объявлено, и ни на элемент шире: множество
// аккаунт-предков выжившей строки после сведения равно множеству её членств —
// не больше (аккаунт, где человека нет, не появляется) и не меньше.
//
// # Почему проба ИСТЕКАЕТ САМА
//
// Её предпосылка — что типа `iam_membership` в модели ещё нет. Появится тип —
// проба покраснеет и потребует переписать себя под новый объект. Послабление,
// которое не истекает само, переживает свой предмет и начинает лгать.
func TestIntegration_MergeWidensTheIdentityScopeExactlyAsDeclared(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	// Предикат читает ОБЪЯВЛЕНИЕ типа, а не слово: упоминание `iam_membership` в
	// комментарии модели объектом аккаунт-скоупа его не делает, и краснеть на нём
	// значило бы объявить окно закрытым по чужой прозе.
	declarations := 0
	for _, line := range strings.Split(canonicalModelText(t), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "type iam_membership") {
			declarations++
		}
	}
	require.Equal(t, 0, declarations,
		"ПРЕДПОСЫЛКА ИСТЕКЛА: модель прав объявила тип `iam_membership` — значит объект "+
			"аккаунт-скоупа переехал с личности на членство, и окно, которое эта проба "+
			"описывает, закрыто. Перепиши пробу под новый объект и сними объявление окна "+
			"из шапки миграции: описание дыры, пережившее дыру, лжёт")

	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "scopeaaa")
	_, accB := seedAccountWithOwner(t, db, "scopebbb")
	// Третий аккаунт, где человека нет ни строкой, ни членством: положительный
	// контроль измерения. Без него «предков ровно два» зеленело бы и на цепи,
	// которая называет всё подряд.
	_, accC := seedAccountWithOwner(t, db, "scopeccc")

	const email = "scope@example.test"
	canonical := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aascope"), email, accA, "ACTIVE", "ext-scope")
	duplicate := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zzscope"), email, accB, "PENDING", "")

	role := anyAssignableRole(t, db)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "sgranta"), canonical, role, "account", accA)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "sgrantb"), duplicate, role, "account", accB)

	// ── «до»: у каждой строки ровно один аккаунт-предок ──────────────────────
	require.Equal(t, []string{"account:" + accA}, scopeParentsOf(t, db, "iam_user", canonical),
		"ПРЕДПОСЫЛКА: до сведения у живой личности ровно один аккаунт-предок — иначе "+
			"измерять расширение не от чего")
	require.Equal(t, []string{"account:" + accB}, scopeParentsOf(t, db, "iam_user", duplicate),
		"ПРЕДПОСЫЛКА: до сведения второй аккаунт достаёт до строки-приглашения, а не до "+
			"живой личности — в этом и состоит разница, которую сведение снимает")

	require.NoError(t, goose.UpTo(db, ".", identityMergeVersion))

	after := scopeParentsOf(t, db, "iam_user", canonical)
	t.Logf("аккаунт-предки выжившей личности после сведения: %v", after)

	// ── расширение РАВНО объявленному ────────────────────────────────────────
	require.Equal(t, []string{"account:" + accA, "account:" + accB}, after,
		"расширение области личности обязано быть РОВНО объявленным: оба аккаунта, где у "+
			"человека есть членство, и ни одного сверх того")

	// ── и равно множеству членств: другого источника у звена нет ─────────────
	wantFromMemberships := []string{}
	for _, a := range membershipAccountsOf(t, db, canonical) {
		wantFromMemberships = append(wantFromMemberships, "account:"+a)
	}
	sort.Strings(wantFromMemberships)
	require.Equal(t, wantFromMemberships, after,
		"аккаунт-предки личности обязаны совпадать с её членствами: расхождение означало "+
			"бы, что у звена завёлся второй источник")

	// ── положительный контроль измерения ─────────────────────────────────────
	require.NotContains(t, after, "account:"+accC,
		"измерение обязано РАЗЛИЧАТЬ аккаунты: если бы цепь называла и тот аккаунт, где "+
			"человека нет, равенство выше не доказывало бы ничего")

	require.Empty(t, scopeParentsOf(t, db, "iam_user", duplicate),
		"у снятой строки не может остаться аккаунт-предка: объекта больше нет")
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 7 — ОДНО И ТО ЖЕ ПРАВО ДВАЖДЫ: сведение разрешает эту форму САМО.
//
// Каноническая строка и дубль держат ЖИВУЮ выдачу одной роли на один объект:
// приглашение выдало право пер-аккаунтной строке, администратор выдал то же
// право активной напрямую. Переставить субъект обеих нельзя — частичный ключ
// `access_bindings_active_grant_uniq` допускает ровно одну живую.
//
// До правки эта форма падала СЫРЫМ 23505: goose ронял накат, сервис не
// поднимался, а оператор читал сообщение Postgres вместо предмета. Миграция при
// этом обещала, что неразрешимых форм ДВЕ и обе названы числом, — то есть
// обещание было неполным на третью.
func TestIntegration_MergeResolvesTheSameGrantHeldTwice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "twiceaaa")
	_, accB := seedAccountWithOwner(t, db, "twicebbb")

	const email = "twice@example.test"
	canonical := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aatwice"), email, accA, "ACTIVE", "ext-twice")
	duplicate := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zztwice"), email, accB, "PENDING", "")

	role := anyAssignableRole(t, db)
	// ДВА НАБОРА ПРАВ на один и тот же объект — ровно то, чем задача называет
	// предмет: право выдано и пер-аккаунтной строке, и активной напрямую.
	byInvite := grantOn(t, db, "acb"+fmt.Sprintf("%017s", "tgrantd"), duplicate, role, "account", accB)
	direct := grantOn(t, db, "acb"+fmt.Sprintf("%017s", "tgrantc"), canonical, role, "account", accB)

	require.Len(t, liveBindingsOnKey(t, db, role, "account", accB), 2,
		"ПРЕДПОСЫЛКА: живых выдач с одним ключом ровно две — на одной форма не воспроизводится")

	before := grantScopesOf(t, db, canonical)

	require.NoError(t, goose.UpTo(db, ".", identityMergeVersion),
		"третья форма обязана иметь НАЗВАННЫЙ исход: сырой 23505 из-под ключа не даёт "+
			"оператору ни предмета, ни следующего шага")

	// ── право осталось, и ровно одно ─────────────────────────────────────────
	require.Equal(t, []string{"account:" + accB}, before,
		"ПРЕДПОСЫЛКА: до сведения право у канонической строки уже было")
	require.Equal(t, []string{"account:" + accB}, grantScopesOf(t, db, canonical),
		"право обязано остаться тем же: гашение дубля не отнимает доступ, потому что то "+
			"же право у человека уже есть другой выдачей")

	require.Equal(t, []string{direct + " субъект " + canonical},
		liveBindingsOnKey(t, db, role, "account", accB),
		"живой обязана остаться выдача КАНОНИЧЕСКОЙ строки: порядок выбора тотальный, "+
			"поэтому два прогона на одинаковых данных гасят одно и то же")

	// ── погашено ОТЗЫВОМ, а не удалением: цепочка аудита переживает сведение ─
	var status, revokedBy string
	require.NoError(t, db.QueryRow(`
		SELECT status, coalesce(revoked_by_user_id, '') FROM kacho_iam.access_bindings WHERE id = $1`,
		byInvite).Scan(&status, &revokedBy))
	require.Equal(t, "REVOKED", status,
		"выдача-дубль обязана остаться строкой: удаление стёрло бы след того, что право выдавали")
	require.Equal(t, "system:identity-merge", revokedBy,
		"отзыв обязан назвать себя: иначе в аудите он неотличим от отзыва администратором")

	// ── и ни одной ссылки на снятую строку ───────────────────────────────────
	require.Empty(t, danglingSubjectRefs(t, db, duplicate),
		"в леджере остались ссылки на снятую строку")
	require.Equal(t, []string{canonical}, rowsWithEmail(t, db, email),
		"сведение обязано состояться: отказ здесь означал бы, что форма объявлена "+
			"неразрешимой, хотя ответ у неё есть")
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 8 — ОТКАЗ на выдаче-дубле, названной субъектом ПОСТОРОННЕГО.
//
// Гашение дубля законно ровно потому, что то же право у того же человека
// остаётся другой выдачей. Если у выдачи есть второй субъект, гашение отнимает
// право у него — а оставить её живой нельзя из-за ключа. Ответа, который
// миграция могла бы вычислить, нет: какая из двух одинаковых выдач остаётся
// жить, решает владелец продукта.
func TestIntegration_MergeRefusesAGroupItCannotDecide_SharedDuplicateGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion-1)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "sharedaa")
	ownerB, accB := seedAccountWithOwner(t, db, "sharedbb")

	const email = "shared@example.test"
	canonical := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aashare"), email, accA, "ACTIVE", "ext-share")
	duplicate := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "zzshare"), email, accB, "PENDING", "")

	role := anyAssignableRole(t, db)
	byInvite := grantOn(t, db, "acb"+fmt.Sprintf("%017s", "hgrantd"), duplicate, role, "account", accB)
	grantOn(t, db, "acb"+fmt.Sprintf("%017s", "hgrantc"), canonical, role, "account", accB)
	// Посторонний — второй адресат ТОЙ ЖЕ выдачи.
	addSubjectTo(t, db, byInvite, ownerB, 1)

	msg := applyMergeExpectingRefusal(t, db)
	require.Contains(t, msg, "названы субъектом не только сводимой личности",
		"отказ обязан НАЗЫВАТЬ предмет: «миграция упала» без предмета не даёт оператору "+
			"ни одного следующего шага. Получено: %s", msg)

	require.Len(t, rowsWithEmail(t, db, email), 2,
		"отказ обязан быть полным: транзакция миграции откатывается целиком")
	require.Len(t, liveBindingsOnKey(t, db, role, "account", accB), 2,
		"отказавшая миграция не гасит ничего: половина работы хуже её отсутствия")
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 9 — КТО НА САМОМ ДЕЛЕ НЕ ДАЁТ ОСИРОТИТЬ ПРАВО.
//
// # Предмет: комментарий про безопасность, который был ложен
//
// Миграция объясняла порядок своих стейтментов так: «членства снимаются ДО
// строки, здесь сторож 472002 спрашивает». Сторож 472002 — отложенный
// constraint-триггер на снятии членства; он ДЕЙСТВИТЕЛЬНО умеет говорить, но не
// в этой форме: он спрашивает на COMMIT, а к COMMIT строки человека уже нет, и
// срабатывает его собственное короткое замыкание. Порядок стейтментов ему
// безразличен — перестановка не роняет ничего.
//
// Комментарий, называющий не того сторожа, приглашает следующего переставить
// стейтменты «раз тот всё равно поймает». Поэтому здесь закрепляется НАСТОЯЩИЙ
// держатель — страж 0050 `principal_not_referenced_as_subject`, — и рядом
// показывается, что 472002 при этом ЖИВ, а не сломан.
func TestIntegration_TheGuardAgainstOrphanedGrantsIsTheSubjectRef(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, identityMergeVersion)
	defer func() { _ = db.Close() }()

	_, acc := seedAccountWithOwner(t, db, "guardaaa")
	person := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "guardpp"), "guard@example.test", acc, "PENDING", "")
	role := anyAssignableRole(t, db)
	binding := grantOn(t, db, "acb"+fmt.Sprintf("%017s", "ggrantx"), person, role, "account", acc)

	require.Equal(t, []string{acc}, membershipAccountsOf(t, db, person),
		"ПРЕДПОСЫЛКА: зеркало завело членство — иначе снимать нечего")

	// ── форма А: порядок миграции. Говорит 0050, и говорит НА СТЕЙТМЕНТЕ ─────
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `DELETE FROM kacho_iam.memberships WHERE user_id = $1`, person)
	require.NoError(t, err, "снятие членства само по себе не отвергается")
	_, err = tx.ExecContext(ctx, `DELETE FROM kacho_iam.users WHERE id = $1`, person)
	require.Error(t, err,
		"снятие строки человека, названной субъектом выдачи, обязано быть отвергнуто: "+
			"иначе право осталось бы без субъекта — выглядит выданным и не действует ни для кого")
	require.Contains(t, err.Error(), "is referenced by an access binding subject",
		"отвергает страж 0050, и он называет предмет. Получено: %s", err)
	require.NoError(t, tx.Rollback())

	// ── форма Б: 472002 ЖИВ — он говорит, пока строка человека остаётся ──────
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `DELETE FROM kacho_iam.memberships WHERE user_id = $1`, person)
	require.NoError(t, err)
	err = tx.Commit()
	require.Error(t, err,
		"сторож 472002 обязан говорить на СВОЕЙ форме: членство, на которое опирается живая "+
			"выдача, снять нельзя. Молчание здесь означало бы, что форма А ничего не доказала — "+
			"мы бы не знали, жив ли он вообще")
	require.Contains(t, err.Error(), "still carries active access bindings",
		"сторож 472002 обязан называть предмет. Получено: %s", err)

	// ── форма В: 472002 МОЛЧИТ, когда строки человека к COMMIT уже нет ───────
	// Именно это и делает миграция, поэтому её порядок стейтментов держится НЕ
	// им. Строим состояние, где 0050 промолчать обязан (субъектной строки нет),
	// и смотрим, поймает ли 472002 осиротевшую легаси-проекцию.
	_, err = db.ExecContext(ctx, `
		DELETE FROM kacho_iam.access_binding_subjects WHERE binding_id = $1`, binding)
	require.NoError(t, err)

	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `DELETE FROM kacho_iam.memberships WHERE user_id = $1`, person)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `DELETE FROM kacho_iam.users WHERE id = $1`, person)
	require.NoError(t, err, "субъектной строки больше нет — 0050 молчит по построению")
	require.NoError(t, tx.Commit(),
		"сторож 472002 на этой форме МОЛЧИТ: к COMMIT строки человека нет, и он коротко "+
			"замыкается. Значит порядок стейтментов миграции держится не им — держит его "+
			"страж 0050 (форма А)")

	var orphaned int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kacho_iam.access_bindings
		 WHERE status = 'ACTIVE' AND subject_type = 'user' AND subject_id = $1`, person).Scan(&orphaned))
	require.Equal(t, 1, orphaned,
		"легаси-проекция осталась указывать на снятую строку, и ни один сторож этого не "+
			"отверг — поэтому миграция считает висячие ссылки САМА и роняет прогон на "+
			"ненулевом числе. Это утверждение о границе стражей, а не о дефекте продукта")

}
