// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// identity_merge_integration_test.go — свойства ЛИЧНОСТИ, ЧЬИХ ЧЛЕНСТВ БОЛЬШЕ
// ОДНОГО (задача kacho#472, стадия S2 перехода IAM-ID-1).
//
// # Здесь стояли семь проб СВЕДЕНИЯ строк личности — предмета у них больше нет
//
// Прежняя редакция файла останавливала цепочку миграций перед переносом
// `20260822234500`, сеяла две строки на одну почту и утверждала об исходе
// переноса: права доехали со своей областью · доступ не расширился · неразрешимая
// группа отвергнута · одна и та же выдача, held дважды, сведена. Ни одного из
// условий этих проб в дереве больше нет, и не по одной причине, а по двум:
//
//  1. миграций сервиса теперь ОДНА — свод; версии, на которой можно было
//     остановиться «перед переносом», не существует;
//  2. состояние «два человека на одну почту» стало НЕПРЕДСТАВИМЫМ: глобальный
//     ключ `users_identity_email_uniq` лежит в своде и отвергает вторую строку
//     на первой же вставке. То есть Given этих проб отвергает продукт, а не
//     проба.
//
// Пробы сняты вместе со своим предметом, а не ослаблены: отказ разовой миграции,
// которой нет, — не свойство схемы, и утверждать о нём нечего. Что осталось
// НАБЛЮДАЕМЫМ и потому утверждается здесь — три свойства, каждое живёт в схеме
// независимо от того, каким путём человек получил второе членство:
//
//   - зеркало не снимает членства, которого не заводило (проба 1);
//   - цепь областей личности называет РОВНО аккаунты её членств (проба 2);
//   - осиротить право снятием строки человека не даёт страж `0050`, а не тот
//     сторож, которого называл комментарий миграции (проба 3).
//
// Приёмки, оставшиеся без держателя вместе со снятыми пробами, названы в отчёте
// линии: сценарии, описывающие поведение разовой миграции, держателя в дереве
// больше не имеют — и это остаток, а не починка.

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

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

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
	db := upAllIAMMigrations(t, dsn)
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
// Проба 2 — ЦЕПЬ ОБЛАСТЕЙ ЛИЧНОСТИ НАЗЫВАЕТ РОВНО АККАУНТЫ ЕЁ ЧЛЕНСТВ.
//
// # Предмет
//
// Цепь областей ведёт от личности к аккаунту через ЧЛЕНСТВО (944001, ветвь 4a).
// Пока членство одно, у объекта личности ровно один аккаунт-предок; со вторым
// членством предков становится два, то есть `iam_user.super_admin: admin from
// account` начинает выполняться администратором ОБОИХ аккаунтов.
//
// Это заявленное следствие, а не побочное: три поверхности дерева требуют,
// чтобы у человека со вторым членством назывались ОБА аккаунта (стадия S3,
// #471). Закрывается оно СМЕНОЙ ОБЪЕКТА — аккаунт-скоупным становится членство,
// а не личность (тип `iam_membership` в модели прав), и это отдельная стадия.
//
// # Что здесь утверждается
//
// Что множество аккаунт-предков РАВНО множеству членств — не больше (аккаунт,
// где человека нет, не появляется) и не меньше. Утверждается это в ОБЕ стороны:
// второе членство предка добавляет, снятие второго членства — убирает. Одной
// стороны мало: «предков два» зеленело бы и на цепи, которая называет всё
// подряд, и на цепи, которая ничего не забывает.
//
// # Что изменилось против прежней редакции
//
// Второе членство прежде появлялось СВЕДЕНИЕМ дублей — его больше нет (см.
// шапку файла). Умерла лестница, а не свойство: членство вставляется прямо, той
// же формой, что у пробы 1, и утверждение стало ШИРЕ — оно больше не о том, что
// делает разовая миграция, а о том, как устроена цепь у всякого человека с
// двумя членствами, каким бы путём второе ни завелось.
//
// # Почему проба ИСТЕКАЕТ САМА
//
// Её предпосылка — что типа `iam_membership` в модели ещё нет. Появится тип —
// проба покраснеет и потребует переписать себя под новый объект. Послабление,
// которое не истекает само, переживает свой предмет и начинает лгать.
func TestIntegration_TheIdentityScopeChainNamesExactlyTheAccountsOfItsMemberships(t *testing.T) {
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
			"описывает, закрыто. Перепиши пробу под новый объект: описание дыры, пережившее "+
			"дыру, лжёт")

	dsn := pgtest.NewEmptyDB(t)
	db := upAllIAMMigrations(t, dsn)
	defer func() { _ = db.Close() }()

	_, accA := seedAccountWithOwner(t, db, "scopeaaa")
	_, accB := seedAccountWithOwner(t, db, "scopebbb")
	// Третий аккаунт, где человека нет ни строкой, ни членством: положительный
	// контроль измерения. Без него «предков ровно два» зеленело бы и на цепи,
	// которая называет всё подряд.
	_, accC := seedAccountWithOwner(t, db, "scopeccc")

	person := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "aascope"), "scope@example.test", accA, "ACTIVE", "ext-scope")

	// ── «до»: одно членство — один аккаунт-предок ────────────────────────────
	require.Equal(t, []string{accA}, membershipAccountsOf(t, db, person),
		"ПРЕДПОСЫЛКА: зеркало завело членство названного аккаунта — иначе измерять нечего")
	require.Equal(t, []string{"account:" + accA}, scopeParentsOf(t, db, "iam_user", person),
		"ПРЕДПОСЫЛКА: у личности с одним членством ровно один аккаунт-предок — иначе "+
			"расширение ниже измерять не от чего")

	// ── второе членство: то, которого зеркало не заводит ни при каком входе ──
	_, err := db.Exec(`
		INSERT INTO kacho_iam.memberships (id, user_id, account_id, state)
		VALUES (kacho_iam.membership_mirror_id($1, $2), $1, $2, 'ACTIVE')`, person, accB)
	require.NoError(t, err, "посев второго членства в аккаунте %s", accB)

	after := scopeParentsOf(t, db, "iam_user", person)
	t.Logf("осмотрено: членств %d, аккаунт-предков %d — %v",
		len(membershipAccountsOf(t, db, person)), len(after), after)

	// ── расширение РАВНО объявленному ────────────────────────────────────────
	require.Equal(t, []string{"account:" + accA, "account:" + accB}, after,
		"область личности обязана называть РОВНО оба аккаунта, где у человека есть "+
			"членство, и ни одного сверх того")

	// ── и равно множеству членств: другого источника у звена нет ─────────────
	wantFromMemberships := []string{}
	for _, a := range membershipAccountsOf(t, db, person) {
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

	// ── обратная сторона: снятие членства УБИРАЕТ предка ─────────────────────
	//
	// Без неё «предков два» зеленело бы на цепи, которая предков только
	// накапливает: администратор аккаунта, из которого человека вывели, сохранял
	// бы власть над его личностью, и заметить это было бы нечем.
	_, err = db.Exec(`
		DELETE FROM kacho_iam.memberships WHERE user_id = $1 AND account_id = $2`, person, accB)
	require.NoError(t, err)
	require.Equal(t, []string{"account:" + accA}, scopeParentsOf(t, db, "iam_user", person),
		"аккаунт-предок пережил снятие членства, которым он держался: цепь предков "+
			"накапливает, а не следует членствам")
}

// ─────────────────────────────────────────────────────────────────────────────
// Проба 3 — КТО НА САМОМ ДЕЛЕ НЕ ДАЁТ ОСИРОТИТЬ ПРАВО.
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
	db := upAllIAMMigrations(t, dsn)
	defer func() { _ = db.Close() }()

	_, acc := seedAccountWithOwner(t, db, "guardaaa")
	person := seedRowInAccount(t, db,
		"usr"+fmt.Sprintf("%017s", "guardpp"), "guard@example.test", acc, "PENDING", "")
	role := anyAssignableRole(t, db)
	binding := grantOn(t, db, "acb"+fmt.Sprintf("%017s", "ggrantx"), person, role, "account", acc)

	require.Equal(t, []string{acc}, membershipAccountsOf(t, db, person),
		"ПРЕДПОСЫЛКА: зеркало завело членство — иначе снимать нечего")

	// ── форма А: снятие членства, затем строки. Говорит 0050, и НА СТЕЙТМЕНТЕ ──
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
