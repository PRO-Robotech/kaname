// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// removing_the_identity_integration_test.go — «СТЕРЕТЬ СТРОКУ ЛИЧНОСТИ» и
// «распоряжаться СВОИМ аккаунтом» решаются РАЗНО, на той двери, куда приходит
// каждый запрос платформы (`AuthorizeService.CheckRelation` — то, что зовёт
// `InternalIAMService.Check`).
//
// # Предмет — тот же класс, что #1102, с более тяжёлым исходом (#1131)
//
// Строка `iam_user` — ГЛОБАЛЬНАЯ личность: одна на все аккаунты человека
// (миграции 20260822234500 / 20260823050000). Значит удаление её из аккаунта A
// стирает человека и в аккаунте B — он теряет личность целиком, а не участие в
// одном тенанте. Запрет обратим, удаление нет, поэтому ошибка в сторону широты
// здесь дороже.
//
// # Чем эта проба отличается от соседней в authzmap
//
// Гейт `authzmap/removing_the_identity_is_not_an_account_right_test.go` читает
// МОДЕЛЬ: он утверждает, что у отношения нет источников уровня аккаунта. Здесь то
// же свойство спрашивается ВЕРДИКТОМ по закоммиченным строкам — то есть
// проверяется не текст модели, а исход. Разъехаться они могут молча: у края своя
// композиция (ответ формы плюс плоский надзор администратора облака), провязанная
// в композиционном корне, а не в модели.
//
// # Пара «отрицание + положительное» — обязательна, и вот почему именно эта
//
// Запрет, проверенный в одиночку, зеленеет на сломанном посеве и на сломанном
// продукте одинаково. Поэтому рядом стоят ОБА исхода, которые сужение обязано
// сохранить, — самоудаление и надзор облака, — и то, что директива оставляет
// пригласившему: распоряжение выдачами своего аккаунта.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// seedRoleGrantingUserDelete — роль, дающая СНЯТИЕ ЛИЧНОСТИ, и выдача её субъекту
// на весь аккаунт: тот самый путь, которым пообъектный доступ приезжает
// пригласившему.
//
// Отличается от соседней `seedRoleGrantingUserRead` одним глаголом, и различие
// несущее: контроль фикстуры ниже спрашивает именно `v_delete`, а роль чтения
// его не даёт. Фикстура, кладущая не тот глагол, доказывала бы запрет на пустоте.
func seedRoleGrantingUserDelete(t *testing.T, w *ciWorld, roleID, bindingID, subjectID, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
	           VALUES ($1, 'test.userdelete', '[]'::jsonb,
	                   jsonb_build_array(jsonb_build_object(
	                       'module', 'iam', 'resources', jsonb_build_array('user'),
	                       'verbs',  jsonb_build_array('delete'))),
	                   'cluster_kacho_root')`, roleID)
	w.exec(t, `INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
	           VALUES ($1, 'iam.user', 'delete')`, roleID)
	w.exec(t, `INSERT INTO kacho_iam.role_rule_selectors
	             (role_id, rule_fp, arm, object_types, match_labels)
	           VALUES ($1, 'fp-rmid', 'anchor', ARRAY['iam.user'::text], '{}'::jsonb)`, roleID)
	w.exec(t, `INSERT INTO kacho_iam.access_bindings
	             (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	           VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, subjectID, roleID, accountID)
	w.exec(t, `INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
	           VALUES ($1, 'user', $2)`, bindingID, subjectID)
}

// TestRemovingTheIdentityIsNotReachableFromInsideTheAccount — вердикт по
// закоммиченным строкам.
func TestRemovingTheIdentityIsNotReachableFromInsideTheAccount(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-rmid1"
		owner      = "usr-rmidown1"
		inviter    = "usr-rmidinv1"
		invitee    = "usr-rmidnew1"
		stranger   = "usr-rmidstr1"
		cloudAdmin = "usr-rmidcld1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, inviter, acc)
	w.seedUser(t, invitee, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, cloudAdmin, acc)

	person := "iam_user:" + invitee

	// Три пути, которыми право доходит до пригласившего, посеяны тем же способом,
	// каким их производит продукт.
	seedRoleGrantingUserDelete(t, w, "rol-rmid1", "acb-rmid1", inviter, acc)
	w.factThroughJournal(t, "user:"+inviter, "admin", "account", acc)
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)
	// Сам человек. Кортеж пишется на заведении пользователя (internal_upsert.go).
	w.factThroughJournal(t, "user:"+invitee, "subject", "iam_user", invitee)
	// Указатель принадлежности — им цепь областей доводит аккаунт до личности.
	w.factThroughJournal(t, "account:"+acc, "account", "iam_user", invitee)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_kacho_root")

	// Выдача, живущая В АККАУНТЕ пригласившего, — предмет его законной власти.
	w.seedRole(t, "rol-rmid2", acc)
	w.seedBinding(t, "acb-rmid2", stranger, "rol-rmid2", "account", acc)
	grantInAccount := "iam_access_binding:acb-rmid2"

	// Гейты спрашиваются У КАТАЛОГА, а не пишутся литералом: каталог порождается
	// из proto и есть единственный источник per-RPC решения края.
	removeRel, removeType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserService/Delete")
	readRel, readType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserService/Get")
	grantRel, grantType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.AccessBindingService/Delete")
	require.Equalf(t, "iam_user", removeType,
		"снятие личности гейтится не на объекте личности (%s) — предмет пробы сменился", removeType)
	require.Equalf(t, "iam_user", readType,
		"чтение записи гейтится не на объекте личности (%s) — контроль сменил предмет", readType)
	require.Equalf(t, "iam_access_binding", grantType,
		"снятие выдачи гейтится не на объекте выдачи (%s) — контроль сменил предмет", grantType)

	// ── КОНТРОЛЬ ФИКСТУРЫ ────────────────────────────────────────────────────
	// Посев ДЕЙСТВИТЕЛЬНО живой: пригласивший держит на этой строке глагол
	// снятия, который материализует выдача. Без этого утверждения каждое
	// отрицание ниже было бы истинно и на пустой базе.
	require.True(t, w.allowed(t, "user:"+inviter, "v_delete", person),
		"КОНТРОЛЬ: пригласивший обязан держать глагол `v_delete` на строке своего члена — "+
			"иначе фикстура ничего не посеяла и все отрицания ниже вакуумны")

	// ── ОТРИЦАНИЕ — предмет пробы ────────────────────────────────────────────
	for _, c := range []struct{ who, what string }{
		{inviter, "пригласивший (пообъектная выдача + делегированный администратор)"},
		{owner, "владелец аккаунта"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+c.who, removeRel, person),
			"%s стирает СТРОКУ ЛИЧНОСТИ своего члена (%s на %s).\n"+
				"Строка `iam_user` глобальна — одна на все аккаунты человека, — поэтому её "+
				"снятие из этого аккаунта стирает человека и во всех остальных: он теряет "+
				"личность целиком, а не участие в одном тенанте. Директива владельца "+
				"оставляет распорядителю аккаунта права и состав участников; для второго есть "+
				"исключение из аккаунта (#1127), а не удаление личности.", c.what, removeRel, person)
	}

	// ── ПОЛОЖИТЕЛЬНОЕ 1 — самоудаление осталось ──────────────────────────────
	require.True(t, w.allowed(t, "user:"+invitee, removeRel, person),
		"САМ ЧЕЛОВЕК не может удалить свою же строку. Самоудаление разрешено всегда и было "+
			"разрешено до этого сужения (`api/user/delete.go`) — значит сужение отняло больше, "+
			"чем собиралось")

	// ── ПОЛОЖИТЕЛЬНОЕ 2 — надзор облака остался ──────────────────────────────
	require.True(t, w.allowed(t, "user:"+cloudAdmin, removeRel, person),
		"администратор облака не может удалить чужую строку личности. Тогда запрет выше "+
			"держится не разделением прав, а недостижимостью отношения, и управление личностью "+
			"сломано незаметно")

	// ── ПОЛОЖИТЕЛЬНОЕ 3 — что директива аккаунту ОСТАВЛЯЕТ ───────────────────
	require.True(t, w.allowed(t, "user:"+inviter, readRel, person),
		"пригласивший перестал ВИДЕТЬ своего человека — сужение задело чтение записи, "+
			"которое остаётся правом аккаунта намеренно")
	require.True(t, w.allowed(t, "user:"+inviter, grantRel, grantInAccount),
		"пригласивший перестал распоряжаться ВЫДАЧАМИ своего аккаунта — это ровно то, что "+
			"директива ему оставляет, и если бы оно отвалилось вместе с запретом, проба обязана "+
			"была покраснеть, а не отчитаться о победе")

	// ── ОТРИЦАНИЕ 2 — посторонний по-прежнему не может ───────────────────────
	require.False(t, w.allowed(t, "user:"+stranger, removeRel, person),
		"посторонний член аккаунта стирает чужую строку личности")

	t.Logf("перепись: гейт снятия личности %s.%s · гейт чтения записи %s.%s · "+
		"гейт снятия выдачи %s.%s · субъектов проверено 5",
		removeType, removeRel, readType, readRel, grantType, grantRel)
}

// TestRemovingAnIdentityWithNoAccountScopeReachesOnlyTheCloud — ОСИРОТЕВШАЯ
// строка личности: у неё нет области, из которой кто-нибудь мог бы до неё
// дотянуться.
//
// # Как такая строка возникает — производственным путём, а не выдумкой посева
//
// Исключение из аккаунта (#1127) снимает строку членства и указатель области, не
// трогая саму личность. Звено цепи `iam_user → account` берётся ИМЕННО из
// членства (миграция 944001), поэтому после исключения последнего членства у
// личности не остаётся предка-аккаунта вовсе. Легаси-колонка `users.account_id`
// при этом сохраняется — миграция #1127 её намеренно не трогает, — поэтому
// посев кладёт человека обычным способом (внешний ключ обязывает) и снимает
// членство ровно тем же оператором, каким его снимает продукт.
//
// # Зачем отдельная проба (#1174)
//
// Соседняя выше меряет строку, у которой предок-аккаунт ЕСТЬ: там
// `super_admin from account` разворачивается по звену цепи. Здесь звена нет, и в
// плане модели у отношения остаётся ровно один источник — `subject`, то есть сам
// человек. Вопрос, ради которого проба и написана: доходит ли до такой строки
// НАДЗОР ОБЛАКА.
//
// Ответ решает не план, а дверь: плоское короткое замыкание администратора
// облака живёт в службе (`AuthorizeService`), а не в модели, и утверждать про
// него можно только ИСХОДОМ. Именно это утверждение опровергала самодельная
// проверка в `api/user/delete.go`: край пропускал надзор облака, а сервис
// отвечал отказом — осиротевшая личность оказывалась неудаляемой никем, тогда
// как человек, потерявший доступ, себя уже не удалит.
//
// # Пара обязательна
//
// Отрицание «посторонний не может» на пустом посеве истинно даром. Поэтому рядом
// стоят оба исхода, которые снятие проверки обязано было сохранить: сам человек
// проходит, посторонний — нет.
func TestRemovingAnIdentityWithNoAccountScopeReachesOnlyTheCloud(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-orph1"
		owner      = "usr-orphown1"
		stranger   = "usr-orphstr1"
		cloudAdmin = "usr-orphcld1"
		orphan     = "usr-orphan1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, cloudAdmin, acc)
	w.seedUser(t, orphan, acc)

	person := "iam_user:" + orphan
	// Кортеж «сам человек» пишется на заведении пользователя (internal_upsert.go)
	// и исключением из аккаунта не снимается — он про личность, а не про участие.
	w.factThroughJournal(t, "user:"+orphan, "subject", "iam_user", orphan)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_kacho_root")

	// Исключение из аккаунта: ровно тот оператор, каким его делает продукт
	// (`RemoveMembership`). Указателя области в журнале эта личность не получала
	// вовсе, поэтому снимать нечего — и это утверждается ниже, а не подразумевается.
	w.exec(t, `DELETE FROM kacho_iam.memberships WHERE user_id = $1`, orphan)

	removeRel, removeType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserService/Delete")
	require.Equalf(t, "iam_user", removeType,
		"снятие личности гейтится не на объекте личности (%s) — предмет пробы сменился", removeType)

	// ── ПРЕДПОСЫЛКА: предка-аккаунта у строки ДЕЙСТВИТЕЛЬНО нет ──────────────
	// Без этого утверждения проба могла бы мерить строку со звеном цепи, и
	// «надзор облака дошёл» ничего не говорило бы о замыкании: его дал бы обычный
	// разворот `super_admin from account`.
	var parents int
	require.NoError(t, w.pool.QueryRow(context.Background(),
		`SELECT count(*)::int FROM kacho_iam.resource_scope_edge
		  WHERE object_type = 'iam_user' AND object_id = $1 AND parent_type = 'account'`,
		orphan).Scan(&parents))
	require.Zerof(t, parents,
		"у строки %s осталось %d звеньев цепи к аккаунту — она не осиротевшая, и проба "+
			"меряет не тот предмет", orphan, parents)

	// Контроль предпосылки в обратную сторону: у СОСЕДНЕЙ строки того же посева
	// звено есть. Иначе «ноль звеньев» означало бы, что представление вообще
	// ничего не отдаёт, и предпосылка была бы выполнена на сломанном посеве.
	var neighbourParents int
	require.NoError(t, w.pool.QueryRow(context.Background(),
		`SELECT count(*)::int FROM kacho_iam.resource_scope_edge
		  WHERE object_type = 'iam_user' AND object_id = $1 AND parent_type = 'account'`,
		stranger).Scan(&neighbourParents))
	require.Positivef(t, neighbourParents,
		"у СОСЕДНЕЙ строки %s тоже нет звена к аккаунту — цепь областей не отдаёт ничего, "+
			"и предпосылка выше выполнена на сломанном посеве", stranger)

	// ── ПОЛОЖИТЕЛЬНОЕ 1 — сам человек проходит ──────────────────────────────
	require.True(t, w.allowed(t, "user:"+orphan, removeRel, person),
		"САМ ЧЕЛОВЕК не может снять свою же осиротевшую строку — тогда фикстура ничего не "+
			"посеяла, и отрицание ниже вакуумно")

	// ── ПОЛОЖИТЕЛЬНОЕ 2 — надзор облака доходит (предмет #1174) ─────────────
	require.True(t, w.allowed(t, "user:"+cloudAdmin, removeRel, person),
		"администратор облака не может снять ОСИРОТЕВШУЮ строку личности. Тогда её не может "+
			"снять НИКТО, кроме неё самой, — а человек, потерявший доступ, себя не удалит. "+
			"Плоское короткое замыкание уровня 1 живёт в службе, а не в плане модели, поэтому "+
			"его исчезновение видно только отсюда")

	// ── ОТРИЦАНИЕ — граница, которую снятие внутрисервисной проверки обязано
	// было сохранить ─────────────────────────────────────────────────────────
	for _, c := range []struct{ who, what string }{
		{stranger, "посторонний член прежнего аккаунта"},
		{owner, "владелец прежнего аккаунта"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+c.who, removeRel, person),
			"%s снимает ОСИРОТЕВШУЮ строку личности (%s на %s). У такой строки цепь областей "+
				"не даёт предка-аккаунта: дотянуться до неё из аккаунта нельзя ни выдачей, ни "+
				"ярусом — и снятие внутрисервисной проверки (#1174) этого не меняло",
			c.what, removeRel, person)
	}

	t.Logf("перепись: гейт снятия личности %s.%s · звеньев к аккаунту у осиротевшей строки %d, "+
		"у соседней %d · субъектов проверено 4",
		removeType, removeRel, parents, neighbourParents)
}
