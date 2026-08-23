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
	"testing"

	"github.com/stretchr/testify/require"
)

// seedRoleGrantingUserDelete — роль, дающая СНЯТИЕ ЛИЧНОСТИ, и выдача её субъекту
// на весь аккаунт: тот самый путь, которым пообъектный доступ приезжает
// пригласившему.
//
// Отличается от соседней `seedRoleGrantingUserEdit` одним глаголом, и различие
// несущее: контроль фикстуры ниже спрашивает именно `v_delete`, а роль правки
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
