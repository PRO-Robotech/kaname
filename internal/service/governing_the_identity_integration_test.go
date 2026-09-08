// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// governing_the_identity_integration_test.go — «распоряжаться СТРОКОЙ ЛИЧНОСТИ»
// и «распоряжаться ПРАВАМИ В СВОЁМ АККАУНТЕ» решаются РАЗНО, на той двери, куда
// приходит каждый запрос платформы (`AuthorizeService.CheckRelation` — то, что
// зовёт `InternalIAMService.Check`).
//
// # Предмет — вторая половина директивы владельца (2026-08-23)
//
// Дословно: «тот кто пригласил может только удалить/добавить права». Первая
// половина закрыта (#1086): выпуск и отзыв удостоверения отвязаны от правки
// записи. Здесь закрыта вторая: правка самой записи, запрет личности и снятие
// запрета перестают быть правом уровня аккаунта (#1102).
//
// Основание — глобальность личности: одна строка `iam_user` на все аккаунты
// человека. Значит записанное в строку действует ВЕЗДЕ, и распорядитель одного
// аккаунта, получив это право, распоряжается за границей своего.
//
// # Чем эта проба отличается от соседней в authzmap
//
// Гейт `authzmap/governing_the_identity_is_not_an_account_right_test.go` читает
// МОДЕЛЬ: он утверждает, что у отношений нет источников уровня аккаунта. Здесь то
// же свойство спрашивается ВЕРДИКТОМ по закоммиченным строкам — то есть
// проверяется не текст модели, а исход. Разъехаться они могут молча: у края своя
// композиция (ответ формы плюс плоский надзор администратора облака), и провязана
// она в композиционном корне, а не в модели. Поэтому уровень 1 утверждается
// ЗДЕСЬ, а не там.
//
// # Пара «отрицание + положительное» — обязательна, и вот почему именно эта
//
// Запрет, проверенный в одиночку, зеленеет на сломанном посеве и на сломанном
// продукте одинаково. Поэтому рядом стоит ровно то, что директива пригласившему
// ОСТАВЛЯЕТ: распоряжение выдачами своего аккаунта. Если бы правка записи
// отвалилась вместе с ним, проба покраснела бы — а не отчиталась о победе.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGoverningTheIdentityIsNotReachableFromInsideTheAccount — вердикт по
// закоммиченным строкам.
func TestGoverningTheIdentityIsNotReachableFromInsideTheAccount(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-govid1"
		owner      = "usr-govidown1"
		inviter    = "usr-govidinv1"
		invitee    = "usr-govidnew1"
		stranger   = "usr-govidstr1"
		cloudAdmin = "usr-govidcld1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, inviter, acc)
	w.seedUser(t, invitee, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, cloudAdmin, acc)

	person := "iam_user:" + invitee

	// Три пути, которыми право доходит до пригласившего, — те же, что у соседней
	// пробы, и посеяны они тем же способом, каким их производит продукт.
	//
	// Путь 1 — ВЫДАЧА внутри аккаунта, чья роль даёт чтение записи: ровно то,
	// что реконсайлер материализует на свежей строке приглашённого (invite.go
	// зовёт reconcileObject "iam.user" сразу после коммита). Прежде роль давала
	// правку; глагол снят с типа (#1128), и фикстура переведена на чтение — иначе
	// она клала бы строку проекции, которой продукт не производит.
	seedRoleGrantingUserRead(t, w, "rol-govid1", "acb-govid1", inviter, acc)
	// Путь 2 — делегированный администратор аккаунта.
	w.factThroughJournal(t, "user:"+inviter, "admin", "account", acc)
	// Путь 3 — владелец аккаунта.
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)
	// Сам человек. Кортеж пишется на заведении пользователя (internal_upsert.go).
	w.factThroughJournal(t, "user:"+invitee, "subject", "iam_user", invitee)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_root")

	// Выдача, живущая В АККАУНТЕ пригласившего, — предмет его законной власти.
	w.seedRole(t, "rol-govid2", acc)
	w.seedBinding(t, "acb-govid2", stranger, "rol-govid2", "account", acc)
	grantInAccount := "iam_access_binding:acb-govid2"

	// Гейты спрашиваются У КАТАЛОГА, а не пишутся литералом: каталог порождается
	// из proto и есть единственный источник per-RPC решения края. Литерал означал
	// бы, что проба утверждает о СВОЁМ представлении гейта, а не о действующем.
	editRel, editType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserService/Update")
	blockRel, blockType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserService/Block")
	unblockRel, unblockType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserService/Unblock")
	readRel, readType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserService/Get")
	grantRel, grantType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.AccessBindingService/Delete")
	for _, c := range []struct{ what, got string }{
		{"правка записи", editType}, {"запрет", blockType},
		{"снятие запрета", unblockType}, {"чтение записи", readType},
	} {
		require.Equalf(t, "iam_user", c.got,
			"%s гейтится не на объекте личности (%s) — предмет пробы сменился", c.what, c.got)
	}
	require.Equalf(t, "iam_access_binding", grantType,
		"снятие выдачи гейтится не на объекте выдачи (%s) — положительный контроль сменил предмет", grantType)

	// ── КОНТРОЛЬ ФИКСТУРЫ ────────────────────────────────────────────────────
	// Посев ДЕЙСТВИТЕЛЬНО живой: пригласивший держит на этой строке глагол чтения,
	// который материализует выдача. Без этого утверждения каждое отрицание ниже
	// было бы истинно и на пустой базе.
	//
	// Контроль СТОЯЛ НА `v_update` и переведён (#1128): глагол снят с типа, и
	// вопрос о нём дверь разрешить не может — она отвечает отказом, а не «нет».
	// Предмет пробы это не меняет: правку записи гейтит `record_writer`, и её
	// недостижимость изнутри аккаунта утверждается ниже, на отношении из каталога.
	require.True(t, w.allowed(t, "user:"+inviter, "v_get", person),
		"КОНТРОЛЬ: пригласивший обязан держать глагол `v_get` на строке своего члена — "+
			"иначе фикстура ничего не посеяла и все отрицания ниже вакуумны")

	// ── ОТРИЦАНИЕ — предмет пробы ────────────────────────────────────────────
	for _, c := range []struct{ who, rel, what string }{
		{inviter, editRel, "правка записи"},
		{inviter, blockRel, "запрет личности"},
		{inviter, unblockRel, "снятие запрета"},
		{owner, editRel, "правка записи"},
		{owner, blockRel, "запрет личности"},
		{owner, unblockRel, "снятие запрета"},
		{stranger, editRel, "правка записи"},
		{stranger, blockRel, "запрет личности"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+c.who, c.rel, person),
			"%s (%s) досталась держателю права ВНУТРИ аккаунта (user:%s).\n"+
				"Человек — ГЛОБАЛЬНАЯ личность: одна строка `iam_user` на все его аккаунты. "+
				"Записанное в строку — метки, решающие состав селекторных выдач, и состояние, "+
				"решающее вход на платформу, — действует во ВСЕХ его аккаунтах сразу, включая те, "+
				"к которым этот держатель отношения не имеет.\n"+
				"Директива владельца оставляет пригласившему ровно одно: удалить или добавить "+
				"права в СВОЁМ аккаунте.", c.what, c.rel, c.who)
	}

	// Сам человек тоже не распоряжается своей строкой: снять с себя запрет
	// значило бы, что запрета нет.
	require.False(t, w.allowed(t, "user:"+invitee, unblockRel, person),
		"человек снял запрет с самого себя — тогда запрет запретом не является")
	require.False(t, w.allowed(t, "user:"+invitee, editRel, person),
		"человек правит свою запись: сегодня это метки, то есть административный отбор, "+
			"по которому селекторные выдачи решают, кому он виден и над кем даёт власть — "+
			"вводить себя в них он не вправе")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: то, что директива ОСТАВЛЯЕТ ────────────────
	// Без этого утверждения запрет выше зеленел бы на дереве, где у пригласившего
	// отняли всё, — и проба отчиталась бы победой о поломке.
	require.True(t, w.allowed(t, "user:"+inviter, grantRel, grantInAccount),
		"пригласивший обязан снимать выдачи в СВОЁМ аккаунте (%s на %s): это ровно то, "+
			"что директива владельца ему оставляет, и запрет выше без этого ничего не утверждает",
		grantRel, grantInAccount)
	require.True(t, w.allowed(t, "user:"+owner, grantRel, grantInAccount),
		"владелец аккаунта обязан снимать выдачи в своём аккаунте")
	// Читать своих людей — тоже его дело, и это НЕ тронуто.
	require.True(t, w.allowed(t, "user:"+inviter, readRel, person),
		"пригласивший обязан ЧИТАТЬ запись своего члена (%s): сужение касалось распоряжения "+
			"строкой, а не видимости людей аккаунта", readRel)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: уровень 1 ──────────────────────────────────
	// Плоский надзор администратора облака — аварийный путь, ради которого каскад
	// и выбран. Без него отношения не держал бы НИКТО, и запрет выше держался бы
	// не разделением прав, а недостижимостью.
	for _, c := range []struct{ rel, what string }{
		{editRel, "правку записи"}, {blockRel, "запрет"}, {unblockRel, "снятие запрета"},
	} {
		require.Truef(t, w.allowed(t, "user:"+cloudAdmin, c.rel, person),
			"уровень 1 (администратор облака) обязан сохранить %s (%s): иначе строкой личности "+
				"не распоряжается никто, и управление ею сломано незаметно", c.what, c.rel)
	}

	t.Logf("перепись: гейт правки %s.%s · запрета %s.%s · снятия %s.%s · чтения %s.%s · "+
		"выдачи %s.%s · субъектов спрошено 5",
		editType, editRel, blockType, blockRel, unblockType, unblockRel,
		readType, readRel, grantType, grantRel)
}
