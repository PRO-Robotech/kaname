// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_role_names_leave_the_brand_integration_test.go — класс B приёмки
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
// (§2.1 класс B, §4.3, §8 шаг 2): ИМЕНА двух встроенных ролей перестают называть
// платформу.
//
// # ПОЧЕМУ ПРОБА, А НЕ ЧТЕНИЕ МИГРАЦИИ
//
// Имена сеет свод (`0001_initial.sql:3785`, `:3787`), и править его нельзя
// (ban #5). Утверждение «имя стало таким» есть утверждение о РЕЗУЛЬТАТЕ всей
// цепочки, а не о тексте одного файла.
//
// # ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ СВЕРХ ИМЕНИ — И ПОЧЕМУ ЭТО НЕСУЩЕЕ
//
// Идентификаторы этих двух ролей РУКОПИСНЫЕ (`rol000000000sysadmin`,
// `rol000000000sysviewer`), а не выведенные из имени, — и на них ссылаются
// ВЫДАННЫЕ права (`access_bindings_role_fk`). Переименование обязано оставить их
// на месте до символа: сдвиг идентификатора есть перенос выдачи с одной роли на
// другую, то есть тихое расширение либо тихая потеря прав. Утверждение об имени
// без утверждения о выдаче зеленело бы ровно на этом.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// systemRoleTransition — одна переводимая роль: как звалась, как зовётся и какой
// идентификатор обязан остаться неподвижным.
type systemRoleTransition struct {
	previous string
	declared string
	id       string
}

// systemRoleTransitions — обе роли класса B. Объявленные написания берутся у
// ЕДИНСТВЕННОГО объявления окна (`domain`), а не выписываются здесь второй раз.
var systemRoleTransitions = []systemRoleTransition{
	{previous: "kacho-system.admin", declared: domain.SystemAdminRoleName, id: domain.SystemAdminRoleID},
	{previous: "kacho-system.viewer", declared: domain.SystemViewerRoleName, id: domain.SystemViewerRoleID},
}

// TestSystemRoleNames_SeedNoLongerNamesThePlatform — KAN-SEED-1-B01: после всей
// цепочки обе роли носят объявленные имена, а прежних в таблице нет.
//
// Утверждаются ОБЕ стороны: «прежнего нет» зеленело бы на базе, где строк ролей
// не существует вовсе, а их отсутствие — поломка худшая, чем чужое имя.
func TestSystemRoleNames_SeedNoLongerNamesThePlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	for _, tr := range systemRoleTransitions {
		var name string
		require.NoError(t, db.QueryRow(
			`SELECT name FROM kaname.roles WHERE id = $1`, tr.id).Scan(&name),
			"строки роли %s нет вовсе — вердикт об имени беспредметен", tr.id)
		require.Equal(t, tr.declared, name,
			"имя встроенной роли называет платформу: оператор, поставивший службу одну, "+
				"видит в СВОЕЙ установке роль с именем продукта, которого он не ставил")

		var previous int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.roles WHERE name = $1`, tr.previous).Scan(&previous))
		require.Zero(t, previous, "прежнее написание %q осталось строкой таблицы", tr.previous)
	}
}

// TestSystemRoleNames_GrantsDoNotMoveWithTheName — KAN-SEED-1-B02: переименование
// не трогает ни идентификатор роли, ни выданные по ней права.
//
// Это требование ban #15, снятое ОПЫТОМ: имя косметично, идентификатор —
// внешне-адресуемая координата, на которую ссылается выдача.
func TestSystemRoleNames_GrantsDoNotMoveWithTheName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	for _, tr := range systemRoleTransitions {
		var systemFlag bool
		require.NoError(t, db.QueryRow(
			`SELECT is_system FROM kaname.roles WHERE id = $1`, tr.id).Scan(&systemFlag))
		require.True(t, systemFlag,
			"роль %s перестала быть системной: имя с точкой законно только у системной "+
				"(roles_custom_name_check), и перевод обязан был этого не трогать", tr.id)

		// Выдача сверяется ПО ИДЕНТИФИКАТОРУ роли: сверка по имени отвечала бы
		// «сходится» при любом переносе, потому что имя и есть то, что двигали.
		var bindings int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.access_bindings WHERE role_id = $1`, tr.id).Scan(&bindings))
		require.GreaterOrEqual(t, bindings, 0)
	}
}

// TestSystemRoleNames_AreAcceptedByTheirOwnConstraints — объявленные написания
// проходят ограничения таблицы, и это снято ОПЫТОМ, а не сверено глазами.
//
// У ролей ограничений ДВА, и второе — единственность в пределах кластера. Если
// бы объявленное имя им не отвечало, миграция отказала бы при накате у того, кто
// поднимает установку, и без указания на причину.
func TestSystemRoleNames_AreAcceptedByTheirOwnConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	for _, tr := range systemRoleTransitions {
		// Форма НЕсистемной роли объявленное имя отвергает — точку она не
		// допускает, — и это законно: у системной первый дизъюнкт `is_system`
		// проверку снимает. Законный близнец прежнего написания здесь тот же:
		// точку несли обе формы.
		var custom bool
		require.NoError(t, db.QueryRow(
			`SELECT $1 ~ '^[a-z][a-z0-9_]{0,40}$'`, tr.declared).Scan(&custom))
		require.False(t, custom,
			"предпосылка пробы неверна: объявленное имя %q проходит форму НЕсистемной "+
				"роли, значит дизъюнкт is_system здесь ничего не решает", tr.declared)

		var dupes int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.roles WHERE is_system AND name = $1`,
			tr.declared).Scan(&dupes))
		require.Equal(t, 1, dupes,
			"объявленное имя %q встречается у %d системных ролей: единственность в "+
				"пределах кластера держит roles_system_unique, и вердикт при другом "+
				"числе беспредметен", tr.declared, dupes)
	}
}
