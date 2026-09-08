// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// system_role_action_injection_test.go — доказательство того, что гейт
// `TestSystemRolePermissionActionExistsInTheCatalog` СПОСОБЕН упасть, и притом
// падает ровно на предмете (задача продукта #1827).
//
// Инъекция ведётся по СИНТЕТИЧЕСКОМУ своду, а не по дереву: фикстура, привязанная
// к живой строке каталога миграций, истекла бы вместе с ней — ровно тогда, когда
// предмет починен, то есть в момент, когда доказательство нужнее всего
// (`testing.md` §«Чтение вердикта» п. 5).
//
// Осей четыре, и по каждой утверждаются ОБЕ стороны:
//
//	  1. негодное действие  → находка, называющая роль и строку;
//	     законный близнец   → молчание;
//	  2. незнакомая форма   → находка, называющая файл;
//	     знакомая форма     → молчание;
//	  3. свод по цепочке    → побеждает ПОСЛЕДНЕЕ присвоение, и в обе стороны:
//	     негодное → годное  → молчание (так и приземляется починка),
//	     годное  → негодное → находка, отнесённая к ПОЗДНЕМУ файлу;
//	  4. пустой обход       → своду нечего судить, и гейт обязан отказать, а не
//	     объявить «находок ноль».

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// catalogActionsFixture — словарь действий фикстуры. Живой каталог здесь не
// читается намеренно: инъекция обязана ронять ТОЛЬКО проверяемое, а сегодняшний
// состав каталога — соседний предмет.
var catalogActionsFixture = map[string]bool{"get": true, "list": true, "delete": true}

const (
	insertBad = `INSERT INTO kaname.roles (id, name, permissions) VALUES ` +
		`('rol0000000000000bad', 'vpc.network.view', '["vpc.network.*.read"]')`
	insertGood = `INSERT INTO kaname.roles (id, name, permissions) VALUES ` +
		`('rol0000000000000bad', 'vpc.network.view', '["vpc.network.*.get"]')`
	updateGood = `UPDATE kaname.roles SET permissions = '["vpc.network.*.get"]'::jsonb ` +
		`WHERE id = 'rol0000000000000bad'`
	updateBad = `UPDATE kaname.roles SET permissions = '["vpc.network.*.read"]'::jsonb ` +
		`WHERE id = 'rol0000000000000bad'`
	updateUnknownForm = `UPDATE kaname.roles SET permissions = permissions - 'vpc.network.*.read' ` +
		`WHERE id = 'rol0000000000000bad'`
	// Объявление таблицы называет и таблицу, и столбец — и присвоением НЕ является.
	// Без этой стороны находка формы зеленела бы на любом DDL.
	createTable = `CREATE TABLE kaname.roles (id text NOT NULL, permissions jsonb NOT NULL)`
)

func judge(t *testing.T, files ...[2]string) (findings, unknown []string, roles int) {
	t.Helper()
	ordered := make([]string, 0, len(files))
	bodies := map[string]string{}
	for _, f := range files {
		ordered = append(ordered, f[0])
		bodies[f[0]] = f[1] + ";"
	}
	state, unknownForms, _ := foldRolePermissions(ordered, bodies)
	return actionFindings(state, catalogActionsFixture), unknownForms, len(state)
}

func TestGateFindsAnActionOutsideTheCatalog(t *testing.T) {
	findings, unknown, roles := judge(t, [2]string{"0001_initial.sql", insertBad})
	require.Empty(t, unknown)
	require.Equal(t, 1, roles)
	require.Len(t, findings, 1, "негодное действие обязано быть находкой")
	require.Contains(t, findings[0], "rol0000000000000bad", "находка обязана назвать роль")
	require.Contains(t, findings[0], "vpc.network.*.read", "находка обязана назвать строку прав")
	require.Contains(t, findings[0], "0001_initial.sql", "находка обязана назвать файл")
}

func TestGateIsSilentOnTheLegitimateTwin(t *testing.T) {
	findings, unknown, roles := judge(t, [2]string{"0001_initial.sql", insertGood})
	require.Empty(t, unknown)
	require.Equal(t, 1, roles, "законная вставка обязана попасть в свод, а не быть пропущенной")
	require.Empty(t, findings, "действие каталога находкой быть не может")
}

func TestGateNamesAFormItDoesNotKnow(t *testing.T) {
	_, unknown, _ := judge(t, [2]string{"20260101000000_x.sql", updateUnknownForm})
	require.Len(t, unknown, 1, "форма, которой разбор не знает, обязана быть находкой, а не молчанием")
	require.Contains(t, unknown[0], "20260101000000_x.sql")

	// Обратная сторона: знакомая форма и объявление таблицы находкой не являются.
	_, unknownKnown, _ := judge(t, [2]string{"20260101000000_x.sql", updateGood})
	require.Empty(t, unknownKnown)
	_, unknownDDL, roles := judge(t, [2]string{"0001_initial.sql", createTable})
	require.Empty(t, unknownDDL, "объявление таблицы присвоением не является")
	require.Zero(t, roles)
}

func TestGateJudgesTheLastAssignmentOfTheChain(t *testing.T) {
	// Так приземляется починка: базовая миграция неизменна, негодное снимает поздняя.
	findings, unknown, roles := judge(t,
		[2]string{"0001_initial.sql", insertBad},
		[2]string{"20260101000000_fix.sql", updateGood},
	)
	require.Empty(t, unknown)
	require.Equal(t, 1, roles)
	require.Empty(t, findings, "позднее годное присвоение обязано перебивать раннее негодное")

	// И вторая сторона: свод не «побеждает годное», он побеждает ПОСЛЕДНЕЕ.
	back, unknownBack, _ := judge(t,
		[2]string{"0001_initial.sql", insertGood},
		[2]string{"20260101000000_regress.sql", updateBad},
	)
	require.Empty(t, unknownBack)
	require.Len(t, back, 1)
	require.Contains(t, back[0], "20260101000000_regress.sql",
		"находка обязана быть отнесена к ПОЗДНЕМУ файлу, иначе чинили бы не тот")
}

func TestGateRefusesAnEmptySweep(t *testing.T) {
	state, unknown, stmts := foldRolePermissions(nil, map[string]string{})
	require.Empty(t, state)
	require.Empty(t, unknown)
	require.Zero(t, stmts)
	require.Empty(t, actionFindings(state, catalogActionsFixture),
		"на пустом своде судья находок не даёт — поэтому «ноль находок» обязан "+
			"отсекаться предпосылкой гейта, а не читаться как зелёное")

	// Та же сторона на непустом корпусе БЕЗ присвоений: файл прочитан, свод пуст.
	_, _, roles := judge(t, [2]string{"0001_initial.sql", createTable})
	require.Zero(t, roles, "предпосылка гейта (`NotZero(len(state))`) обязана отказать здесь")
	require.True(t, strings.HasPrefix(createTable, "CREATE"))
}

func TestGateJudgesOnlyTheForwardHalfOfAMigration(t *testing.T) {
	// Обратный ход миграции ВОЗВРАЩАЕТ снятое — иначе он не откат. Читая файл
	// целиком, свод взял бы это возвращение как последнее присвоение и объявил
	// бы починку несостоявшейся.
	forward := "-- +goose Up\n" + updateGood + ";\n-- +goose Down\n" + updateBad
	findings, unknown, roles := judge(t, [2]string{"20260101000000_fix.sql", forward})
	require.Empty(t, unknown)
	require.Equal(t, 1, roles)
	require.Empty(t, findings, "негодное присвоение обратного хода судиться не должно")

	// Обратная сторона: без разделителя судится ВСЁ — то есть разрез отсекает
	// именно обратный ход, а не «всё, что после первого оператора».
	flat, _, _ := judge(t, [2]string{"20260101000000_fix.sql", updateGood + ";\n" + updateBad})
	require.Len(t, flat, 1, "без разделителя goose позднее присвоение обязано судиться")
}
