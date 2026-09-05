// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// projection_scan_arity_test.go — каждая каноническая проекция колонок читается
// РОВНО СТОЛЬКИМИ приёмниками, сколько в ней колонок.
//
// ПРЕДМЕТ. Порядок колонок ресурса записан в двух местах: в проекции
// (`<res>Cols`, уезжающей в SELECT/RETURNING) и в списке назначений `row.Scan`.
// Компилятор их не связывает: расхождение выражается ТОЛЬКО отказом живой
// Postgres на пути чтения — «number of field descriptions must equal number of
// destinations». То есть колонка, добавленная в проекцию и не добавленная в
// приёмники, ломает свой путь чтения ЦЕЛИКОМ и молчит до первого стенда.
//
// Наблюдалось (#1943/#1940): `owner_module` приехал в `roleCols` вместе со своей
// миграцией, `scanRole` назначение под него завёл, а `scanRoleWithVersion` —
// нет. `RoleService.Update` читает роль через `GetWithVersion`, поэтому правка
// ЛЮБОЙ роли отвечала арендатору фиксированным `INTERNAL`, из которого следующий
// шаг не восстановим.
//
// ЧЕМ ЭТА ПРОБА НЕ ЯВЛЯЕТСЯ. Она не сверяет ПОРЯДОК и не сверяет ТИПЫ — только
// арность. Порядок и типы держит делегирование: у одной проекции один список
// назначений, и второго места, которое могло бы с ним разойтись, больше нет.
// Арность — остаточная ось: единственный список всё ещё способен отстать от
// самой проекции, и ровно это здесь и произошло.
//
// Проба НЕ требует Postgres: приёмник считает длину списка и обрывает чтение
// сигнальной ошибкой, поэтому она исполняется и под `-short`.
package pg

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// errArityProbe обрывает чтение сразу после захвата длины: тело сканера за
// row.Scan нас не касается, а его исполнение на пустых значениях внесло бы в
// пробу отказы, к её предмету не относящиеся.
var errArityProbe = errors.New("arity probe: destinations counted")

// destCounter — приёмник, считающий назначения. Удовлетворяет и локальному
// `scanner`, и `pgx.Row`: у обоих ровно этот метод.
type destCounter struct{ n int }

func (d *destCounter) Scan(dest ...any) error {
	d.n = len(dest)
	return errArityProbe
}

// countProjectionColumns считает колонки верхнего уровня. Запятая ВНУТРИ
// скобок разделителем не является: `abCols` несёт `COALESCE(role_id, ”)`, и
// наивное деление по запятой насчитало бы там лишнюю колонку — то есть проба
// судила бы эталонную пару виновной.
func countProjectionColumns(cols string) int {
	depth, n := 0, 1
	for _, r := range cols {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}

// TestProjectionColumnCounterKnowsParentheses — проверка ПРЕДПОСЫЛКИ самой пробы.
// Считалка колонок — её измерительный прибор; ошибись он, и таблица ниже
// зеленела бы или краснела не по делу, оставаясь на вид работающей.
func TestProjectionColumnCounterKnowsParentheses(t *testing.T) {
	require.Equal(t, 1, countProjectionColumns("id"))
	require.Equal(t, 3, countProjectionColumns("id, name, created_at"))
	// Запятая внутри скобок — не разделитель.
	require.Equal(t, 2, countProjectionColumns("id, COALESCE(role_id, '') AS role_id"))
	require.Equal(t, 1, countProjectionColumns("COALESCE(a, b, c)"))
	// Живая проекция со скобками — восемнадцать колонок, а не девятнадцать.
	require.Equal(t, 18, countProjectionColumns(abCols),
		"abCols: считалка обязана пропустить запятую внутри COALESCE")
}

// TestProjectionScanArityMatchesItsColumns — несущее утверждение.
func TestProjectionScanArityMatchesItsColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		// extra — приёмники СВЕРХ проекции: OCC-токен, признак вставки. Число
		// стоит здесь явно, потому что оно часть контракта запроса: запрос,
		// дописывающий колонку к проекции, обязан объявить её и тут.
		extra int
		scan  func(*destCounter)
	}{
		{"roleCols/scanRole", roleCols, 0,
			func(d *destCounter) { _, _ = scanRole(d) }},
		{"roleCols/scanRoleWithVersion", roleCols, 1,
			func(d *destCounter) { var v string; _, _ = scanRoleWithVersion(d, &v) }},

		{"userCols/scanUser", userCols, 0,
			func(d *destCounter) { _, _ = scanUser(d) }},
		{"userCols/scanUserWithCreated", userCols, 1,
			func(d *destCounter) {
				var u domain.User
				var created bool
				_ = scanUserWithCreated(d, &u, &created)
			}},
		{"userCols/scanUserWithInserted", userCols, 1,
			func(d *destCounter) {
				var u domain.User
				var inserted bool
				_ = scanUserWithInserted(d, &u, &inserted)
			}},

		{"userPoolCols/scanUserFromRow", userPoolCols, 0,
			func(d *destCounter) { _, _ = scanUserFromRow(d) }},

		// Эталонная пара — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. `scanAB` делегирует
		// `scanABWithVersion`, список назначений один. Она обязана молчать; если
		// покраснеет и она, значит негодна проба, а не дерево.
		{"abCols/scanAB", abCols, 0,
			func(d *destCounter) { _, _ = scanAB(d) }},
		{"abCols/scanABWithVersion", abCols, 1,
			func(d *destCounter) { var v string; _, _ = scanABWithVersion(d, &v) }},

		{"accountCols/scanAccount", accountCols, 0,
			func(d *destCounter) { _, _ = scanAccount(d) }},
		{"projectCols/scanProject", projectCols, 0,
			func(d *destCounter) { _, _ = scanProject(d) }},
		{"saCols/scanSA", saCols, 0,
			func(d *destCounter) { _, _ = scanSA(d) }},
		{"groupCols/scanGroup", groupCols, 0,
			func(d *destCounter) { _, _ = scanGroup(d) }},
		{"recoveryCols/scanRecoveryCompletionWithInserted", recoveryCols, 1,
			func(d *destCounter) {
				var rc domain.RecoveryCompletion
				var inserted bool
				_ = scanRecoveryCompletionWithInserted(d, &rc, &inserted)
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEmpty(t, tc.cols, "проекция пуста — сверять не с чем")
			want := countProjectionColumns(tc.cols) + tc.extra

			d := &destCounter{}
			tc.scan(d)

			require.NotZero(t, d.n,
				"сканер не позвал Scan — проба ничего не измерила")
			require.Equalf(t, want, d.n,
				"проекция несёт %d колонок (+%d сверх неё), а сканер объявляет %d приёмников: "+
					"колонка добавлена в проекцию и не добавлена в приёмники — "+
					"этот путь чтения отказывает на КАЖДОЙ строке",
				countProjectionColumns(tc.cols), tc.extra, d.n)
		})
	}

	// Объём осмотренного: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного». Пустая таблица прошла бы молча и выглядела бы исправной.
	t.Logf("перепись: проекций-сканеров осмотрено %d", len(cases))
	require.GreaterOrEqual(t, len(cases), 13,
		"таблица усохла: сканер выпал из-под наблюдения вместе со своей проекцией")
}
