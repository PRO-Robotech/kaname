// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

// verb_class_branches_test.go — задача #1819: у классификатора глаголов не
// должно быть ветвей, до которых ничто не доходит, и входов, которые он не
// обслуживает.
//
// # Что здесь спрашивается — и почему НЕ то, что называла задача
//
// Задача предлагала сравнить токены классификатора с глаголами КАТАЛОГА ПРАВ.
// Это сравнение двух словарей, которые не пересекаются вовсе: у аннотаций
// третий сегмент — глагол RPC (`vpc.networks.get`), у ролей — ярус
// (`compute.disk.edit`), и шапка этого пакета называет пересечение нулём.
// Перемерено: строк аннотаций 309, строк прав ролей 85, общих — 0. Значит
// «токен без глагола каталога» ничего не сообщает о живости ветви: каталог
// этому классификатору на вход не подаётся НИКОГДА.
//
// Вход классификатора — последний сегмент строки прав РОЛИ, и его словарь
// ОТКРЫТ: ограничение таблицы принимает любой токен вида `[a-z][a-zA-Z0-9_-]*`.
// Поэтому недостижимой ветви здесь не бывает by construction, а измеримо другое
// и более полезное: КАЖДЫЙ объявленный токен обязан давать ИМЕННО тот ярус, в
// чьей ветви он записан, а неизвестный вход — наименьшее право.
//
// # Почему перечень токенов ВЫВОДИТСЯ из исходника
//
// Выписанный здесь перечень был бы вторым местом об одном предмете: токен,
// добавленный в классификатор и забытый здесь, остался бы непроверенным, а
// вердикт — зелёным. Перечень читается разбором ИСПОЛНЯЕМОЙ части: те же имена
// стоят в комментариях соседних ветвей, и проверка по тексту считала бы
// собственное объяснение.
//
// # Чего эта проба НЕ ловит — названо, а не подразумевается
//
// Ожидание выводится из ТОГО ЖЕ исходника, который проверяется, поэтому
// ПЕРЕНОС токена из ветви в ветвь она не заметит: обе стороны сравнения
// переезжают вместе. Проверено инъекцией — перенос `patch` из пишущего класса
// в административный оставил пробу зелёной. Правильность отнесения глагола к
// ярусу — предмет обзора и приёмки, здесь спрашивается другое: что объявленная
// ветвь ДОХОДИТ до входа, что класс, ею возвращаемый, отображается в ярус, и
// что неизвестный вход не получает больше наименьшего права.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// verbClassBranches читает исходник классификатора и возвращает
// токен → имя класса, в чьей ветви он записан.
func verbClassBranches(t *testing.T) map[string]string {
	t.Helper()

	const src = "permissions_to_relations.go"
	raw, err := os.ReadFile(src)
	require.NoError(t, err)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, raw, parser.SkipObjectResolution)
	require.NoError(t, err)

	out := map[string]string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "verbClass" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			// Класс ветви — идентификатор, который она возвращает.
			class := ""
			for _, stmt := range clause.Body {
				ret, ok := stmt.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				if id, ok := ret.Results[0].(*ast.Ident); ok {
					class = id.Name
				}
			}
			if class == "" {
				return true
			}
			for _, expr := range clause.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				tok, uerr := strconv.Unquote(lit.Value)
				require.NoError(t, uerr)
				out[tok] = class
			}
			return true
		})
	}
	return out
}

// relationOfClass — отношение, которое обязан дать классификатор, назвавший
// этот класс. Пара с самим классификатором: он выбирает класс, отображение
// класса в отношение делает PermissionsToRelations.
var relationOfClass = map[string]Relation{
	"classRead":  "viewer",
	"classWrite": "editor",
	"classAdmin": "admin",
}

func TestVerbClass_EveryDeclaredTokenProducesItsOwnTier(t *testing.T) {
	t.Parallel()

	branches := verbClassBranches(t)
	byClass := map[string]int{}
	for _, class := range branches {
		byClass[class]++
	}
	names := make([]string, 0, len(byClass))
	for c := range byClass {
		names = append(names, c+"="+strconv.Itoa(byClass[c]))
	}
	sort.Strings(names)
	t.Logf("перепись: токенов классификатора %d, по классам: %s",
		len(branches), strings.Join(names, ", "))

	require.NotEmpty(t, branches,
		"разбор не нашёл НИ ОДНОГО токена классификатора — он читает не то, и его ноль ничего не значит")
	require.Len(t, byClass, len(relationOfClass),
		"классов в исходнике %d, а отображение классов в отношения знает %d — одно из двух устарело: %v",
		len(byClass), len(relationOfClass), byClass)

	for tok, class := range branches {
		want, known := relationOfClass[class]
		require.True(t, known, "токен %q объявлен в неизвестном классе %s", tok, class)

		// Строка прав роли той же формы, что принимает ограничение таблицы:
		// модуль.ресурс.имя.ЯРУС.
		got := PermissionsToRelations([]string{"vpc.network.*." + tok})
		require.Equal(t, []Relation{want}, got,
			"токен %q записан в ветви %s, а даёт %v — ветвь до него не доходит либо перекрыта соседней",
			tok, class, got)
	}
}

func TestVerbClass_UnknownVerbFallsBackToLeastPrivilege(t *testing.T) {
	t.Parallel()

	branches := verbClassBranches(t)
	// Словарь последнего сегмента ОТКРЫТ ограничением таблицы, поэтому вход,
	// которого нет ни в одной ветви, — не край, а штатный случай. Токен
	// выбирается так, чтобы он заведомо не совпал ни с одной ветвью, и это
	// проверяется, а не предполагается.
	const unknown = "frobnicatetheentiretenant"
	require.NotContains(t, branches, unknown,
		"контрольный токен внезапно объявлен ветвью — проба перестала спрашивать про неизвестный вход")

	got := PermissionsToRelations([]string{"vpc.network.*." + unknown})
	require.Equal(t, []Relation{"viewer"}, got,
		"неизвестный глагол дал %v вместо наименьшего права", got)

	// Положительный контроль: та же форма строки с ИЗВЕСТНЫМ пишущим глаголом
	// даёт большее право. Без него «всегда viewer» было бы зелено и на
	// классификаторе, который не различает ничего.
	stronger := PermissionsToRelations([]string{"vpc.network.*.update"})
	require.Equal(t, []Relation{"editor"}, stronger,
		"известный пишущий глагол не дал editor (%v) — проба не отличает неизвестный вход от любого", stronger)
}
