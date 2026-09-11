// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_projection_sole_writer.go — разбор операторов записи в проекции
// роли: «кто АВТОРУЕТ строку, кто её СНИМАЕТ, переселяет ли снимающий-не-автор
// снятое» (порт с монорепо `internal/repohygiene/roleverbsolewriter_test.go`,
// держатель `TestIAMRV112_RoleVerbProjectionHasASoleWriter`, снят вынесением
// службы доступа — `kacho#2597`).
//
// # Предмет
//
// Таблицы `kaname.role_verb` и `kaname.role_rule_ref` — проекции роли, то, из
// чего цепь вердикта собирает ответ «разрешено ли действие». Класс, ради
// которого гейт заведён: ДВЕ реализации знают, что такое законная строка, и
// расходятся МОЛЧА — обе компилируются, у обеих есть пробы, и различаются они
// только на входе, который ни одна проба не подаёт.
//
// # Единица — «авторует», а не «пишет» (решение kacho#1034, перенесено дословно)
//
// Что такое законная строка, объявляет ТОЛЬКО `INSERT`: он называет колонки и
// значения. `DELETE`/`UPDATE` строку не авторуют — они её снимают или правят.
// Значит класс живёт в АВТОРСТВЕ, а не в записи вообще, и единица гейта —
// функция, ВНОСЯЩАЯ строку. Снимающий не-автор обязан ПЕРЕСЕЛИТЬ снятое в
// `kaname.role_grant_orphan` ТЕМ ЖЕ оператором — иначе отобранное право
// неотличимо от никогда не выданного.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь-константа слоя (без
// префикса `services/iam/` — код лежит от корня модуля kaname), обход дерева
// (`gitenv`+`git ls-files` вручную → `github.com/PRO-Robotech/kacho/pkg/treecorpus`
// и `internal/testsupport/platformtree.RequireCorpus`, потому что предмет —
// внутри службы, дерева платформы модулю не нужно). Осталось дословно: имена
// таблиц-проекций, форма распознавателя (узел-литерал разобранного AST, а не
// текст файла), три оси проверки (авторство · переселение · слой) и имя
// держателя `TestIAMRV112_RoleVerbProjectionHasASoleWriter` — на нём стоят
// цитаты `docs/engineering/acceptance/role-verb-projection-sole-writer.md`,
// `rule-segments-have-a-referent.md` и `module-manifest-roles-and-seed-grants.md`,
// написанные ДО выноса, когда `internal/repohygiene` был тем же репозиторием.
//
// # Граница названа, а не умолчана
//
// Гейт читает СТРОКОВЫЕ ЛИТЕРАЛЫ непроверочного кода Go, разобранного в дерево,
// и приписывает находку объемлющей функции. Он НЕ видит: SQL миграций (там
// запись законна — миграция и есть схема), проб (им положено готовить
// состояние), имя таблицы, собранное из кусков (слепая зона, предикатом по
// подстроке не ловится ничем).
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// RoleVerbTable — проекция «роль → тип объекта × глагол».
const RoleVerbTable = "kaname.role_verb"

// RoleRuleRefTable — вторая проекция того же объявления: каждый объявленный
// сегмент правила (kacho#1030). Предмет у таблиц разный, а требование к
// автору — одно.
const RoleRuleRefTable = "kaname.role_rule_ref"

// RoleGrantOrphanTable — куда обязано переселяться снятое не-автором.
const RoleGrantOrphanTable = "kaname.role_grant_orphan"

// RoleProjectionTables — таблицы, у каждой из которых автор обязан быть один.
var RoleProjectionTables = []string{RoleVerbTable, RoleRuleRefTable}

// RoleVerbWriterLayer — слой, которому принадлежит SQL проекции. Писатель вне
// него — находка, даже если он один.
const RoleVerbWriterLayer = "/internal/repo/"

// AuthorVerbOf — оператор, которым строка ВНОСИТСЯ.
func AuthorVerbOf(table string) string { return "INSERT INTO " + table }

// RemovalVerbsOf — операторы, которыми строка СНИМАЕТСЯ либо правится.
//
// Чтение (`SELECT … FROM`, `JOIN`) в перечень не входит намеренно: читатели у
// проекции законны и служат близнецом, на котором гейт молчит.
func RemovalVerbsOf(table string) []string {
	return []string{"DELETE FROM " + table, "UPDATE " + table}
}

// RoleProjectionOp — один найденный оператор над проекцией.
type RoleProjectionOp struct {
	// Func — объемлющая функция; пустое имя означает пакетный уровень.
	Func string
	// Verb — какой оператор найден.
	Verb string
	// Authors — оператор ВНОСИТ строку.
	Authors bool
	// Relocates — ТОТ ЖЕ литерал переселяет снятое в RoleGrantOrphanTable.
	//
	// Признак читается по литералу, а не по функции: переселение и снятие
	// обязаны быть неделимы, а неделимы они ровно тогда, когда стоят в одном
	// операторе.
	Relocates bool
}

// RoleVerbWritesIn — совместимая обёртка для инъекции по первой проекции.
func RoleVerbWritesIn(filename, src string) ([]RoleProjectionOp, int, error) {
	return RoleProjectionWritesIn(filename, src, RoleVerbTable)
}

// RoleProjectionWritesIn разбирает исходник Go и возвращает операторы над
// таблицей проекции, приписанные объемлющей функции, плюс число строковых
// литералов, называющих таблицу вообще (перепись предпосылки: читатели тоже
// считаются).
//
// Признак судит УЗЕЛ-ЛИТЕРАЛ разобранного дерева, а не текст файла: имя
// таблицы встречается и в комментариях — в том числе в комментариях,
// объясняющих эту самую проверку, — и гейт по подстроке краснел бы на
// собственном объяснении.
func RoleProjectionWritesIn(filename, src, table string) ([]RoleProjectionOp, int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, 0, err
	}

	type span struct {
		from, to token.Pos
		name     string
	}
	var spans []span
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = roleProjectionTypeName(fn.Recv.List[0].Type) + "." + name
		}
		spans = append(spans, span{from: fn.Body.Pos(), to: fn.Body.End(), name: name})
	}

	var (
		ops      []RoleProjectionOp
		mentions int
	)
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if !strings.Contains(lit.Value, table) {
			return true
		}
		mentions++
		upper := strings.ToUpper(lit.Value)
		owner := ""
		for _, s := range spans {
			if lit.Pos() >= s.from && lit.End() <= s.to {
				owner = s.name
				break
			}
		}
		relocates := strings.Contains(upper, strings.ToUpper("INSERT INTO "+RoleGrantOrphanTable))

		if author := AuthorVerbOf(table); strings.Contains(upper, strings.ToUpper(author)) {
			ops = append(ops, RoleProjectionOp{Func: owner, Verb: author, Authors: true, Relocates: relocates})
		}
		for _, verb := range RemovalVerbsOf(table) {
			if strings.Contains(upper, strings.ToUpper(verb)) {
				ops = append(ops, RoleProjectionOp{Func: owner, Verb: verb, Relocates: relocates})
			}
		}
		return true
	})
	return ops, mentions, nil
}

// roleProjectionTypeName — имя типа получателя метода, для приписки функции.
func roleProjectionTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return roleProjectionTypeName(t.X)
	default:
		return ""
	}
}
