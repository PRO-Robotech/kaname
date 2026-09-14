// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_monorepo_gate_ledger.go — разбор «какие имена проб объявлены этим
// деревом».
//
// Служебная половина ведомости гейтов, снятых из монорепо выносом службы
// (kacho#2597): ведомость обязана уметь спросить дерево, резолвится ли
// названный ею держатель, — и спросить УЗЛОМ ОБЪЯВЛЕНИЯ, а не подстрокой.
//
// Разница несущая. Имя пробы встречается в этом дереве трижды помимо своего
// объявления: в прозе приёмок, в комментариях, объясняющих чем держится
// свойство, и в самой ведомости ниже. Подстрочный разбор объявил бы держателя
// живым по упоминанию о нём — то есть ведомость доказывала бы сама себя.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// DeclaredFuncCensus — объём осмотренного одним файлом.
type DeclaredFuncCensus struct {
	// Decls — объявлений функций прочитано.
	Decls int
	// Tests — из них объявлений проб (имя начинается с Test).
	Tests int
}

// ScanDeclaredFuncNames возвращает имена функций, ОБЪЯВЛЕННЫХ в файле.
//
// Объявление, а не упоминание: узел ast.FuncDecl, а не совпадение текста.
// Метод (функция с приёмником) объявлением пробы не является и в набор не
// идёт — иначе метод с именем вида TestX выдал бы себя за держателя.
func ScanDeclaredFuncNames(path string, src []byte) (map[string]bool, DeclaredFuncCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, DeclaredFuncCensus{}, err
	}
	out := map[string]bool{}
	var census DeclaredFuncCensus
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		census.Decls++
		if strings.HasPrefix(fn.Name.Name, "Test") {
			census.Tests++
		}
		out[fn.Name.Name] = true
	}
	return out, census, nil
}
