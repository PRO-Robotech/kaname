// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_stamp_word.go — разбор объявления строковой константы синтаксическим
// деревом, а не текстом.
//
// # Предмет
//
// Слово «сборка штамп не проставила» стоит в прозе (шапках, документации) не
// реже, чем в объявлении. Поиск по подстроке нашёл бы собственное объяснение и
// остался бы зелёным при разошедшихся объявлениях — узел объявления константы
// судится вместо строки файла ровно по этой причине.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// ConstStringValue — значение строковой константы, объявленной в исходнике.
//
// Возвращает признак находки отдельно от значения: «объявления нет» и
// «объявлено пустым» — разные состояния, и схлопывать их нельзя.
func ConstStringValue(src []byte, name string) (string, bool, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name+".go", src, 0)
	if err != nil {
		return "", false, fmt.Errorf("разбор исходника: %w", err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", false, fmt.Errorf(
						"%s объявлена не строковым литералом: значение вычисляется, "+
							"и сверить его разбором нельзя", name)
				}
				unquoted, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return "", false, fmt.Errorf("значение %s: %w", name, uerr)
				}
				return unquoted, true, nil
			}
		}
	}
	return "", false, nil
}
