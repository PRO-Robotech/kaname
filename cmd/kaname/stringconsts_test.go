// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// stringconsts_test.go — ОБЩИЙ распознаватель строкового довода для проб,
// читающих объявления композиционного корня.
//
// # Зачем общий, а не по копии в каждой пробе
//
// Форм, в которых корень записывает строку-довод, ТРИ: литерал, склейка
// литералов и ИМЕНОВАННАЯ КОНСТАНТА пакета. Третья появилась вместе с ручками
// поверхностей (#2639): имя ручки профиля нужно в двух местах — в причине, по
// которой поверхность выключена, и в отказе стража различимости адресов, —
// поэтому оно объявлено константой один раз, а не выписано литералом дважды.
//
// Распознаватель, не знающий формы, не краснеет и не зеленеет — он МОЛЧИТ: всё,
// записанное новой формой, выпадает из наблюдения. Именно так и вышло: два
// гейта осей адреса перестали видеть ручки в ту же минуту, как литерал стал
// константой, и ни один из них не сказал, что ослеп, — они сказали «ручка не
// названа ни одной осью».
//
// Копия распознавателя в каждой пробе вернула бы тот же класс со сдвигом: одна
// научилась бы новой форме, вторая нет, и разошлись бы они молча.
//
// # Граница, названная вслух
//
// Распознаётся константа ПАКЕТА, а не значение переменной: переменная получает
// значение в рантайме, и «причина выключения» у неё непроверяема по объявлению.
// Обе стороны этой границы доказаны инъекцией.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// packageStringConsts собирает строковые константы верхнего уровня НЕ-тестовых
// файлов каталога.
//
// Каталог принимается доводом по той же причине, что и у пробы, которая зовёт:
// инъекция подаёт синтетический вход, не трогая рабочей копии.
func packageStringConsts(dir string) (map[string]string, error) {
	out := map[string]string{}
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	for _, path := range names {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, perr
		}
		collectStringConsts(file, out)
	}
	return out, nil
}

// collectStringConsts добавляет строковые константы одного разобранного файла.
func collectStringConsts(file *ast.File, out map[string]string) {
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
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if s, ok := resolveStringExpr(vs.Values[i], out); ok {
					out[name.Name] = s
				}
			}
		}
	}
}

// resolveStringExpr складывает значение строкового выражения из литералов и
// известных констант пакета. Неизвестная часть делает результат неразрешённым —
// «не знаю» здесь отличимо от пустой строки, и это несущее различие: пустая
// причина выключения есть находка, а неразрешённая — граница распознавателя.
func resolveStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		// Развёртывание, а не срез кавычек: экранированные последовательности
		// иначе доехали бы до сравнения в своей записи, и «содержит ручку»
		// решалось бы формой литерала, а не его значением.
		unquoted, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return unquoted, true
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, okL := resolveStringExpr(v.X, consts)
		right, okR := resolveStringExpr(v.Y, consts)
		if !okL || !okR {
			return "", false
		}
		return left + right, true
	default:
		return "", false
	}
}
