// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
)

type callerEmbeddedLiteralKey struct {
	pkg     *surfaceSrcPkg
	literal *ast.CompositeLit
}

// Индекс заменяет только статический поиск поля в CompositeLit. Значения —
// исходные выражения, не ответы обхода; bindings, UNKNOWN и lifetime не кешируются.
// Построение заканчивается до публикации callerGraphMemo. Копии графа читают
// общие карты без записей; неизвестный пакет/AST и лимит оставляют исходный путь.
type callerEmbeddedLiteralIndex struct {
	values map[callerEmbeddedLiteralKey]map[*types.Var]ast.Expr
	weight int
}

const (
	callerEmbeddedLiteralEntries = 4096
	callerEmbeddedLiteralValues  = 16384
)

func (index *callerEmbeddedLiteralIndex) add(sp *surfaceSrcPkg, literal *ast.CompositeLit) {
	if sp == nil || sp.info == nil || literal == nil {
		return
	}
	if len(index.values) >= callerEmbeddedLiteralEntries || len(literal.Elts) > callerEmbeddedLiteralValues-index.weight {
		return
	}
	key := callerEmbeddedLiteralKey{sp, literal}
	if _, exists := index.values[key]; exists {
		return
	}
	typ := types.Unalias(sp.info.TypeOf(literal))
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(ptr.Elem())
	}
	if typ == nil {
		return
	}
	st, ok := typ.Underlying().(*types.Struct)
	if !ok {
		return
	}
	// Любой неверный ключ оставляет весь литерал исходному поиску: тот может
	// найти запрошенное поле до ошибки, а для более позднего поля вернуть UNKNOWN.
	for _, element := range literal.Elts {
		if keyed, ok := element.(*ast.KeyValueExpr); ok {
			id, valid := keyed.Key.(*ast.Ident)
			if !valid {
				return
			}
			if field, valid := sp.info.Uses[id].(*types.Var); !valid || field == nil {
				// Неполная типизация остаётся исходному поиску, даже если
				// сам тип литерала уже известен.
				return
			}
		}
	}
	var values map[*types.Var]ast.Expr
	for position, element := range literal.Elts {
		var field *types.Var
		value := element
		if keyed, ok := element.(*ast.KeyValueExpr); ok {
			field, _ = sp.info.Uses[keyed.Key.(*ast.Ident)].(*types.Var)
			value = keyed.Value
		} else if position < st.NumFields() {
			field = st.Field(position)
		}
		if field == nil {
			continue
		}
		field = field.Origin()
		if _, exists := values[field]; exists {
			continue // Исходный упорядоченный обход выбирает первое совпадение.
		}
		if values == nil {
			values = map[*types.Var]ast.Expr{}
		}
		values[field] = value
	}
	if index.values == nil {
		index.values = map[callerEmbeddedLiteralKey]map[*types.Var]ast.Expr{}
	}
	index.values[key] = values
	index.weight += len(values)
}

// Сохраняем только чтение, которое инициализирует строковое поле литерала
// значением другого строкового поля. Адрес поля, селектор метода и упаковка в
// интерфейс сюда не попадают. Узел AST однозначно задаёт позицию копирования.
func (g *callerGraph) indexCopiedStringField(sp *surfaceSrcPkg, pair *ast.KeyValueExpr) {
	key, ok := pair.Key.(*ast.Ident)
	if !ok {
		return
	}
	dst, ok := sp.info.Uses[key].(*types.Var)
	if !ok || !dst.IsField() || !types.Identical(dst.Type(), types.Typ[types.String]) {
		return
	}
	read, ok := ast.Unparen(pair.Value).(*ast.SelectorExpr)
	if !ok {
		return
	}
	sel := sp.info.Selections[read]
	if sel == nil || sel.Kind() != types.FieldVal || len(sel.Index()) != 1 ||
		!types.Identical(sel.Type(), types.Typ[types.String]) {
		return
	}
	if g.copiedStringFields == nil {
		g.copiedStringFields = make(map[*ast.SelectorExpr]*surfaceSrcPkg)
	}
	g.copiedStringFields[read] = sp
}
