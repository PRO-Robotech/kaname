// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Нулевой локальный срез или прямое поле нулевой структуры получает
// backing исключительно от self-append. Копия заголовка передаёт доступ к тем же
// элементам. Это выделение отлично от другого точного literal/make.
// Доказываем только несовпадение владельцев записи:
// элементы, возвращённые алиасы и неизвестное происхождение самого среза
// остаются в обычном обходе. Положительное совпадение owners проверяет caller.
func (p *callerLifetimeProbe) separateLocalAppendBacking(write callerLifetimeWrite, object callerObjectKey) bool {
	src := write.owner
	if write.whole || src.pkg == nil || src.pkg.info == nil || src.pkg.types == nil || src.expr == nil ||
		src.tuple != -1 || src.elem || src.rangeKey || src.rangeVal || src.opAssign ||
		object.pkg == nil || object.pkg.info == nil || object.expr == nil || object.field != nil || object.zero != nil ||
		p.steps > callerLifetimeStepLimit || p.g.semanticOverflow || p.g.ctx != nil && p.g.ctx.Err() != nil {
		return false
	}
	if !callerExactAllocation(object) {
		return false
	}
	id, _ := callerLocalAppendPlace(src.pkg, src.expr)
	if id == nil {
		return p.g.privateAppendReceiver(src)
	}
	v, ok := src.pkg.info.Uses[id].(*types.Var)
	if !ok || v.IsField() || v.Parent() == nil || v.Parent() == src.pkg.types.Scope() || p.g.index == nil || p.g.index.addrTaken[v] {
		return false
	}
	fk, zero := p.g.zeroVars[v]
	if !zero || fk != src.fk || fk.fn == nil && fk.lit == nil {
		return false
	}
	ownerType := src.pkg.info.TypeOf(src.expr)
	if ownerType == nil {
		return false
	}
	if _, slice := ownerType.Underlying().(*types.Slice); !slice {
		return false
	}
	if known, found := p.g.localAppendBuilders[v]; found {
		return known
	}
	known := p.g.closedLocalAppendBuilder(src.pkg, fk, v)
	if p.g.ctx != nil && p.g.ctx.Err() != nil {
		return false
	}
	if p.g.localAppendBuilders == nil {
		p.g.localAppendBuilders = map[*types.Var]bool{}
	}
	// Число записей ограничено zeroVars. Проверка каждого кандидата конечна,
	// а повторный unknown owner не запускает новый обход AST.
	p.g.localAppendBuilders[v] = known
	return known
}

// Прямой селектор адресует ячейку самого value, а не вложенный или
// разыменованный объект. Идентификатор возвращается для полного учёта uses.
func callerLocalAppendPlace(sp *surfaceSrcPkg, expr ast.Expr) (*ast.Ident, *types.Var) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e, nil
	case *ast.SelectorExpr:
		base, ok := ast.Unparen(e.X).(*ast.Ident)
		selection := sp.info.Selections[e]
		if !ok || selection == nil || selection.Kind() != types.FieldVal || selection.Indirect() || len(selection.Index()) != 1 {
			return nil, nil
		}
		if _, value := selection.Recv().Underlying().(*types.Struct); !value {
			return nil, nil
		}
		field, _ := selection.Obj().(*types.Var)
		if field != nil {
			return base, field
		}
	}
	return nil, nil
}

func callerExactAllocation(object callerObjectKey) bool {
	typ := object.pkg.info.TypeOf(object.expr)
	if typ == nil {
		return false
	}
	switch e := object.expr.(type) {
	case *ast.CompositeLit:
		switch typ.Underlying().(type) {
		case *types.Struct, *types.Array, *types.Slice, *types.Map:
			return true
		}
	case *ast.CallExpr:
		id, ok := ast.Unparen(e.Fun).(*ast.Ident)
		if !ok {
			return false
		}
		builtin, ok := object.pkg.info.Uses[id].(*types.Builtin)
		if !ok || builtin.Name() != "make" {
			return false
		}
		switch typ.Underlying().(type) {
		case *types.Slice, *types.Map, *types.Chan:
			return true
		}
	}
	return false
}

func (g *callerGraph) closedLocalAppendBuilder(sp *surfaceSrcPkg, fk fkey, variable *types.Var) bool {
	body, found := g.bodies[callerNode{fn: fk.fn, lit: fk.lit}]
	if !found || body.sp != sp || body.node == nil {
		return false
	}
	allowed := map[*ast.Ident]bool{}
	declared, appended, complete := false, false, true
	steps := 0
	visit := func(node ast.Node) bool {
		steps++
		if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
		id, ok := node.(*ast.Ident)
		return !ok || sp.info.Uses[id] != variable || allowed[id]
	}
	ast.Inspect(body.node, func(node ast.Node) bool {
		if node == nil || !complete {
			return false
		}
		// Предок разрешает ровно свои позиции до посещения идентификаторов.
		// Каждое тело, включая вложенные замыкания, расходует общий лимит.
		if !visit(node) {
			complete = false
			return false
		}
		switch n := node.(type) {
		case *ast.FuncLit:
			// Внутри замыкания даже чтение по значению считается захватом.
			for child := range ast.Preorder(n) {
				if child != n && !visit(child) {
					complete = false
					break
				}
			}
			return false
		case *ast.ValueSpec:
			for _, id := range n.Names {
				if sp.info.Defs[id] == variable && len(n.Values) == 0 {
					declared = true
				}
			}
		case *ast.AssignStmt:
			if n.Tok != token.ASSIGN || len(n.Lhs) != 1 || len(n.Rhs) != 1 {
				break
			}
			lhs, field := callerLocalAppendPlace(sp, n.Lhs[0])
			if lhs == nil || sp.info.Uses[lhs] != variable {
				break
			}
			lhsType := sp.info.TypeOf(n.Lhs[0])
			if lhsType == nil {
				break
			}
			if _, slice := lhsType.Underlying().(*types.Slice); !slice {
				break
			}
			call, ok := ast.Unparen(n.Rhs[0]).(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || !types.Identical(sp.info.TypeOf(call), lhsType) {
				break
			}
			fun, ok := ast.Unparen(call.Fun).(*ast.Ident)
			if !ok {
				break
			}
			builtin, ok := sp.info.Uses[fun].(*types.Builtin)
			if !ok || builtin.Name() != "append" {
				break
			}
			first, firstField := callerLocalAppendPlace(sp, call.Args[0])
			if first == nil || sp.info.Uses[first] != variable || firstField != field || !types.Identical(sp.info.TypeOf(call.Args[0]), lhsType) {
				break
			}
			allowed[lhs], allowed[first], appended = true, true, true
		case *ast.CallExpr:
			for i, arg := range n.Args {
				id, ok := ast.Unparen(arg).(*ast.Ident)
				if !ok || sp.info.Uses[id] != variable {
					continue
				}
				callee := sp.info.Types[n.Fun]
				if callee.IsBuiltin() {
					// Остальные builtins (включая unsafe) сохраняют прежний отказ.
					// Позиции self-append уже разрешены присваиванием выше.
					fun, ok := ast.Unparen(n.Fun).(*ast.Ident)
					if ok && len(n.Args) == 1 && (fun.Name == "len" || fun.Name == "cap") {
						allowed[id] = true
					}
					continue
				}
				if !callee.IsValue() || callee.Type == nil {
					continue
				}
				sig, ok := callee.Type.Underlying().(*types.Signature)
				if !ok || i >= sig.Params().Len() || !types.Identical(sig.Params().At(i).Type(), variable.Type()) {
					continue
				}
				// Вариативный хвост получает сам срез только при f(..., out...).
				if sig.Variadic() && i == sig.Params().Len()-1 && !n.Ellipsis.IsValid() {
					continue
				}
				allowed[id] = true
			}
		case *ast.ReturnStmt:
			for _, result := range n.Results {
				if id, ok := ast.Unparen(result).(*ast.Ident); ok && sp.info.Uses[id] == variable {
					allowed[id] = true
				}
			}
		}
		return true
	})
	return complete && declared && appended
}
