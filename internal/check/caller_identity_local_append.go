// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Нулевой локальный срез, доступный только self-append и возврату
// по значению, получает backing исключительно от append. Эта память не является памятью другого
// точного literal/make. Доказываем только несовпадение владельцев записи:
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
	id, ok := ast.Unparen(src.expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := src.pkg.info.Uses[id].(*types.Var)
	if !ok || v.IsField() || v.Parent() == nil || v.Parent() == src.pkg.types.Scope() || p.g.index == nil || p.g.index.addrTaken[v] {
		return false
	}
	fk, zero := p.g.zeroVars[v]
	if !zero || fk != src.fk || fk.fn == nil && fk.lit == nil {
		return false
	}
	if _, slice := v.Type().Underlying().(*types.Slice); !slice {
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
	ast.Inspect(body.node, func(node ast.Node) bool {
		if node == nil || !complete {
			return false
		}
		steps++
		if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
			complete = false
			return false
		}
		switch n := node.(type) {
		case *ast.FuncLit:
			// Полный проход ниже увидит захват без разрешённой позиции.
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
			lhs, ok := ast.Unparen(n.Lhs[0]).(*ast.Ident)
			if !ok || sp.info.Uses[lhs] != variable {
				break
			}
			call, ok := ast.Unparen(n.Rhs[0]).(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || !types.Identical(sp.info.TypeOf(call), variable.Type()) {
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
			first, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
			if !ok || sp.info.Uses[first] != variable || !types.Identical(sp.info.TypeOf(first), variable.Type()) {
				break
			}
			allowed[lhs], allowed[first], appended = true, true, true
		case *ast.ReturnStmt:
			for _, result := range n.Results {
				if call, ok := ast.Unparen(result).(*ast.CallExpr); ok {
					// При return f(out...) передаётся копия заголовка, поэтому
					// вызов не заменит локальное выделение. Остальной обход
					// сохраняет содержимое, эффекты вызова и его результат.
					// Любой захват out, включая замыкание f, обнаружит Uses.
					if !call.Ellipsis.IsValid() || len(call.Args) != 1 {
						continue
					}
					calleeType := sp.info.TypeOf(call.Fun)
					if calleeType == nil {
						continue
					}
					signature, ok := calleeType.Underlying().(*types.Signature)
					if !ok || !signature.Variadic() || signature.Params().Len() != 1 ||
						!types.Identical(sp.info.TypeOf(call.Args[0]), signature.Params().At(0).Type()) {
						continue
					}
					result = call.Args[0]
				}
				if id, ok := ast.Unparen(result).(*ast.Ident); ok && sp.info.Uses[id] == variable {
					allowed[id] = true
				}
			}
		}
		return true
	})
	if !complete || !declared || !appended {
		return false
	}
	// Объявление найдено внутри этого тела. Область локальной переменной
	// заканчивается там же, поэтому все её употребления находятся здесь,
	// включая захваты вложенных замыканий. Учитываем полный обход тела
	// в том же лимите, не начисляя работу за остальной пакет.
	for node := range ast.Preorder(body.node) {
		steps++
		if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
		if id, ok := node.(*ast.Ident); ok && sp.info.Uses[id] == variable && !allowed[id] {
			return false
		}
	}
	return true
}
