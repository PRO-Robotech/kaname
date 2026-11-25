// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// В модели типизированного Go непубличный метод может получить чужой receiver
// через method value/expression или интерфейс своего пакета. Полная перепись
// исключает такие вызовы. Контракт не описывает подмену машинного кода.
func (g *callerGraph) privateAppendReceiver(src valueSrc) bool {
	sp, fn := src.pkg, src.fk.fn
	if fn == nil || src.fk.lit != nil || fn.Exported() || fn.Pkg() != sp.types || g.index == nil {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	ptr, ok := types.Unalias(recv.Type()).(*types.Pointer)
	if !ok || fn.Signature().RecvTypeParams().Len() != 0 {
		return false
	}
	if _, ok := ptr.Elem().Underlying().(*types.Struct); !ok {
		return false
	}
	id, field := privateAppendField(sp, src.expr)
	if id == nil || sp.info.Uses[id] != recv || field == nil {
		return false
	}
	if _, slice := field.Type().Underlying().(*types.Slice); !slice {
		return false
	}
	if known, found := g.localAppendBuilders[recv]; found {
		return known
	}
	closed := g.closedPrivateAppendReceiver(sp, fn, recv, ptr.Elem())
	if g.ctx != nil && g.ctx.Err() != nil {
		return false
	}
	if g.localAppendBuilders == nil {
		g.localAppendBuilders = map[*types.Var]bool{}
	}
	g.localAppendBuilders[recv] = closed
	return closed
}

func privateAppendField(sp *surfaceSrcPkg, expr ast.Expr) (*ast.Ident, *types.Var) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}
	id, ok := sel.X.(*ast.Ident)
	s := sp.info.Selections[sel]
	if !ok || s == nil || s.Kind() != types.FieldVal || len(s.Index()) != 1 {
		return nil, nil
	}
	field, _ := s.Obj().(*types.Var)
	return id, field
}

func (g *callerGraph) closedPrivateAppendReceiver(sp *surfaceSrcPkg, fn *types.Func, recv *types.Var, typ types.Type) bool {
	calls := g.index.calls[fn]
	if len(calls) != 1 || calls[0].pkg != sp || calls[0].fk.fn == nil || calls[0].fk.lit != nil {
		return false
	}
	for _, pkg := range sp.types.Imports() {
		// В том числе //go:linkname: компилятор требует импорт unsafe в его файле.
		if pkg.Path() == "unsafe" {
			return false
		}
	}
	site := calls[0]
	sel, ok := site.call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	s := sp.info.Selections[sel]
	root, ok := sel.X.(*ast.Ident)
	if !ok || s == nil || s.Kind() != types.MethodVal || s.Obj() != fn || len(s.Index()) != 1 {
		return false
	}
	local, ok := sp.info.Uses[root].(*types.Var)
	if !ok || !types.Identical(local.Type(), typ) || local.Parent() == nil || local.Parent() == sp.types.Scope() || g.index.addrTaken[local] {
		return false
	}
	if fk, zero := g.zeroVars[local]; !zero || fk != site.fk {
		return false
	}
	steps := 0
	closed, declared, called, appended := true, false, false, false
	for _, file := range sp.files {
		ast.PreorderStack(file, nil, func(node ast.Node, stack []ast.Node) bool {
			steps++
			if !closed || steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
				closed = false
				return false
			}
			if decl, ok := node.(*ast.FuncDecl); ok && decl.Body == nil {
				closed = false
				return false
			}
			id, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if other, ok := sp.info.Defs[id].(*types.Func); ok && other.Name() == fn.Name() && isIfaceMethod(other) {
				closed = false
				return false
			}
			if sp.info.Defs[id] == local {
				spec, ok := stack[len(stack)-1].(*ast.ValueSpec)
				declared = ok && len(spec.Values) == 0
			}
			obj := sp.info.Uses[id]
			if obj != fn && obj != recv && obj != local {
				return true
			}
			for _, parent := range stack {
				if _, capture := parent.(*ast.FuncLit); capture {
					closed = false
					return false
				}
			}
			switch obj {
			case fn:
				if len(stack) >= 3 {
					stmt, sync := stack[len(stack)-3].(*ast.ExprStmt)
					called = sync && stmt.X == site.call && stack[len(stack)-2] == site.call && stack[len(stack)-1] == sel && id == sel.Sel
				}
				closed = id == sel.Sel && called
			case local:
				closed = id == root || privateAppendLocalRead(sp, id, stack, site.fk.fn.Signature())
			case recv:
				var self bool
				closed, self = privateAppendReceiverUse(sp, id, stack)
				appended = appended || self
			}
			return closed
		})
		if !closed {
			return false
		}
	}
	return declared && called && appended
}

// Локальную ячейку можно вернуть по значению, прочесть счётчик или длину среза.
// Даже адрес соседнего скаляра и связанное значение метода сюда не попадают.
func privateAppendLocalRead(sp *surfaceSrcPkg, id *ast.Ident, stack []ast.Node, caller *types.Signature) bool {
	parent := stack[len(stack)-1]
	if ret, ok := parent.(*ast.ReturnStmt); ok {
		for i, result := range ret.Results {
			if result == id && i < caller.Results().Len() && types.Identical(caller.Results().At(i).Type(), sp.info.TypeOf(id)) {
				return true
			}
		}
		return false
	}
	sel, ok := parent.(*ast.SelectorExpr)
	if !ok || len(stack) < 2 {
		return false
	}
	base, field := privateAppendField(sp, sel)
	if base != id || field == nil {
		return false
	}
	use := stack[len(stack)-2]
	switch n := use.(type) {
	case *ast.CallExpr:
		if len(n.Args) == 1 && n.Args[0] == sel {
			if fun, ok := n.Fun.(*ast.Ident); ok && sp.info.Uses[fun] == types.Universe.Lookup("len") {
				_, slice := field.Type().Underlying().(*types.Slice)
				return slice
			}
		}
		if types.Identical(field.Type(), types.Typ[types.Int]) {
			for _, arg := range n.Args {
				if arg == sel {
					return true
				}
			}
		}
	case *ast.BinaryExpr:
		return n.Op == token.ADD && types.Identical(field.Type(), types.Typ[types.Int])
	}
	return false
}

// Приращение int может идти через вложенные value-поля. Все заголовки срезов
// имеют единственную форму записи: прямое поле = builtin append(то же поле,...).
func privateAppendReceiverUse(sp *surfaceSrcPkg, id *ast.Ident, stack []ast.Node) (allowed, self bool) {
	i := len(stack) - 1
	sel, ok := stack[i].(*ast.SelectorExpr)
	if !ok || i < 1 {
		return false, false
	}
	base, field := privateAppendField(sp, sel)
	if base != id || field == nil {
		return false, false
	}
	i--
	if _, slice := field.Type().Underlying().(*types.Slice); slice {
		var assignment *ast.AssignStmt
		switch parent := stack[i].(type) {
		case *ast.AssignStmt:
			assignment = parent
		case *ast.CallExpr:
			if i > 0 && len(parent.Args) > 0 && parent.Args[0] == sel {
				assignment, _ = stack[i-1].(*ast.AssignStmt)
			}
		}
		if assignment == nil || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return false, false
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return false, false
		}
		fun, ok := call.Fun.(*ast.Ident)
		left, lf := privateAppendField(sp, assignment.Lhs[0])
		right, rf := privateAppendField(sp, call.Args[0])
		good := ok && sp.info.Uses[fun] == types.Universe.Lookup("append") &&
			left != nil && right != nil && (id == left || id == right) &&
			sp.info.Uses[left] == sp.info.Uses[right] && lf == field && rf == field &&
			types.Identical(sp.info.TypeOf(call), field.Type())
		return good, good
	}
	for i > 0 {
		next, ok := stack[i].(*ast.SelectorExpr)
		if !ok {
			break
		}
		s := sp.info.Selections[next]
		if next.X != sel || s == nil || s.Kind() != types.FieldVal || s.Indirect() || len(s.Index()) != 1 {
			return false, false
		}
		if _, value := sp.info.TypeOf(sel).Underlying().(*types.Struct); !value {
			return false, false
		}
		sel = next
		i--
	}
	if !types.Identical(sp.info.TypeOf(sel), types.Typ[types.Int]) {
		return false, false
	}
	switch use := stack[i].(type) {
	case *ast.IncDecStmt:
		return use.X == sel && use.Tok == token.INC, false
	case *ast.AssignStmt:
		return len(use.Lhs) == 1 && use.Lhs[0] == sel && use.Tok == token.ADD_ASSIGN, false
	}
	return false, false
}
