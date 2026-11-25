// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Для *receiver.field = value нужен адрес ячейки: прежнее содержимое
// интерфейса или указателя в отдельной локальной переменной на него не влияет.
// Обычная достижимость для непрозрачных вызовов по-прежнему обходит содержимое.
func (p *callerLifetimeProbe) separateProjectedStore(src valueSrc, sel *ast.SelectorExpr) bool {
	if !callerFreshReplayContext(p.g.ctx) || src.fk.fn == nil || src.fk.lit != nil ||
		src.tuple != -1 || src.elem || src.rangeKey || src.rangeVal || src.opAssign {
		return false
	}
	if p.want.zero == nil {
		lit, ok := p.want.expr.(*ast.CompositeLit)
		if !ok {
			return false
		}
		t := p.want.pkg.info.TypeOf(lit)
		if t == nil {
			return false
		}
		if _, ok := t.Underlying().(*types.Struct); !ok {
			return false
		}
	} else if p.want.expr != nil || p.want.zero.IsField() {
		return false
	}
	cells, known := p.g.projectedStoreCells[sel]
	if !known {
		cells = p.g.closedProjectedStore(src, sel)
		if p.g.semanticOverflow || p.g.ctx != nil && p.g.ctx.Err() != nil {
			return false
		}
		if p.g.projectedStoreCells == nil {
			p.g.projectedStoreCells = map[*ast.SelectorExpr]map[*types.Var]bool{}
		}
		p.g.projectedStoreCells[sel] = cells
	}
	return len(cells) != 0 && !cells[p.want.zero] && !p.g.semanticOverflow && (p.g.ctx == nil || p.g.ctx.Err() == nil)
}

// У закрытого типа ровно три допустимых упоминания: получатель записывающего
// метода, тип результата конструктора и его возвращаемый литерал. Каждый вызов
// конструктора передаёт результат непосредственно методу через проверенное тело
// диспетчера. Отсутствие промежуточного алиаса исключает замену всего носителя.
func (g *callerGraph) closedProjectedStore(src valueSrc, sel *ast.SelectorExpr) map[*types.Var]bool {
	sp, method := src.pkg, src.fk.fn
	sig := method.Signature()
	recv, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || sig.Recv() == nil || sp.info.Uses[recv] != sig.Recv() ||
		sig.Params().Len() != 0 || sig.Results().Len() != 0 || len(sp.info.Uses) > callerLifetimeStepLimit {
		return nil
	}
	ptr, ok := types.Unalias(sig.Recv().Type()).(*types.Pointer)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj().Pkg() != sp.types || named.Obj().Exported() {
		return nil
	}
	carrier := named.Origin().Obj()
	selection := sp.info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	if _, ok := types.Unalias(field.Type()).(*types.Pointer); !ok {
		return nil
	}
	steps := 0
	var factory *types.Func
	allowed := map[*ast.Ident]bool{recv: true}
	for _, file := range sp.files {
		for _, d := range file.Decls {
			steps++
			if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
				return nil
			}
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			f, ok := sp.info.Defs[fn.Name].(*types.Func)
			if !ok {
				continue
			}
			if f == method {
				if fn.Recv == nil || len(fn.Recv.List) != 1 {
					return nil
				}
				allowed[projectedStoreName(fn.Recv.List[0].Type)] = true
				continue
			}
			s := f.Signature()
			if s.Results().Len() != 1 {
				continue
			}
			out, ok := types.Unalias(s.Results().At(0).Type()).(*types.Pointer)
			if !ok {
				continue
			}
			result, ok := types.Unalias(out.Elem()).(*types.Named)
			if !ok || result.Origin().Obj() != carrier {
				continue
			}
			if factory != nil || f.Exported() || s.Recv() != nil || s.Params().Len() != 1 ||
				len(fn.Body.List) != 1 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				return nil
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return nil
			}
			addr, ok := ast.Unparen(ret.Results[0]).(*ast.UnaryExpr)
			if !ok || addr.Op != token.AND {
				return nil
			}
			lit, ok := ast.Unparen(addr.X).(*ast.CompositeLit)
			if !ok || len(lit.Elts) != 1 || !types.Identical(sp.info.TypeOf(lit), out.Elem()) {
				return nil
			}
			kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
			if !ok {
				return nil
			}
			key, ok := kv.Key.(*ast.Ident)
			actual, variable := ast.Unparen(kv.Value).(*ast.Ident)
			if !ok || !variable || sp.info.Uses[actual] != s.Params().At(0) {
				return nil
			}
			member, ok := sp.info.Uses[key].(*types.Var)
			if !ok || member.Origin() != field.Origin() {
				return nil
			}
			allowed[projectedStoreName(fn.Type.Results.List[0].Type)] = true
			allowed[projectedStoreName(lit.Type)] = true
			factory = f
		}
	}
	if factory == nil {
		return nil
	}
	cells := map[*types.Var]bool{}
	for _, file := range sp.files {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil || steps > callerLifetimeStepLimit {
				return false
			}
			steps++
			if g.ctx != nil && g.ctx.Err() != nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			inner, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr)
			if !ok || len(inner.Args) != 1 {
				return true
			}
			id := projectedStoreName(inner.Fun)
			if id == nil || sp.info.Uses[id] != factory || !g.directProjectedDispatch(sp, call, method) {
				return true
			}
			addr, ok := ast.Unparen(inner.Args[0]).(*ast.UnaryExpr)
			if !ok || addr.Op != token.AND {
				return true
			}
			target, ok := ast.Unparen(addr.X).(*ast.Ident)
			if !ok {
				return true
			}
			cell, ok := sp.info.Uses[target].(*types.Var)
			if !ok || cell.IsField() || cell.Pkg() != sp.types || cell.Parent() == nil || cell.Parent() == sp.types.Scope() {
				return true
			}
			switch cell.Type().Underlying().(type) {
			case *types.Interface, *types.Pointer:
				cells[cell] = true
				allowed[id] = true
			}
			return true
		})
		if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
			return nil
		}
	}
	for id, obj := range sp.info.Uses {
		if g.ctx != nil && g.ctx.Err() != nil {
			return nil
		}
		if (obj == carrier || obj == sig.Recv() || obj == factory) && !allowed[id] {
			return nil
		}
	}
	return cells
}

// Используем идентичность из go/types и у явно инстанцированных имён.
func projectedStoreName(expr ast.Expr) *ast.Ident {
	switch x := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return x
	case *ast.StarExpr:
		return projectedStoreName(x.X)
	case *ast.IndexExpr:
		return projectedStoreName(x.X)
	case *ast.IndexListExpr:
		return projectedStoreName(x.X)
	}
	return nil
}

// Диспетчер непосредственно вызывает метод единственного аргумента, без
// сохранения или передачи переданного носителя другому коду.
func (g *callerGraph) directProjectedDispatch(sp *surfaceSrcPkg, site *ast.CallExpr, method *types.Func) bool {
	f := callerFunction(sp, site.Fun)
	if f == nil {
		return false
	}
	f = f.Origin()
	sig := f.Signature()
	if sig.Recv() != nil || sig.Params().Len() != 1 || sig.Variadic() {
		return false
	}
	body := g.bodies[callerNode{fn: f}]
	block, ok := body.node.(*ast.BlockStmt)
	if !ok || body.sp != sp || len(block.List) != 1 {
		return false
	}
	stmt, ok := block.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := ast.Unparen(stmt.X).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method.Name() {
		return false
	}
	receiver, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || sp.info.Uses[receiver] != sig.Params().At(0) {
		return false
	}
	selection := sp.info.Selections[sel]
	return selection != nil && selection.Kind() == types.MethodVal && len(selection.Index()) == 1
}
