// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Общий индекс источников записывает в p также правую часть *p = value.
// Для записи целой ячейки отличаем место назначения от хранившегося значения.
// Закрытый случай — приватная функция пишет по адресу отдельной скалярной
// переменной. Эта переменная не может быть полем структурного литерала.
func (p *callerLifetimeProbe) separateScalarStore(dst, query valueSrc, objects map[callerObjectKey]bool) bool {
	if p.field == nil || p.want.field != nil || p.want.pkg == nil || p.want.pkg.info == nil ||
		dst.pkg == nil || dst.pkg.types == nil || dst.pkg.info == nil ||
		p.steps > callerLifetimeStepLimit || p.g.semanticOverflow || p.g.ctx != nil && p.g.ctx.Err() != nil {
		return false
	}
	if sel, ok := ast.Unparen(dst.expr).(*ast.SelectorExpr); ok {
		return p.separateProjectedStore(dst, sel)
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
	} else if !p.directReceiverCell(query, objects) {
		return false
	}
	id, ok := ast.Unparen(dst.expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := dst.pkg.info.Uses[id].(*types.Var)
	if !ok {
		return false
	}
	if known, found := p.g.scalarStoreParams[v]; found {
		return known
	}
	if p.g.scalarStoreParams == nil {
		p.g.scalarStoreParams = map[*types.Var]bool{}
	}
	known := p.g.closedScalarStoreParam(dst.pkg, v)
	if p.g.ctx != nil && p.g.ctx.Err() != nil {
		return false
	}
	p.g.scalarStoreParams[v] = known
	return known
}

// callerObjects добавляет ячейку переменной к её загруженным значениям. Здесь
// проверяется только сама ячейка получателя. Каждый литерал, на который он
// указывает, остаётся отдельным ключом в том же обходе времени жизни.
func (p *callerLifetimeProbe) directReceiverCell(query valueSrc, objects map[callerObjectKey]bool) bool {
	recv := p.want.zero
	id, ok := ast.Unparen(query.expr).(*ast.Ident)
	if !ok || query.pkg != p.want.pkg || query.pkg.info.Uses[id] != recv || p.want.expr != nil ||
		query.tuple != -1 || query.elem || query.rangeKey || query.rangeVal || query.opAssign ||
		!p.g.parameters[recv].recv || p.g.index == nil || p.g.index.addrTaken[recv] {
		return false
	}
	ptr, ok := types.Unalias(recv.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	field, index, _ := types.LookupFieldOrMethod(ptr.Elem(), false, p.field.Pkg(), p.field.Name())
	direct, ok := field.(*types.Var)
	if !ok || len(index) != 1 || direct.Origin() != p.field {
		return false
	}
	for obj := range objects {
		lit, ok := obj.expr.(*ast.CompositeLit)
		if ok && obj.zero == nil && obj.field == nil && obj.pkg != nil && obj.pkg.info != nil &&
			types.Identical(obj.pkg.info.TypeOf(lit), ptr.Elem()) {
			return true
		}
	}
	return false
}

func (g *callerGraph) closedScalarStoreParam(sp *surfaceSrcPkg, variable *types.Var) bool {
	param, ok := g.parameters[variable]
	if !ok || param.recv || param.fk.fn == nil || param.fk.fn.Exported() {
		return false
	}
	fn := param.fk.fn
	sig, ok := fn.Type().(*types.Signature)
	if !ok || fn.Pkg() != sp.types || sig.TypeParams().Len() != 0 || sig.RecvTypeParams().Len() != 0 {
		return false
	}
	ptr, ok := types.Unalias(variable.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	elem, ok := ptr.Elem().Underlying().(*types.Basic)
	if !ok || elem.Kind() == types.Invalid || elem.Kind() == types.UnsafePointer || elem.Kind() == types.Uintptr || elem.Info()&types.IsUntyped != 0 {
		return false
	}
	// Каждое употребление самой функции, её указателя-параметра и всех
	// скалярных ячеек должно попасть в нижеприведённую перепись.
	allowed := map[*ast.Ident]bool{}
	cells := map[*types.Var]bool{}
	for _, site := range g.index.calls[fn] {
		if site.pkg != sp || param.index < 0 || param.index >= len(site.call.Args) {
			return false
		}
		addr, ok := ast.Unparen(site.call.Args[param.index]).(*ast.UnaryExpr)
		if !ok || addr.Op != token.AND {
			return false
		}
		id, ok := ast.Unparen(addr.X).(*ast.Ident)
		if !ok {
			return false
		}
		cell, ok := sp.info.Uses[id].(*types.Var)
		if !ok || cell.Pkg() != sp.types || cell.Parent() == nil || cell.Parent() == sp.types.Scope() || cell.IsField() || !types.Identical(cell.Type(), ptr.Elem()) {
			return false
		}
		cells[cell] = true
		allowed[id] = true
		switch callee := ast.Unparen(site.call.Fun).(type) {
		case *ast.Ident:
			allowed[callee] = true
		case *ast.SelectorExpr:
			allowed[callee.Sel] = true
		default:
			return false
		}
	}
	if len(cells) == 0 {
		return false
	}
	for _, write := range g.lifetimeWrites {
		if write.whole && write.owner.pkg == sp {
			if id, ok := ast.Unparen(write.owner.expr).(*ast.Ident); ok && sp.info.Uses[id] == variable {
				allowed[id] = true
			}
		}
	}
	closed := true
	for _, file := range sp.files {
		ast.Inspect(file, func(node ast.Node) bool {
			if !closed {
				return false
			}
			switch n := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						if cell, ok := sp.info.Uses[id].(*types.Var); ok && cells[cell] {
							allowed[id] = true
						}
					}
				}
			case *ast.CallExpr:
				if len(n.Args) == 1 && sp.info.Types[n.Fun].IsType() {
					if id, ok := ast.Unparen(n.Args[0]).(*ast.Ident); ok {
						if cell, ok := sp.info.Uses[id].(*types.Var); ok && cells[cell] {
							allowed[id] = true
						}
					}
				}
			case *ast.SelectorExpr:
				selection := sp.info.Selections[n]
				if selection != nil {
					if method, ok := selection.Obj().(*types.Func); ok && method.Origin() == fn && !allowed[n.Sel] {
						closed = false
					}
				}
			case *ast.Ident:
				if other, ok := sp.info.Defs[n].(*types.Func); ok && other.Name() == fn.Name() && isIfaceMethod(other) {
					closed = false
					return false
				}
				obj := sp.info.Uses[n]
				cell, _ := obj.(*types.Var)
				if (obj == fn || obj == variable || cells[cell]) && !allowed[n] {
					closed = false
				}
			}
			return closed
		})
		if !closed || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
	}
	return true
}

// Адрес отдельной локальной скалярной переменной не является выделением
// срезового литерала. Объект литерала проверяет вызывающий objectWrites.
// Сохраняем только неизменяемые данные вызова. Активную привязку проверяем
// заново перед каждым пропуском, включая повторный вызов в том же корне.
type callerScalarSliceStore struct {
	address valueSrc
	cell    *types.Var
}

func (p *callerLifetimeProbe) separateClosedScalarSliceStore(w callerLifetimeWrite) bool {
	g, src := p.g, w.owner
	if !w.whole || !g.lifetimeScanning || g.scalarStoreNative || g.semanticOverflow ||
		p.steps > callerLifetimeStepLimit || !callerFreshReplayContext(g.ctx) || g.ctx != nil && g.ctx.Err() != nil ||
		src.pkg == nil || src.pkg.info == nil || src.pkg.types == nil || src.fk.fn == nil || src.fk.lit != nil ||
		src.tuple != -1 || src.elem || src.rangeKey || src.rangeVal || src.opAssign || w.value.pkg != src.pkg || w.value.fk != src.fk || w.value.expr == nil ||
		w.value.tuple != -1 || w.value.elem || w.value.rangeKey || w.value.rangeVal || w.value.opAssign {
		return false
	}
	id, ok := ast.Unparen(src.expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := src.pkg.info.Uses[id].(*types.Var)
	if !ok || len(g.live[v]) != 1 || g.parameters[v].fk != src.fk {
		return false
	}
	cert, known := g.scalarSliceStores[v]
	if !known {
		cert = g.closedScalarSliceStore(src, v)
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
		if g.scalarSliceStores == nil {
			g.scalarSliceStores = map[*types.Var]callerScalarSliceStore{}
		}
		g.scalarSliceStores[v] = cert
	}
	return cert.cell != nil && g.live[v][0] == cert.address && len(g.live[cert.cell]) == 0
}

func (g *callerGraph) closedScalarSliceStore(src valueSrc, v *types.Var) callerScalarSliceStore {
	var refused callerScalarSliceStore
	param, ok := g.parameters[v]
	if !ok || param.recv || param.fk.fn != src.fk.fn || param.index < 0 || g.index == nil {
		return refused
	}
	fn := src.fk.fn
	sites := g.index.calls[fn]
	if len(sites) != 1 || sites[0].pkg != src.pkg || param.index >= len(sites[0].call.Args) {
		return refused
	}
	for _, dep := range src.pkg.types.Imports() {
		if dep.Path() == "unsafe" || dep.Path() == "C" {
			return refused
		}
	}
	site := sites[0]
	sel, ok := ast.Unparen(site.call.Fun).(*ast.SelectorExpr)
	if !ok {
		return refused
	}
	method := src.pkg.info.Selections[sel]
	if method == nil || method.Kind() != types.MethodVal || method.Obj() != fn || len(method.Index()) != 1 || isIfaceMethod(fn) {
		return refused
	}
	arg := site.call.Args[param.index]
	addr, ok := ast.Unparen(arg).(*ast.UnaryExpr)
	if !ok || addr.Op != token.AND {
		return refused
	}
	id, ok := ast.Unparen(addr.X).(*ast.Ident)
	if !ok {
		return refused
	}
	cell, ok := src.pkg.info.Uses[id].(*types.Var)
	if !ok {
		return refused
	}
	if _, zero := g.zeroVars[cell]; !zero {
		return refused
	}
	if !g.closedScalarStoreParam(src.pkg, v) {
		return refused
	}
	return callerScalarSliceStore{valueSrc{pkg: site.pkg, fk: site.fk, expr: arg, tuple: -1}, cell}
}
