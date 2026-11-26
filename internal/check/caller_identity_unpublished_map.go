// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Индекс хранит только записи до первого стороннего действия. Каждое
// исполнение этого префикса проходит через свежее объявление: объявления и
// записи лежат в верхнем блоке функции, непосредственно друг за другом, без
// меток и переходов. Публикация handle ниже префикса допустима.
func (g *callerGraph) indexUnpublishedMapWrites(body callerBody, source func(ast.Expr) valueSrc) {
	block, ok := body.node.(*ast.BlockStmt)
	if !ok || len(block.List) > callerLifetimeStepLimit || g.index == nil || body.sp == nil || body.sp.info == nil {
		return
	}
	var variable *types.Var
	for _, stmt := range block.List {
		if variable != nil {
			if write, ok := callerUnpublishedMapWrite(body.sp, variable, stmt, source); ok {
				if g.unpublishedMapWrites == nil {
					g.unpublishedMapWrites = make(map[callerLifetimeWrite]*types.Var)
				}
				g.unpublishedMapWrites[write] = variable
				continue
			}
		}
		variable = nil
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			continue
		}
		lit, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok || len(lit.Elts) != 0 {
			continue
		}
		v, ok := body.sp.info.Defs[id].(*types.Var)
		if !ok || g.index.addrTaken[v] {
			continue
		}
		typ, ok := v.Type().Underlying().(*types.Map)
		if !ok || !types.Identical(typ.Key(), types.Typ[types.String]) || !types.Identical(typ.Elem(), types.Typ[types.String]) {
			continue
		}
		// Неучтённая или повторно записанная ячейка не получает сертификат,
		// даже когда её тип совпал. Индекс отличает m[k] от m = ...
		refs := g.index.varWrites[v]
		if len(refs) > callerLifetimeStepLimit {
			continue
		}
		direct := 0
		for _, ref := range refs {
			if !ref.elem {
				direct++
				if ref != source(lit) {
					direct = -1
					break
				}
			}
		}
		if direct == 1 {
			variable = v
		}
	}
}

func callerUnpublishedMapWrite(sp *surfaceSrcPkg, variable *types.Var, stmt ast.Stmt, source func(ast.Expr) valueSrc) (callerLifetimeWrite, bool) {
	if guard, ok := stmt.(*ast.IfStmt); ok {
		if guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
			return callerLifetimeWrite{}, false
		}
		cond, ok := guard.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ && cond.Op != token.EQL || sp.info.Types[cond.Y].Value == nil {
			return callerLifetimeWrite{}, false
		}
		id, ok := cond.X.(*ast.Ident)
		if !ok || !types.Identical(sp.info.TypeOf(id), types.Typ[types.String]) {
			return callerLifetimeWrite{}, false
		}
		stmt = guard.Body.List[0]
	}
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return callerLifetimeWrite{}, false
	}
	index, ok := assign.Lhs[0].(*ast.IndexExpr)
	if !ok || sp.info.Types[index.Index].Value == nil {
		return callerLifetimeWrite{}, false
	}
	id, ok := index.X.(*ast.Ident)
	if !ok || sp.info.Uses[id] != variable {
		return callerLifetimeWrite{}, false
	}
	value := assign.Rhs[0]
	if _, ok := value.(*ast.Ident); !ok && sp.info.Types[value].Value == nil {
		return callerLifetimeWrite{}, false
	}
	return callerLifetimeWrite{owner: source(id), value: source(value)}, true
}

func callerLiteralSliceAllocation(object callerObjectKey) bool {
	if object.field != nil || object.zero != nil || object.pkg == nil || object.pkg.info == nil {
		return false
	}
	lit, ok := object.expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	typ := object.pkg.info.TypeOf(lit)
	if typ == nil {
		return false
	}
	_, ok = typ.Underlying().(*types.Slice)
	return ok
}

func (p *callerLifetimeProbe) separateUnpublishedMapWrite(write callerLifetimeWrite) bool {
	v := p.g.unpublishedMapWrites[write]
	return v != nil && len(p.g.live[v]) == 0 && p.steps <= callerLifetimeStepLimit && !p.g.semanticOverflow &&
		callerFreshReplayContext(p.g.ctx) && (p.g.ctx == nil || p.g.ctx.Err() == nil)
}
